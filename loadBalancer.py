# File: lb.py
# A simple POX-based load balancer for ICMP traffic

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp, ipv4, icmp

log = core.getLogger()

class SimpleLoadBalancer(object):
    """
    A simple POX controller that implements round-robin load balancing
    between two real servers for traffic destined to a 'virtual IP'.
    """

    def __init__(self, connection):
        # Store the connection object
        self.connection = connection
        self.dpid = connection.dpid
        self.name = dpid_to_str(self.dpid)

        # Our 'virtual IP' (VIP) that clients will ping
        self.virtual_ip = IPAddr("10.0.0.10")

        # The real server IPs behind our load balancer
        self.server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]

        # Corresponding MAC addresses of servers (manually known or discovered)
        self.server_macs = [EthAddr("00:00:00:00:00:05"),
                            EthAddr("00:00:00:00:00:06")]

        # Round-robin index
        self.next_server = 0

        # ARP cache: IP -> (MAC, port)
        # We store where we last saw a given IP (either client or server)
        self.arp_table = {}

        # Add listeners
        connection.addListeners(self)

        log.info("LoadBalancer initialized for Switch %s", self.name)

    def _pick_server(self):
        """
        Pick the next server in round-robin fashion.
        Returns (server_ip, server_mac).
        """
        server_ip = self.server_ips[self.next_server]
        server_mac = self.server_macs[self.next_server]
        self.next_server = (self.next_server + 1) % len(self.server_ips)
        return server_ip, server_mac

    def _handle_PacketIn(self, event):
        """
        Handle incoming packets from the switch.
        """
        packet = event.parsed
        if not packet:
            return

        inport = event.port

        # Learn or update ARP table with the sender's info (IP, MAC, port)
        self._update_arp_table(packet, inport)

        # Check if ARP
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode == arp.REQUEST:
                self._handle_arp_request(event, arp_pkt, inport)
            elif arp_pkt.opcode == arp.REPLY:
                # If you want to handle ARP replies (from servers, e.g.),
                # you could process them here. Typically, we just learn from them.
                pass
            return

        # Check if IP
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next

            # We only handle ICMP (ping) for load balancing
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                self._handle_icmp(event, ip_pkt, inport)
            else:
                # Not ICMP; you could handle TCP/UDP load balancing similarly
                self._flood(event)  # Or drop/other logic
            return

        # Otherwise, do something default (e.g. flood)
        self._flood(event)

    def _handle_arp_request(self, event, arp_pkt, inport):
        """
        Handle ARP requests. If the ARP is for our virtual IP, respond
        with a chosen server MAC (round-robin). Also install flows.
        """
        if arp_pkt.protodst == self.virtual_ip:
            # Round-robin pick a real server
            server_ip, server_mac = self._pick_server()

            # 1) Send ARP reply to the requesting host with server's MAC,
            #    but the "sender IP" in the ARP reply is the virtual IP.
            self._send_arp_reply(event, arp_pkt, server_mac, inport)

            # 2) Install flow rules for client->server and server->client
            client_ip = arp_pkt.protosrc
            client_mac = arp_pkt.hwsrc
            self._install_loadbalancer_rules(client_ip, client_mac,
                                             server_ip, server_mac,
                                             inport)
        else:
            # Normal ARP request (not for our VIP).
            # If we know the MAC, respond; otherwise flood
            if arp_pkt.protodst in self.arp_table:
                (dst_mac, dst_port) = self.arp_table[arp_pkt.protodst]
                self._send_arp_reply(event, arp_pkt, dst_mac, inport,
                                     override_ip=arp_pkt.protodst)
            else:
                self._flood(event)

    def _install_loadbalancer_rules(self, client_ip, client_mac,
                                    server_ip, server_mac,
                                    client_inport):
        """
        Push two unidirectional flow rules:
          1) Client -> Server: match on inport=client_inport, dst_ip=VIP
             actions: rewrite dst_ip=server_ip, dst_mac=server_mac, output=server_port
          2) Server -> Client: match on inport=server_port, src_ip=server_ip, dst_ip=client_ip
             actions: rewrite src_ip=VIP, src_mac=server_mac_for_vip?, output=client_inport
        """
        # Find the server port if known from ARP table
        # (Alternatively, you might discover it or keep a static mapping.)
        server_port = None
        # If we already learned server_ip from an ARP or some config:
        if server_ip in self.arp_table:
            server_port = self.arp_table[server_ip][1]
        else:
            # If we don't know it, we might guess or rely on subsequent ARP from server
            # For a single switch with ports: h1=1, h2=2, h3=3, h4=4, h5=5, h6=6, for instance:
            # If server_ip is 10.0.0.5 => port 5, if 10.0.0.6 => port 6, etc.
            if str(server_ip) == "10.0.0.5":
                server_port = 5
            elif str(server_ip) == "10.0.0.6":
                server_port = 6

        # (1) Flow: Client -> Server
        fm_c_s = of.ofp_flow_mod()
        fm_c_s.match.in_port = client_inport
        fm_c_s.match.dl_type = 0x0800             # IP
        fm_c_s.match.nw_dst = self.virtual_ip     # The VIP
        # Actions: rewrite IP dst to server_ip, MAC dst to server_mac, output to server_port
        fm_c_s.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm_c_s.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        if server_port:
            fm_c_s.actions.append(of.ofp_action_output(port=server_port))
        else:
            # If we don't know, we can flood or drop; let's just flood for example
            fm_c_s.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

        self.connection.send(fm_c_s)

        # (2) Flow: Server -> Client
        fm_s_c = of.ofp_flow_mod()
        fm_s_c.match.in_port = server_port
        fm_s_c.match.dl_type = 0x0800             # IP
        fm_s_c.match.nw_src = server_ip
        fm_s_c.match.nw_dst = client_ip
        # Actions: rewrite IP src from server_ip to VIP,
        # (MAC src can be the real server's MAC or a "virtual" MAC—your choice)
        fm_s_c.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
        # Some designs also rewrite the MAC src to a "virtual" MAC so that clients
        # see consistent MAC. For simplicity, let's keep the server's real MAC:
        # fm_s_c.actions.append(of.ofp_action_dl_addr.set_src(<virtual MAC>))

        # Finally, output to the client_inport
        fm_s_c.actions.append(of.ofp_action_output(port=client_inport))

        self.connection.send(fm_s_c)

        log.info("Installed LB flow for %s <-> %s", client_ip, server_ip)

    def _send_arp_reply(self, event, arp_req, reply_mac, outport,
                        override_ip=None):
        """
        Craft and send an ARP reply packet. By default, ARP 'sender IP'
        is the VIP, unless override_ip is specified.
        """
        r = arp()
        r.opcode = arp.REPLY
        r.hwdst = arp_req.hwsrc
        r.protodst = arp_req.protosrc
        r.protosrc = override_ip if override_ip else self.virtual_ip
        r.hwsrc = reply_mac

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.dst = arp_req.hwsrc
        e.src = reply_mac
        e.set_payload(r)

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=outport))
        self.connection.send(msg)

        log.debug("Sent ARP reply to %s (IP=%s, MAC=%s)",
                  str(arp_req.protosrc),
                  str(r.protosrc), str(reply_mac))

    def _handle_icmp(self, event, ip_pkt, inport):
        """
        If we get an ICMP destined for the VIP but no ARP triggered yet,
        we can either drop or handle it. Typically, the client OS will
        ARP first, so we might not get here for the first packet.
        """
        # Simple approach: if we have no rule installed, just flood or drop.
        # Or you can do a dynamic check. We'll just flood as a fallback.
        self._flood(event)

    def _update_arp_table(self, packet, inport):
        """
        Whenever we see an ARP or IP packet, learn its IP->MAC->port
        (so we can respond to ARP requests on behalf of that IP if needed).
        """
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode in (arp.REQUEST, arp.REPLY):
                self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, inport)
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next
            # If it's an IP packet, we can glean the src IP and MAC
            self.arp_table[ip_pkt.srcip] = (packet.src, inport)

    def _flood(self, event):
        """
        Flood the packet out all ports (except input port).
        """
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

def launch():
    """
    Launch the load balancer module.
    """
    def start_switch(event):
        log.info("Controlling %s", dpid_to_str(event.dpid))
        SimpleLoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

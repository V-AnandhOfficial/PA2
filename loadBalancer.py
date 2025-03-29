# File: lb_debug.py
# A POX-based load balancer for ICMP traffic with extensive debugging

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
    Extensive logging is added for debugging.
    """

    def __init__(self, connection):
        self.connection = connection
        self.dpid = connection.dpid
        self.name = dpid_to_str(self.dpid)
        log.info("Initializing Load Balancer for Switch %s", self.name)

        # Define the virtual IP that clients will use
        self.virtual_ip = IPAddr("10.0.0.10")
        log.info("Virtual IP set to %s", self.virtual_ip)

        # Real server IPs and their corresponding MAC addresses
        self.server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
        self.server_macs = [EthAddr("00:00:00:00:00:05"),
                            EthAddr("00:00:00:00:00:06")]
        log.info("Server IPs: %s and %s", self.server_ips[0], self.server_ips[1])
        log.info("Server MACs: %s and %s", self.server_macs[0], self.server_macs[1])

        # Round-robin index for load balancing
        self.next_server = 0

        # ARP cache: maps IPAddr -> (EthAddr, port)
        self.arp_table = {}
        log.debug("Initial ARP table: %s", self.arp_table)

        # Listen for incoming packets
        connection.addListeners(self)
        log.info("Load Balancer for Switch %s is now listening for packets", self.name)

    def _pick_server(self):
        """
        Pick the next server using round-robin.
        """
        server_ip = self.server_ips[self.next_server]
        server_mac = self.server_macs[self.next_server]
        log.debug("Round-robin picked server %s with MAC %s", server_ip, server_mac)
        self.next_server = (self.next_server + 1) % len(self.server_ips)
        return server_ip, server_mac

    def _handle_PacketIn(self, event):
        """
        Main packet handler for PacketIn events.
        """
        packet = event.parsed
        if not packet:
            log.warning("Ignoring packet with no parsed content")
            return

        inport = event.port
        log.debug("PacketIn received on port %s: %s", inport, packet)

        # Learn/update ARP table from this packet
        self._update_arp_table(packet, inport)

        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            log.debug("Handling ARP packet: %s", arp_pkt)
            if arp_pkt.opcode == arp.REQUEST:
                log.info("ARP Request received from %s for IP %s", arp_pkt.protosrc, arp_pkt.protodst)
                self._handle_arp_request(event, arp_pkt, inport)
            elif arp_pkt.opcode == arp.REPLY:
                log.info("ARP Reply received from %s", arp_pkt.protosrc)
            else:
                log.warning("Unknown ARP opcode: %s", arp_pkt.opcode)
            return

        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next
            log.debug("Handling IP packet: %s", ip_pkt)
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                log.info("ICMP packet from %s to %s", ip_pkt.srcip, ip_pkt.dstip)
                self._handle_icmp(event, ip_pkt, inport)
            else:
                log.info("Non-ICMP IP packet; defaulting to flood")
                self._flood(event)
            return

        else:
            log.info("Unhandled Ethernet type: %s; flooding", packet.type)
            self._flood(event)

    def _handle_arp_request(self, event, arp_pkt, inport):
        """
        Process ARP requests.
        """
        if arp_pkt.protodst == self.virtual_ip:
            log.info("ARP request for Virtual IP %s received from %s", self.virtual_ip, arp_pkt.protosrc)
            server_ip, server_mac = self._pick_server()
            log.info("Responding with server IP %s and MAC %s", server_ip, server_mac)
            self._send_arp_reply(event, arp_pkt, server_mac, inport)
            client_ip = arp_pkt.protosrc
            client_mac = arp_pkt.hwsrc
            self._install_loadbalancer_rules(client_ip, client_mac,
                                             server_ip, server_mac,
                                             inport)
        else:
            log.info("ARP request for %s received; checking ARP table", arp_pkt.protodst)
            if arp_pkt.protodst in self.arp_table:
                dst_mac, dst_port = self.arp_table[arp_pkt.protodst]
                log.info("Found ARP entry for %s: MAC %s at port %s", arp_pkt.protodst, dst_mac, dst_port)
                self._send_arp_reply(event, arp_pkt, dst_mac, inport,
                                     override_ip=arp_pkt.protodst)
            else:
                log.info("No ARP entry found for %s; flooding ARP request", arp_pkt.protodst)
                self._flood(event)

    def _install_loadbalancer_rules(self, client_ip, client_mac, server_ip, server_mac, client_inport):
        """
        Install two flow rules:
          - Client to Server: rewrite destination IP/MAC.
          - Server to Client: rewrite source IP to virtual IP.
        """
        # Determine the server port
        server_port = None
        if server_ip in self.arp_table:
            server_port = self.arp_table[server_ip][1]
            log.debug("Found server %s in ARP table on port %s", server_ip, server_port)
        else:
            if str(server_ip) == "10.0.0.5":
                server_port = 5
            elif str(server_ip) == "10.0.0.6":
                server_port = 6
            log.debug("Server port for %s not learned, using default: %s", server_ip, server_port)

        # Install flow rule for Client -> Server
        fm_c_s = of.ofp_flow_mod()
        fm_c_s.match.in_port = client_inport
        fm_c_s.match.dl_type = 0x0800             # IP
        fm_c_s.match.nw_dst = self.virtual_ip
        fm_c_s.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm_c_s.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        if server_port:
            fm_c_s.actions.append(of.ofp_action_output(port=server_port))
            log.debug("Client -> Server rule: set dst IP to %s, dst MAC to %s, output port %s",
                      server_ip, server_mac, server_port)
        else:
            fm_c_s.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            log.debug("Client -> Server rule: unknown server port, flooding")

        self.connection.send(fm_c_s)
        log.info("Installed flow for Client (%s) -> Server (%s)", client_ip, server_ip)

        # Install flow rule for Server -> Client
        fm_s_c = of.ofp_flow_mod()
        fm_s_c.match.in_port = server_port
        fm_s_c.match.dl_type = 0x0800             # IP
        fm_s_c.match.nw_src = server_ip
        fm_s_c.match.nw_dst = client_ip
        fm_s_c.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
        fm_s_c.actions.append(of.ofp_action_output(port=client_inport))
        self.connection.send(fm_s_c)
        log.info("Installed flow for Server (%s) -> Client (%s)", server_ip, client_ip)

    def _send_arp_reply(self, event, arp_req, reply_mac, outport, override_ip=None):
        """
        Create and send an ARP reply.
        """
        log.debug("Preparing ARP reply to %s", arp_req.protosrc)
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
        log.info("Sent ARP reply: %s is-at %s (to port %s)", r.protosrc, reply_mac, outport)

    def _handle_icmp(self, event, ip_pkt, inport):
        """
        Handle ICMP traffic. Typically, this should not be hit if flows are in place.
        """
        log.debug("Received ICMP packet: %s", ip_pkt)
        log.info("No matching flow for ICMP from %s to %s; flooding as fallback", ip_pkt.srcip, ip_pkt.dstip)
        self._flood(event)

    def _update_arp_table(self, packet, inport):
        """
        Update the ARP table based on the packet's information.
        """
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode in (arp.REQUEST, arp.REPLY):
                self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, inport)
                log.debug("Updated ARP table with ARP packet: %s -> (%s, port %s)",
                          arp_pkt.protosrc, arp_pkt.hwsrc, inport)
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next
            self.arp_table[ip_pkt.srcip] = (packet.src, inport)
            log.debug("Updated ARP table with IP packet: %s -> (%s, port %s)",
                      ip_pkt.srcip, packet.src, inport)

    def _flood(self, event):
        """
        Flood the packet out all ports except the input.
        """
        log.debug("Flooding packet received on port %s", event.port)
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
        log.info("Switch %s has connected", dpid_to_str(event.dpid))
        SimpleLoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

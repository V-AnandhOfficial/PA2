from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp, ipv4

log = core.getLogger()

class VirtualIPLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        # Virtual IP used by clients.
        self.virtual_ip = IPAddr("10.0.0.10")
        # Real server IPs and MACs (hardcoded for h5 and h6).
        self.server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
        self.server_macs = [EthAddr("00:00:00:00:00:05"),
                            EthAddr("00:00:00:00:00:06")]
        # Round-robin pointer.
        self.next_server = 0
        # ARP table: maps IPAddr -> (EthAddr, port)
        self.arp_table = {}
        # Mapping from client IP to assigned server (server_ip, server_mac)
        self.client_server_map = {}
        connection.addListeners(self)
        log.info("Load Balancer initialized on switch %s", dpid_to_str(connection.dpid))

    def _pick_server(self):
        server_ip = self.server_ips[self.next_server]
        server_mac = self.server_macs[self.next_server]
        self.next_server = (self.next_server + 1) % len(self.server_ips)
        return server_ip, server_mac

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return
        inport = event.port
        self._update_arp_table(packet, inport)

        # Process ARP packets as before.
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode == arp.REQUEST:
                # Handle ARP requests for the virtual IP.
                if arp_pkt.protodst == self.virtual_ip:
                    client_ip = arp_pkt.protosrc
                    if client_ip in self.client_server_map:
                        server_ip, server_mac = self.client_server_map[client_ip]
                        log.info("Client %s already assigned to server %s", client_ip, server_ip)
                    else:
                        server_ip, server_mac = self._pick_server()
                        self.client_server_map[client_ip] = (server_ip, server_mac)
                        log.info("Assigning client %s to server %s", client_ip, server_ip)
                    self._send_arp_reply(event, arp_pkt, server_mac, inport)
                    self._install_flow_rules(client_ip, packet.src, server_ip, server_mac, inport)
                else:
                    if arp_pkt.protodst in self.arp_table:
                        dst_mac, _ = self.arp_table[arp_pkt.protodst]
                        self._send_arp_reply(event, arp_pkt, dst_mac, inport,
                                             override_ip=arp_pkt.protodst)
                    else:
                        self._flood(event)
            return

        # Process IP packets destined to the virtual IP.
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next
            # Check if the packet is intended for the virtual IP.
            if ip_pkt.dstip == self.virtual_ip:
                client_ip = ip_pkt.srcip
                if client_ip in self.client_server_map:
                    server_ip, server_mac = self.client_server_map[client_ip]
                    log.info("Processing IP packet from client %s using assigned server %s", client_ip, server_ip)
                else:
                    server_ip, server_mac = self._pick_server()
                    self.client_server_map[client_ip] = (server_ip, server_mac)
                    log.info("Assigning client %s to server %s (via IP packet)", client_ip, server_ip)
                    # Install flow rules for subsequent packets.
                    self._install_flow_rules(client_ip, packet.src, server_ip, server_mac, inport)
                
                # Determine server port based on the server's IP.
                server_port = 5 if str(server_ip) == "10.0.0.5" else 6

                # Issue a packet_out to immediately handle this IP packet.
                msg = of.ofp_packet_out()
                msg.data = event.ofp.data
                # Rewrite destination IP and MAC.
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_output(port=server_port))
                self.connection.send(msg)
                log.info("Redirected IP packet from client %s to server %s", client_ip, server_ip)
            else:
                # For non-virtual IP packets, fallback to flooding.
                log.info("Received IP packet not destined for virtual IP; flooding")
                self._flood(event)
            return

        else:
            self._flood(event)

    def _update_arp_table(self, packet, inport):
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode in (arp.REQUEST, arp.REPLY):
                self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, inport)
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.next
            self.arp_table[ip_pkt.srcip] = (packet.src, inport)

    def _send_arp_reply(self, event, arp_req, reply_mac, outport, override_ip=None):
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
        log.info("Sent ARP reply: %s is-at %s (to port %s)",
                 r.protosrc, reply_mac, outport)

    def _install_flow_rules(self, client_ip, client_mac, server_ip, server_mac, client_port):
        # Determine the server's port (h5 on port 5, h6 on port 6).
        server_port = 5 if str(server_ip) == "10.0.0.5" else 6

        # Flow rule for Client -> Server.
        fm_c2s = of.ofp_flow_mod()
        fm_c2s.match.in_port = client_port
        fm_c2s.match.dl_type = 0x0800  # IP packets.
        fm_c2s.match.nw_dst = self.virtual_ip
        fm_c2s.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm_c2s.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm_c2s.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm_c2s)
        log.info("Installed flow: Client %s -> Server %s", client_ip, server_ip)

        # Flow rule for Server -> Client.
        fm_s2c = of.ofp_flow_mod()
        fm_s2c.match.in_port = server_port
        fm_s2c.match.dl_type = 0x0800  # IP packets.
        fm_s2c.match.nw_src = server_ip
        fm_s2c.match.nw_dst = client_ip
        fm_s2c.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
        fm_s2c.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm_s2c)
        log.info("Installed flow: Server %s -> Client %s", server_ip, client_ip)

    def _flood(self, event):
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        VirtualIPLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)

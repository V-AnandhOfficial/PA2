from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp, ipv4

log = core.getLogger()

class VirtualIPLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        # Virtual IP that clients will use.
        self.virtual_ip = IPAddr("10.0.0.10")
        # Real server IPs and MACs.
        self.server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
        self.server_macs = [EthAddr("00:00:00:00:00:05"),
                            EthAddr("00:00:00:00:00:06")]
        # Round-robin pointer.
        self.next_server = 0
        # ARP table: maps IPAddr -> (EthAddr, port)
        self.arp_table = {}
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
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode == arp.REQUEST:
                if arp_pkt.protodst == self.virtual_ip:
                    server_ip, server_mac = self._pick_server()
                    self._send_arp_reply(event, arp_pkt, server_mac, inport)
                    self._install_flow_rules(arp_pkt.protosrc, arp_pkt.hwsrc,
                                             server_ip, server_mac, inport)
                else:
                    if arp_pkt.protodst in self.arp_table:
                        dst_mac, _ = self.arp_table[arp_pkt.protodst]
                        self._send_arp_reply(event, arp_pkt, dst_mac, inport,
                                             override_ip=arp_pkt.protodst)
                    else:
                        self._flood(event)
            return
        elif packet.type == ethernet.IP_TYPE:
            self._flood(event)
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

    def _install_flow_rules(self, client_ip, client_mac, server_ip, server_mac, client_port):
        # Use static port mapping: assume h5 is on port 5 and h6 on port 6.
        server_port = 5 if str(server_ip) == "10.0.0.5" else 6
        # Flow: Client -> Server. Match on in_port and VIP, rewrite to server IP/MAC.
        fm_c2s = of.ofp_flow_mod()
        fm_c2s.match.in_port = client_port
        fm_c2s.match.dl_type = 0x0800
        fm_c2s.match.nw_dst = self.virtual_ip
        fm_c2s.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm_c2s.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm_c2s.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm_c2s)
        # Flow: Server -> Client. Match on server port, rewrite server IP to VIP.
        fm_s2c = of.ofp_flow_mod()
        fm_s2c.match.in_port = server_port
        fm_s2c.match.dl_type = 0x0800
        fm_s2c.match.nw_src = server_ip
        fm_s2c.match.nw_dst = client_ip
        fm_s2c.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
        fm_s2c.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm_s2c)

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

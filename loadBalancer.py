from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class VirtualIPLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        
        self.virtual_ip = IPAddr("10.0.0.10")
        self.virtual_mac = EthAddr("00:00:00:00:00:10")
        
        self.server_pool = [
            (IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05")),
            (IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"))
        ]
        
        self.server_index = 0 
        connection.addListeners(self)
        log.info("Virtual IP Load Balancer initialized on %s", connection)
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if isinstance(packet.next, arp):
            self.handle_arp(event, packet)
        elif isinstance(packet.next, ipv4):
            self.handle_ip(event, packet)

    def handle_arp(self, event, packet):
        a = packet.next

        if a.opcode == arp.REQUEST and a.protodst == self.virtual_ip:
            log.debug("Received ARP request for virtual IP %s", self.virtual_ip)

            # Create ARP reply
            r = arp()
            r.hwtype = a.hwtype
            r.prototype = a.prototype
            r.hwlen = a.hwlen
            r.protolen = a.protolen
            r.opcode = arp.REPLY
            r.hwdst = a.hwsrc
            r.protodst = a.protosrc
            r.protosrc = self.virtual_ip
            r.hwsrc = self.virtual_mac

            e = ethernet()
            e.type = ethernet.ARP_TYPE
            e.src = self.virtual_mac
            e.dst = packet.src
            e.payload = r

            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
            log.debug("Sent ARP reply with virtual MAC %s", self.virtual_mac)

    def handle_ip(self, event, packet):
        ip_packet = packet.next

        if ip_packet.dstip == self.virtual_ip:
            server_ip, server_mac = self.server_pool[self.server_index]
            self.server_index = (self.server_index + 1) % len(self.server_pool)
            log.debug("Mapping client request from %s to server %s", ip_packet.srcip, server_ip)

            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, event.port)
            fm.idle_timeout = 10
            fm.hard_timeout = 30
            fm.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
            fm.actions.append(of.ofp_action_output(port=self.get_port_for_ip(server_ip)))

            self.connection.send(fm)

            po = of.ofp_packet_out()
            po.data = event.ofp
            po.actions = fm.actions
            self.connection.send(po)
        
        elif ip_packet.srcip in [s[0] for s in self.server_pool]:
            log.debug("Mapping server response from %s to virtual IP %s", ip_packet.srcip, self.virtual_ip)

            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, event.port)
            fm.idle_timeout = 10
            fm.hard_timeout = 30
            fm.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
            fm.actions.append(of.ofp_action_dl_addr.set_src(self.virtual_mac))
            fm.actions.append(of.ofp_action_output(port=event.port))

            self.connection.send(fm)

            po = of.ofp_packet_out()
            po.data = event.ofp
            po.actions = fm.actions
            self.connection.send(po)

def get_port_for_ip(self, ip):
    if ip == IPAddr("10.0.0.5"):
        return 5  # h5 is on port s1-eth5
    elif ip == IPAddr("10.0.0.6"):
        return 6  # h6 is on port s1-eth6
    else:
        return of.OFPP_FLOOD

def launch():
    def start_switch(event):
        log.info("Switch %s connected", event.connection)
        VirtualIPLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)

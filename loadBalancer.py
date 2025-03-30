from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
import time

log = core.getLogger()

# Configuration constants
VIRTUAL_IP = IPAddr("10.0.0.10") 
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  
SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]

class VirtualIPLoadBalancer(object):
    
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        
        self.mac_to_port = {}
        
        self.client_to_server = {}
        
        self.current_server = 0
        
        log.info("Virtual IP Load Balancer initialized")
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        packet_in = event.ofp
        in_port = packet_in.in_port
        
        self.mac_to_port[packet.src] = in_port
        
        if packet.type == pkt.ethernet.ARP_TYPE:
            self._handle_arp(event, packet, in_port)
            return
        
        if packet.type == pkt.ethernet.IP_TYPE:
            self._handle_ip(event, packet, in_port)
            return
        
        self._handle_other(event, packet, in_port)
    
    def _handle_arp(self, event, packet, in_port):
        """
        Handle ARP packets
        """
        arp_packet = packet.payload
        
        if arp_packet.opcode == pkt.arp.REQUEST:
            if arp_packet.protodst == VIRTUAL_IP:
                log.info("Received ARP request for virtual IP %s from %s", 
                         VIRTUAL_IP, arp_packet.hwsrc)
                
                server_idx = self._get_next_server(arp_packet.hwsrc)
                server_ip = SERVER_IPS[server_idx]
                server_mac = SERVER_MACS[server_idx]
                
                arp_reply = pkt.arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = arp_packet.protosrc
                
                ether = pkt.ethernet()
                ether.type = pkt.ethernet.ARP_TYPE
                ether.src = server_mac
                ether.dst = packet.src
                ether.payload = arp_reply
                
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)
                
                log.info("Sent ARP reply: %s is at %s", VIRTUAL_IP, server_mac)
                
                self._setup_flow_entries(arp_packet.protosrc, server_ip, server_idx, in_port)
                return
            
            elif any(arp_packet.protosrc == server_ip for server_ip in SERVER_IPS):
                log.info("Server %s is asking for client %s's MAC address", 
                         arp_packet.protosrc, arp_packet.protodst)
                
                self._handle_other(event, packet, in_port)
                return
        
        self._handle_other(event, packet, in_port)
    
    def _handle_ip(self, event, packet, in_port):
        ip_packet = packet.payload
        
        if ip_packet.dstip == VIRTUAL_IP:
            log.info("IP packet to virtual IP: %s -> %s", ip_packet.srcip, ip_packet.dstip)
            
            server_idx = self._get_server_for_client(ip_packet.srcip)
            server_ip = SERVER_IPS[server_idx]
            server_port = self.mac_to_port.get(SERVER_MACS[server_idx])
            
            if server_port is None:
                log.warning("Unknown server port for %s", SERVER_MACS[server_idx])
                return
            
            actions = []
            actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MACS[server_idx]))
            actions.append(of.ofp_action_output(port=server_port))
            
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = in_port
            msg.actions = actions
            self.connection.send(msg)
            
            self._setup_flow_entries(ip_packet.srcip, server_ip, server_idx, in_port)
            return
            
        elif any(ip_packet.srcip == server_ip for server_ip in SERVER_IPS):
            server_idx = SERVER_IPS.index(ip_packet.srcip)
            
            client_ip = None
            for client, assigned_server in self.client_to_server.items():
                if assigned_server == server_idx and client == ip_packet.dstip:
                    client_ip = client
                    break
            
            if client_ip is not None:
                log.info("IP packet from server to client: %s -> %s", ip_packet.srcip, ip_packet.dstip)
                
                client_port = self.mac_to_port.get(packet.dst)
                if client_port is None:
                    log.warning("Unknown client port for %s", packet.dst)
                    return
                
                actions = []
                actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
                actions.append(of.ofp_action_output(port=client_port))
                
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = actions
                self.connection.send(msg)
                return
        
        self._handle_other(event, packet, in_port)
    
    def _handle_other(self, event, packet, in_port):

        if packet.dst not in self.mac_to_port:
            log.debug("Flooding packet to unknown destination")
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
        else:
            port = self.mac_to_port[packet.dst]
            log.debug("Forwarding packet to port %s", port)
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=port))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
    
    def _get_next_server(self, client_mac):
        server_idx = self.current_server
        self.current_server = (self.current_server + 1) % len(SERVER_IPS)
        log.info("Assigning server %s to client %s", server_idx, client_mac)
        return server_idx
    
    def _get_server_for_client(self, client_ip):
        if client_ip not in self.client_to_server:
            # Assign a new server for this client
            server_idx = self._get_next_server(client_ip)
            self.client_to_server[client_ip] = server_idx
        
        return self.client_to_server[client_ip]
    
    def _setup_flow_entries(self, client_ip, server_ip, server_idx, client_port):
        server_mac = SERVER_MACS[server_idx]
        server_port = self.mac_to_port.get(server_mac)
        
        if server_port is None:
            log.warning("Unknown server port for %s, not setting up flow entries yet", server_mac)
            return
        
        self.client_to_server[client_ip] = server_idx
        
        log.info("Setting up flow entries for %s <-> %s", client_ip, server_ip)
        
        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_dst = VIRTUAL_IP
        msg.match.nw_src = client_ip
        msg.match.in_port = client_port
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_output(port=server_port))
        msg.idle_timeout = 300  
        self.connection.send(msg)
        
        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        msg.match.in_port = server_port
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_output(port=client_port))
        msg.idle_timeout = 300 
        self.connection.send(msg)


def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        VirtualIPLoadBalancer(event.connection)
    
    core.openflow.addListenerByName("ConnectionUp", start_switch)
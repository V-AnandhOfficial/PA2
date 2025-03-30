# This application is a Load Balancer that uses POX to divert traffic Round-Robin style

# Author: Vivek Anandh
# Date: Marh 23, 2025

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
import time

log = core.getLogger()

# Configuration constants
VIRTUAL_IP = IPAddr("10.0.0.10")  # Virtual IP address
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real server IP addresses
SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  # Server MAC addresses

 # A virtual IP load balancing switch implementation using POX.
class VirtualIPLoadBalancer(object):
    # Initialize the load balancer
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        
        # Dictionary to store MAC addresses of hosts
        self.mac_to_port = {}
        
        # Dictionary to map client IPs to assigned server index
        self.client_to_server = {}
        
        # Counter for round-robin assignment
        self.current_server = 0
        
        log.info("Virtual IP Load Balancer initialized")
    
    # Handle packet in messages from the switch
    def _handle_PacketIn(self, event):
        packet = event.parsed
        
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        packet_in = event.ofp
        in_port = packet_in.in_port
        
        # Learn MAC to port mapping
        self.mac_to_port[packet.src] = in_port
        
        # Handle ARP packets
        if packet.type == pkt.ethernet.ARP_TYPE:
            self._handle_arp(event, packet, in_port)
            return
        
        # Handle IP packets
        if packet.type == pkt.ethernet.IP_TYPE:
            self._handle_ip(event, packet, in_port)
            return
        
        # For other packet types, use normal L2 learning switch behavior
        self._handle_other(event, packet, in_port)
    
    # Handle ARP packets
    def _handle_arp(self, event, packet, in_port):
        arp_packet = packet.payload
        
        # Handle ARP requests for the virtual IP
        if arp_packet.opcode == pkt.arp.REQUEST:
            if arp_packet.protodst == VIRTUAL_IP:
                log.info("Received ARP request for virtual IP %s from %s", 
                         VIRTUAL_IP, arp_packet.hwsrc)
                
                # Assign the next server in round-robin fashion
                server_idx = self._get_next_server(arp_packet.hwsrc)
                server_ip = SERVER_IPS[server_idx]
                server_mac = SERVER_MACS[server_idx]
                
                # Create ARP reply
                arp_reply = pkt.arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = arp_packet.protosrc
                
                # Create Ethernet packet
                ether = pkt.ethernet()
                ether.type = pkt.ethernet.ARP_TYPE
                ether.src = server_mac
                ether.dst = packet.src
                ether.payload = arp_reply
                
                # Create OpenFlow message
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)
                
                log.info("Sent ARP reply: %s is at %s", VIRTUAL_IP, server_mac)
                
                # Set up flow entries for future traffic
                self._setup_flow_entries(arp_packet.protosrc, server_ip, server_idx, in_port)
                return
            
            # Handle ARP requests from servers to clients
            elif any(arp_packet.protosrc == server_ip for server_ip in SERVER_IPS):
                # This is a server asking for a client's MAC address
                log.info("Server %s is asking for client %s's MAC address", 
                         arp_packet.protosrc, arp_packet.protodst)
                
                # Let regular ARP resolution happen
                self._handle_other(event, packet, in_port)
                return
        
        # For other ARP packets, use normal L2 behavior
        self._handle_other(event, packet, in_port)
    
    # Handle IP packets
    def _handle_ip(self, event, packet, in_port):
        ip_packet = packet.payload
        
        # Check if this is traffic to/from our virtual IP or servers
        if ip_packet.dstip == VIRTUAL_IP:
            # Client -> Virtual IP traffic
            # Should be handled by flow rules, but in case not:
            log.info("IP packet to virtual IP: %s -> %s", ip_packet.srcip, ip_packet.dstip)
            
            server_idx = self._get_server_for_client(ip_packet.srcip)
            server_ip = SERVER_IPS[server_idx]
            server_port = self.mac_to_port.get(SERVER_MACS[server_idx])
            
            if server_port is None:
                log.warning("Unknown server port for %s", SERVER_MACS[server_idx])
                return
            
            # Modify packet and forward
            actions = []
            actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MACS[server_idx]))
            actions.append(of.ofp_action_output(port=server_port))
            
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = in_port
            msg.actions = actions
            self.connection.send(msg)
            
            # Also set up a flow rule for future packets
            self._setup_flow_entries(ip_packet.srcip, server_ip, server_idx, in_port)
            return
            
        elif any(ip_packet.srcip == server_ip for server_ip in SERVER_IPS):
            # Server directs Client traffic and Checks if this server is responding to a client that was using virtual IP
            server_idx = SERVER_IPS.index(ip_packet.srcip)
            
            # Find client that this server is responding to
            client_ip = None
            for client, assigned_server in self.client_to_server.items():
                if assigned_server == server_idx and client == ip_packet.dstip:
                    # This is a response from a server to a client using the virtual IP
                    client_ip = client
                    break
            
            if client_ip is not None:
                log.info("IP packet from server to client: %s -> %s", ip_packet.srcip, ip_packet.dstip)
                
                client_port = self.mac_to_port.get(packet.dst)
                if client_port is None:
                    log.warning("Unknown client port for %s", packet.dst)
                    return
                
                # Modify packet and forward
                actions = []
                actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
                actions.append(of.ofp_action_output(port=client_port))
                
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = actions
                self.connection.send(msg)
                return
        
        # For other IP packets, use normal L2 behavior
        self._handle_other(event, packet, in_port)
    
    # Handle other packet types with basic L2 switching behavior
    def _handle_other(self, event, packet, in_port):
        # Basic L2 learning switch
        if packet.dst not in self.mac_to_port:
            # Flood to all ports except the input port
            log.debug("Flooding packet to unknown destination")
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
        else:
            # Forward to specific port
            port = self.mac_to_port[packet.dst]
            log.debug("Forwarding packet to port %s", port)
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=port))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
    
    # Get the next server index using round-robin algorithm
    def _get_next_server(self, client_mac):
        server_idx = self.current_server
        self.current_server = (self.current_server + 1) % len(SERVER_IPS)
        log.info("Assigning server %s to client %s", server_idx, client_mac)
        return server_idx
    
    # Get the server index assigned to a specific client
    def _get_server_for_client(self, client_ip):
        if client_ip not in self.client_to_server:
            # Assign a new server for this client
            server_idx = self._get_next_server(client_ip)
            self.client_to_server[client_ip] = server_idx
        
        return self.client_to_server[client_ip]
    
    # Set up OpenFlow entries for both client->server and server->client traffic
    def _setup_flow_entries(self, client_ip, server_ip, server_idx, client_port):

        # Get the port for the server
        server_mac = SERVER_MACS[server_idx]
        server_port = self.mac_to_port.get(server_mac)
        
        if server_port is None:
            log.warning("Unknown server port for %s, not setting up flow entries yet", server_mac)
            return
        
        # Store the client to server mapping
        self.client_to_server[client_ip] = server_idx
        
        log.info("Setting up flow entries for %s <-> %s", client_ip, server_ip)
        
        # Client -> Server flow entry
        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_dst = VIRTUAL_IP
        msg.match.nw_src = client_ip
        msg.match.in_port = client_port
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_output(port=server_port))
        msg.idle_timeout = 300  # 5 minutes
        self.connection.send(msg)
        
        # Server -> Client flow entry
        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        msg.match.in_port = server_port
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_output(port=client_port))
        msg.idle_timeout = 300  # 5 minutes
        self.connection.send(msg)

# Start the virtual IP load balancer
def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        VirtualIPLoadBalancer(event.connection)
    
    core.openflow.addListenerByName("ConnectionUp", start_switch)
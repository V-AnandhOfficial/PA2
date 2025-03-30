<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> parent of 01292a0 (revert)
# Import POX Libraries
from pox.core import core  
import pox.openflow.libopenflow_01 as Of  
from pox.lib.addresses import EthAddr, IPAddr  
import pox.lib.packet as Pkt 
import time  
<<<<<<< HEAD

# Global logger instance for logging controller events
Log = core.getLogger()  

# Configuration constants for load balancing
VirtualIp = IPAddr("10.0.0.10")  
ServerIps = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  
ServerMacs = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  

# Class implementing a load balancer that directs traffic from a virtual IP to backend servers
class VirtualIpLoadBalancer(object):
    
    # Initialize the load balancer instance.
    # Parameters: Connection - The OpenFlow connection to a switch.
    def __init__(self, Connection):
        self.Connection = Connection 
        Connection.addListeners(self)  

        self.MacToPort = {}  # Dictionary mapping observed MAC addresses to switch ports
        self.ClientToServer = {}  # Mapping of client IP addresses to backend server indices
        self.CurrentServer = 0  # Index tracking the next server to assign using round-robin scheduling

        Log.info("Virtual IP Load Balancer initialized") 

    # Process incoming packet-in events from the switch.
    # Parameters: Event - The OpenFlow event containing the incoming packet and metadata.
    def HandlePacketIn(self, Event):
        Packet = Event.parsed  # Obtain the parsed Ethernet packet from the event

        if not Packet.parsed:
            Log.warning("Ignoring incomplete packet") 
=======
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
import time
=======
>>>>>>> parent of 01292a0 (revert)

 # Global logger instance for logging controller events
Log = core.getLogger() 

<<<<<<< HEAD
# Configuration constants
VIRTUAL_IP = IPAddr("10.0.0.10")  # Virtual IP address
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real server IP addresses
SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  # Server MAC addresses

class VirtualIPLoadBalancer(object):
    """
    A virtual IP load balancing switch implementation using POX.
    """
    
    def __init__(self, connection):
        """
        Initialize the load balancer
        """
        self.connection = connection
        connection.addListeners(self)
        
        # Dictionary to store MAC addresses of hosts
        self.mac_to_port = {}
        
        # Dictionary to map client IPs to assigned server index
        self.client_to_server = {}
        
        # Counter for round-robin assignment
        self.current_server = 0
        
        log.info("Virtual IP Load Balancer initialized")
    
    def _handle_PacketIn(self, event):
        """
        Handle packet in messages from the switch
        """
        packet = event.parsed
        
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
>>>>>>> parent of ef72b83 (sdf)
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
<<<<<<< HEAD

        self.HandleOther(Event, Packet, InPort)  # Fallback handling for non-ARP, non-IP packets

    # Process ARP packets to facilitate client-server mapping.
    # Parameters:
    #   Event - The OpenFlow event containing the ARP packet.
    #   Packet - The parsed Ethernet packet.
    #   InPort - The switch port on which the packet was received.
    def HandleArp(self, Event, Packet, InPort):

=======
# Configuration constants for load balancing
VirtualIp = IPAddr("10.0.0.10") 
ServerIps = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  
ServerMacs = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  

class VirtualIpLoadBalancer(object):
    # Class implementing a load balancer that directs traffic from a virtual IP to backend servers

    def __init__(self, Connection):
        # Initialize the load balancer instance.
        # Parameters:
        #   Connection - The OpenFlow connection to a switch.
        self.Connection = Connection  # Save the OpenFlow connection for later use
        Connection.addListeners(self)  # Register this instance to listen for events on the connection

        self.MacToPort = {}  # Dictionary mapping observed MAC addresses to switch ports
        self.ClientToServer = {}  # Mapping of client IP addresses to backend server indices
        self.CurrentServer = 0  # Index tracking the next server to assign using round-robin scheduling

        Log.info("Virtual IP Load Balancer initialized")  # Log the successful initialization

    def HandlePacketIn(self, Event):
        # Process incoming packet-in events from the switch.
        # Parameters:
        #   Event - The OpenFlow event containing the incoming packet and metadata.
        # Returns: None
        Packet = Event.parsed  # Obtain the parsed Ethernet packet from the event

        if not Packet.parsed:
            Log.warning("Ignoring incomplete packet")  # Log a warning if the packet could not be parsed
            return

        PacketIn = Event.ofp  # Extract the raw OpenFlow packet message
        InPort = PacketIn.in_port  # Get the port number on which the packet arrived

        self.MacToPort[Packet.src] = InPort  # Learn the source MAC address and its associated port

        if Packet.type == Pkt.ethernet.ARP_TYPE:
            self.HandleArp(Event, Packet, InPort)  # Delegate processing of ARP packets
            return

        if Packet.type == Pkt.ethernet.IP_TYPE:
            self.HandleIp(Event, Packet, InPort)  # Delegate processing of IP packets
            return

        self.HandleOther(Event, Packet, InPort)  # Fallback handling for non-ARP, non-IP packets

    def HandleArp(self, Event, Packet, InPort):
        # Process ARP packets to facilitate client-server mapping.
        # Parameters:
        #   Event - The OpenFlow event containing the ARP packet.
        #   Packet - The parsed Ethernet packet.
        #   InPort - The switch port on which the packet was received.
        # Returns: None
>>>>>>> parent of 01292a0 (revert)
        ArpPacket = Packet.payload  # Extract the ARP payload from the Ethernet frame

        if ArpPacket.opcode == Pkt.arp.REQUEST:
            if ArpPacket.protodst == VirtualIp:
                Log.info("Received ARP request for virtual IP %s from %s", VirtualIp, ArpPacket.hwsrc)
<<<<<<< HEAD
                
                # Determine which backend server should handle this client's request using round-robin
                ServerIdx = self.GetNextServer(ArpPacket.hwsrc)
                ServerIp = ServerIps[ServerIdx]  
                ServerMac = ServerMacs[ServerIdx]  

                # Create a new ARP packet for the reply and set the reply's source MAC to the chosen server's MAC
                ArpReply = Pkt.arp()  
                ArpReply.hwsrc = ServerMac 
                ArpReply.hwdst = ArpPacket.hwsrc  
                ArpReply.opcode = Pkt.arp.REPLY 
                ArpReply.protosrc = VirtualIp  
                ArpReply.protodst = ArpPacket.protosrc  

                # Create an Ethernet frame to encapsulate the ARP reply and specify that the Ethernet frame carries an ARP packet
                Ether = Pkt.ethernet()  
                Ether.type = Pkt.ethernet.ARP_TYPE  
                Ether.src = ServerMac  
                Ether.dst = Packet.src  
                Ether.payload = ArpReply  
                
                # Create a packet-out message to send the ARP reply and serialize the Ethernet frame into binary format
                Msg = Of.ofp_packet_out() 
                Msg.data = Ether.pack()  
                Msg.actions.append(Of.ofp_action_output(port=InPort))  
                self.Connection.send(Msg)  

                Log.info("Sent ARP reply: %s is at %s", VirtualIp, ServerMac)  

                self.SetupFlowEntries(ArpPacket.protosrc, ServerIp, ServerIdx, InPort)  # Install flow rules to streamline future traffic
                return

            elif any(ArpPacket.protosrc == ServerIp for ServerIp in ServerIps):
                Log.info("Server %s is asking for client %s's MAC address", ArpPacket.protosrc, ArpPacket.protodst)
                
                # For ARP requests from servers, use generic handling
                self.HandleOther(Event, Packet, InPort)
                return

        self.HandleOther(Event, Packet, InPort)  # Fallback for ARP packets that do not match specific criteria

    # Process IP packets for load-balanced forwarding between clients and servers.
    # Parameters:
    #   Event - The OpenFlow event containing the IP packet.
    #   Packet - The parsed Ethernet packet.
    #   InPort - The switch port on which the packet was received.
    def HandleIp(self, Event, Packet, InPort):
        IpPacket = Packet.payload  # Extract the IP packet from the Ethernet frame

        if IpPacket.dstip == VirtualIp:
            Log.info("IP packet to virtual IP: %s -> %s", IpPacket.srcip, IpPacket.dstip)
            
            # Determine the backend server assigned for this client using stored mapping or round-robin
            ServerIdx = self.GetServerForClient(IpPacket.srcip)
            ServerIp = ServerIps[ServerIdx]  # Get the server's IP address
            ServerPort = self.MacToPort.get(ServerMacs[ServerIdx])  # Look up the server's switch port using its MAC

            if ServerPort is None:
                Log.warning("Unknown server port for %s", ServerMacs[ServerIdx])
                return

            # Change destination IP to backend server's IP and specify output action to forward the packet to the server
            Actions = []  
            Actions.append(Of.ofp_action_nw_addr.set_dst(ServerIp))  
            Actions.append(Of.ofp_action_dl_addr.set_dst(ServerMacs[ServerIdx]))  
            Actions.append(Of.ofp_action_output(port=ServerPort)) 
             
            # Create a packet-out message for forwarding the IP packet and attach the list of actions to the message
            Msg = Of.ofp_packet_out()  
            Msg.data = Event.ofp  
            Msg.in_port = InPort  
            Msg.actions = Actions 
            self.Connection.send(Msg)  

            # Install flow rules for efficient future handling
            self.SetupFlowEntries(IpPacket.srcip, ServerIp, ServerIdx, InPort)  
            return

        elif any(IpPacket.srcip == ServerIp for ServerIp in ServerIps):
            
            # Handle packets originating from backend servers directed to clients
            ServerIdx = ServerIps.index(IpPacket.srcip)  

            ClientIp = None 
            for Client, AssignedServer in self.ClientToServer.items():
                if AssignedServer == ServerIdx and Client == IpPacket.dstip:
                    ClientIp = Client  
                    break

            if ClientIp is not None:
                Log.info("IP packet from server to client: %s -> %s", IpPacket.srcip, IpPacket.dstip)
                ClientPort = self.MacToPort.get(Packet.dst) 
                if ClientPort is None:
                    Log.warning("Unknown client port for %s", Packet.dst)
                    return

                # List to hold actions for modifying the packet on return path and modify source IP to the virtual IP for transparency
                Actions = []  
                Actions.append(Of.ofp_action_nw_addr.set_src(VirtualIp))  
                Actions.append(Of.ofp_action_output(port=ClientPort))  

                # Create a packet-out message for the server-to-client packet and send the message to complete the packet forwarding
                Msg = Of.ofp_packet_out()  
                Msg.data = Event.ofp  
                Msg.in_port = InPort  
                Msg.actions = Actions  
                self.Connection.send(Msg) 
                return

        self.HandleOther(Event, Packet, InPort)
        
    # Fallback handler for packets that do not match ARP or IP processing rules.
    # Parameters:
    #   Event - The OpenFlow event containing the packet.
    #   Packet - The parsed Ethernet packet.
    #   InPort - The switch port on which the packet was received.
    def HandleOther(self, Event, Packet, InPort):
        if Packet.dst not in self.MacToPort:
            Log.debug("Flooding packet to unknown destination")
            
            # Create a packet-out message to flood the packet and send the flood message out the switch
            Msg = Of.ofp_packet_out()  
            Msg.actions.append(Of.ofp_action_output(port=Of.OFPP_FLOOD))  
            Msg.data = Event.ofp  
            Msg.in_port = Event.port  
            self.Connection.send(Msg) 
        else:
            # Retrieve the specific port for the destination MAC and transmit the packet-out message to the switch
            Port = self.MacToPort[Packet.dst]  
            Log.debug("Forwarding packet to port %s", Port)
            Msg = Of.ofp_packet_out() 
            Msg.actions.append(Of.ofp_action_output(port=Port)) 
            Msg.data = Event.ofp 
            Msg.in_port = Event.port 
            self.Connection.send(Msg)  

    # Determine the next backend server index to assign for load balancing.
    # Parameters:
    #   ClientIdentifier - A unique identifier for the client (MAC or IP) requesting service.
    # Returns:
    #   Integer index of the assigned backend server.
    def GetNextServer(self, ClientIdentifier):
        ServerIdx = self.CurrentServer  
        self.CurrentServer = (self.CurrentServer + 1) % len(ServerIps) 
        Log.info("Assigning server %s to client %s", ServerIdx, ClientIdentifier)
        return ServerIdx

    # Retrieve or assign a backend server for a given client IP.
    # Parameters:
    #   ClientIp - The IP address of the client.
    # Returns:
    #   Integer index of the backend server assigned to the client.
    def GetServerForClient(self, ClientIp):
        if ClientIp not in self.ClientToServer:
            ServerIdx = self.GetNextServer(ClientIp)  
            self.ClientToServer[ClientIp] = ServerIdx  

        return self.ClientToServer[ClientIp]

    # Set up flow table entries in the switch to efficiently forward traffic between a client and its backend server.
    # Parameters:
    #   ClientIp - The IP address of the client.
    #   ServerIp - The IP address of the assigned backend server.
    #   ServerIdx - The index of the backend server in the configuration lists.
    #   ClientPort - The switch port number where the client is connected.
    def SetupFlowEntries(self, ClientIp, ServerIp, ServerIdx, ClientPort):
        ServerMac = ServerMacs[ServerIdx]  
        ServerPort = self.MacToPort.get(ServerMac) 
        
        if ServerPort is None:
            Log.warning("Unknown server port for %s, not setting up flow entries yet", ServerMac)
=======
        
        # For other packet types, use normal L2 learning switch behavior
        self._handle_other(event, packet, in_port)
    
    def _handle_arp(self, event, packet, in_port):
        """
        Handle ARP packets
        """
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
    
    def _handle_ip(self, event, packet, in_port):
        """
        Handle IP packets
        """
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
            # Server -> Client traffic
            # Check if this server is responding to a client that was using virtual IP
            server_idx = SERVER_IPS.index(ip_packet.srcip)
            
            # Find client that this server is responding to
            client_ip = None
            for client, assigned_server in self.client_to_server.items():
                if assigned_server == server_idx and client == ip_packet.dstip:
                    # This is a response from a server to a client using the virtual IP
                    client_ip = client
=======
                # Determine which backend server should handle this client's request using round-robin
                ServerIdx = self.GetNextServer(ArpPacket.hwsrc)
                ServerIp = ServerIps[ServerIdx]  # Select the server's IP address
                ServerMac = ServerMacs[ServerIdx]  # Select the server's MAC address

                ArpReply = Pkt.arp()  # Create a new ARP packet for the reply
                ArpReply.hwsrc = ServerMac  # Set the reply's source MAC to the chosen server's MAC
                ArpReply.hwdst = ArpPacket.hwsrc  # Set the reply's destination MAC to the client's MAC
                ArpReply.opcode = Pkt.arp.REPLY  # Specify the ARP opcode for reply
                ArpReply.protosrc = VirtualIp  # Use the virtual IP as the source protocol address
                ArpReply.protodst = ArpPacket.protosrc  # Set the reply's destination protocol address to the client's IP

                Ether = Pkt.ethernet()  # Create an Ethernet frame to encapsulate the ARP reply
                Ether.type = Pkt.ethernet.ARP_TYPE  # Specify that the Ethernet frame carries an ARP packet
                Ether.src = ServerMac  # Set source MAC address in the Ethernet frame to server's MAC
                Ether.dst = Packet.src  # Set destination MAC address to the client's MAC
                Ether.payload = ArpReply  # Attach the ARP reply to the Ethernet frame

                Msg = Of.ofp_packet_out()  # Create a packet-out message to send the ARP reply
                Msg.data = Ether.pack()  # Serialize the Ethernet frame into binary format
                Msg.actions.append(Of.ofp_action_output(port=InPort))  # Specify output action to send the packet back on the incoming port
                self.Connection.send(Msg)  # Transmit the packet-out message via the connection

                Log.info("Sent ARP reply: %s is at %s", VirtualIp, ServerMac)  # Log the ARP reply details

                self.SetupFlowEntries(ArpPacket.protosrc, ServerIp, ServerIdx, InPort)  # Install flow rules to streamline future traffic
                return

            elif any(ArpPacket.protosrc == ServerIp for ServerIp in ServerIps):
                Log.info("Server %s is asking for client %s's MAC address", ArpPacket.protosrc, ArpPacket.protodst)
                # For ARP requests from servers, use generic handling
                self.HandleOther(Event, Packet, InPort)
                return

        self.HandleOther(Event, Packet, InPort)  # Fallback for ARP packets that do not match specific criteria

    def HandleIp(self, Event, Packet, InPort):
        # Process IP packets for load-balanced forwarding between clients and servers.
        # Parameters:
        #   Event - The OpenFlow event containing the IP packet.
        #   Packet - The parsed Ethernet packet.
        #   InPort - The switch port on which the packet was received.
        # Returns: None
        IpPacket = Packet.payload  # Extract the IP packet from the Ethernet frame

        if IpPacket.dstip == VirtualIp:
            Log.info("IP packet to virtual IP: %s -> %s", IpPacket.srcip, IpPacket.dstip)
            # Determine the backend server assigned for this client using stored mapping or round-robin
            ServerIdx = self.GetServerForClient(IpPacket.srcip)
            ServerIp = ServerIps[ServerIdx]  # Get the server's IP address
            ServerPort = self.MacToPort.get(ServerMacs[ServerIdx])  # Look up the server's switch port using its MAC

            if ServerPort is None:
                Log.warning("Unknown server port for %s", ServerMacs[ServerIdx])
                return

            Actions = []  # List to hold OpenFlow actions for modifying and forwarding the packet
            Actions.append(Of.ofp_action_nw_addr.set_dst(ServerIp))  # Change destination IP to backend server's IP
            Actions.append(Of.ofp_action_dl_addr.set_dst(ServerMacs[ServerIdx]))  # Change destination MAC to backend server's MAC
            Actions.append(Of.ofp_action_output(port=ServerPort))  # Specify output action to forward the packet to the server

            Msg = Of.ofp_packet_out()  # Create a packet-out message for forwarding the IP packet
            Msg.data = Event.ofp  # Use the original packet data from the event
            Msg.in_port = InPort  # Set the incoming port for proper handling
            Msg.actions = Actions  # Attach the list of actions to the message
            self.Connection.send(Msg)  # Send the packet-out message to the switch

            self.SetupFlowEntries(IpPacket.srcip, ServerIp, ServerIdx, InPort)  # Install flow rules for efficient future handling
            return

        elif any(IpPacket.srcip == ServerIp for ServerIp in ServerIps):
            # Handle packets originating from backend servers directed to clients
            ServerIdx = ServerIps.index(IpPacket.srcip)  # Determine which server sent the packet

            ClientIp = None  # Variable to store the client's IP address
            for Client, AssignedServer in self.ClientToServer.items():
                if AssignedServer == ServerIdx and Client == IpPacket.dstip:
                    ClientIp = Client  # Identify the client associated with this server assignment
>>>>>>> parent of 01292a0 (revert)
                    break

            if ClientIp is not None:
                Log.info("IP packet from server to client: %s -> %s", IpPacket.srcip, IpPacket.dstip)
                ClientPort = self.MacToPort.get(Packet.dst)  # Look up the client’s switch port by destination MAC
                if ClientPort is None:
                    Log.warning("Unknown client port for %s", Packet.dst)
                    return
<<<<<<< HEAD
                
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
    
    def _handle_other(self, event, packet, in_port):
        """
        Handle other packet types with basic L2 switching behavior
        """
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
    
    def _get_next_server(self, client_mac):
        """
        Get the next server index using round-robin algorithm
        """
        server_idx = self.current_server
        self.current_server = (self.current_server + 1) % len(SERVER_IPS)
        log.info("Assigning server %s to client %s", server_idx, client_mac)
        return server_idx
    
    def _get_server_for_client(self, client_ip):
        """
        Get the server index assigned to a specific client
        """
        if client_ip not in self.client_to_server:
            # Assign a new server for this client
            server_idx = self._get_next_server(client_ip)
            self.client_to_server[client_ip] = server_idx
        
        return self.client_to_server[client_ip]
    
    def _setup_flow_entries(self, client_ip, server_ip, server_idx, client_port):
        """
        Set up OpenFlow entries for both client->server and server->client traffic
        """
        # Get the port for the server
        server_mac = SERVER_MACS[server_idx]
        server_port = self.mac_to_port.get(server_mac)
        
        if server_port is None:
            log.warning("Unknown server port for %s, not setting up flow entries yet", server_mac)
>>>>>>> parent of ef72b83 (sdf)
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

<<<<<<< HEAD
        self.ClientToServer[ClientIp] = ServerIdx 

        Log.info("Setting up flow entries for %s <-> %s", ClientIp, ServerIp)
        
        # Create flow entry for client-to-server traffic
        Msg = Of.ofp_flow_mod()  
        Msg.match.dl_type = Pkt.ethernet.IP_TYPE  
        Msg.match.nw_dst = VirtualIp  
        Msg.match.nw_src = ClientIp 
        Msg.match.in_port = ClientPort  
        Msg.actions.append(Of.ofp_action_nw_addr.set_dst(ServerIp))  
        Msg.actions.append(Of.ofp_action_dl_addr.set_dst(ServerMac)) 
        Msg.actions.append(Of.ofp_action_output(port=ServerPort))  
        Msg.idle_timeout = 300  
        self.Connection.send(Msg)  

        # Create flow entry for server-to-client traffic
        Msg = Of.ofp_flow_mod()  
        Msg.match.dl_type = Pkt.ethernet.IP_TYPE  
        Msg.match.nw_src = ServerIp  
        Msg.match.nw_dst = ClientIp 
        Msg.match.in_port = ServerPort  
        Msg.actions.append(Of.ofp_action_nw_addr.set_src(VirtualIp))  
        Msg.actions.append(Of.ofp_action_output(port=ClientPort))  
        Msg.idle_timeout = 300  
        self.Connection.send(Msg) 

# Entry point for starting the load balancer application.
def Launch():
    # Callback function that handles new switch connections.
    # Parameters: Event - The connection event containing details of the new switch.
    def StartSwitch(Event):
        Log.info("Controlling %s" % (Event.connection,))  
        VirtualIpLoadBalancer(Event.connection)  
        
    # Register listener for switch connection events
    core.openflow.addListenerByName("ConnectionUp", StartSwitch) 
=======

def launch():
    """
    Start the virtual IP load balancer
    """
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        VirtualIPLoadBalancer(event.connection)
    
    core.openflow.addListenerByName("ConnectionUp", start_switch)
>>>>>>> parent of ef72b83 (sdf)
=======

                Actions = []  # List to hold actions for modifying the packet on return path
                Actions.append(Of.ofp_action_nw_addr.set_src(VirtualIp))  # Modify source IP to the virtual IP for transparency
                Actions.append(Of.ofp_action_output(port=ClientPort))  # Forward the packet to the client’s port

                Msg = Of.ofp_packet_out()  # Create a packet-out message for the server-to-client packet
                Msg.data = Event.ofp  # Set the original packet data
                Msg.in_port = InPort  # Set the incoming port
                Msg.actions = Actions  # Attach the action list
                self.Connection.send(Msg)  # Send the message to complete the packet forwarding
                return

        self.HandleOther(Event, Packet, InPort)  # Fallback for IP packets not matching any criteria

    def HandleOther(self, Event, Packet, InPort):
        # Fallback handler for packets that do not match ARP or IP processing rules.
        # Parameters:
        #   Event - The OpenFlow event containing the packet.
        #   Packet - The parsed Ethernet packet.
        #   InPort - The switch port on which the packet was received.
        # Returns: None
        if Packet.dst not in self.MacToPort:
            Log.debug("Flooding packet to unknown destination")
            Msg = Of.ofp_packet_out()  # Create a packet-out message to flood the packet
            Msg.actions.append(Of.ofp_action_output(port=Of.OFPP_FLOOD))  # Add flood action to broadcast the packet
            Msg.data = Event.ofp  # Use the original packet data
            Msg.in_port = Event.port  # Set the incoming port for correct handling
            self.Connection.send(Msg)  # Send the flood message out the switch
        else:
            Port = self.MacToPort[Packet.dst]  # Retrieve the specific port for the destination MAC
            Log.debug("Forwarding packet to port %s", Port)
            Msg = Of.ofp_packet_out()  # Create a packet-out message for targeted forwarding
            Msg.actions.append(Of.ofp_action_output(port=Port))  # Add action to forward the packet to the known port
            Msg.data = Event.ofp  # Use the original packet data
            Msg.in_port = Event.port  # Set the incoming port for reference
            self.Connection.send(Msg)  # Transmit the packet-out message to the switch

    def GetNextServer(self, ClientIdentifier):
        # Determine the next backend server index to assign for load balancing.
        # Parameters:
        #   ClientIdentifier - A unique identifier for the client (MAC or IP) requesting service.
        # Returns:
        #   Integer index of the assigned backend server.
        ServerIdx = self.CurrentServer  # Retrieve the current server index for assignment
        self.CurrentServer = (self.CurrentServer + 1) % len(ServerIps)  # Update index using round-robin scheduling
        Log.info("Assigning server %s to client %s", ServerIdx, ClientIdentifier)
        return ServerIdx

    def GetServerForClient(self, ClientIp):
        # Retrieve or assign a backend server for a given client IP.
        # Parameters:
        #   ClientIp - The IP address of the client.
        # Returns:
        #   Integer index of the backend server assigned to the client.
        if ClientIp not in self.ClientToServer:
            ServerIdx = self.GetNextServer(ClientIp)  # Assign a new server using round-robin if not already assigned
            self.ClientToServer[ClientIp] = ServerIdx  # Store the mapping from client to server index

        return self.ClientToServer[ClientIp]

    def SetupFlowEntries(self, ClientIp, ServerIp, ServerIdx, ClientPort):
        # Set up flow table entries in the switch to efficiently forward traffic between a client and its backend server.
        # Parameters:
        #   ClientIp - The IP address of the client.
        #   ServerIp - The IP address of the assigned backend server.
        #   ServerIdx - The index of the backend server in the configuration lists.
        #   ClientPort - The switch port number where the client is connected.
        # Returns: None
        ServerMac = ServerMacs[ServerIdx]  # Retrieve the MAC address for the selected server
        ServerPort = self.MacToPort.get(ServerMac)  # Get the switch port associated with the server's MAC address

        if ServerPort is None:
            Log.warning("Unknown server port for %s, not setting up flow entries yet", ServerMac)
            return

        self.ClientToServer[ClientIp] = ServerIdx  # Ensure the client-to-server mapping is up-to-date

        Log.info("Setting up flow entries for %s <-> %s", ClientIp, ServerIp)
        # Create flow entry for client-to-server traffic
        Msg = Of.ofp_flow_mod()  # Construct a flow modification message
        Msg.match.dl_type = Pkt.ethernet.IP_TYPE  # Match IP packets based on Ethernet type
        Msg.match.nw_dst = VirtualIp  # Match packets destined for the virtual IP address
        Msg.match.nw_src = ClientIp  # Match packets originating from the client
        Msg.match.in_port = ClientPort  # Match packets arriving on the client's port
        Msg.actions.append(Of.ofp_action_nw_addr.set_dst(ServerIp))  # Set action to change destination IP to server IP
        Msg.actions.append(Of.ofp_action_dl_addr.set_dst(ServerMac))  # Set action to change destination MAC to server MAC
        Msg.actions.append(Of.ofp_action_output(port=ServerPort))  # Forward packet to the server port
        Msg.idle_timeout = 300  # Set flow idle timeout to free resources after inactivity
        self.Connection.send(Msg)  # Send the flow mod message to the switch

        # Create flow entry for server-to-client traffic
        Msg = Of.ofp_flow_mod()  # Construct a flow modification message for reverse traffic
        Msg.match.dl_type = Pkt.ethernet.IP_TYPE  # Match IP packets based on Ethernet type
        Msg.match.nw_src = ServerIp  # Match packets originating from the backend server
        Msg.match.nw_dst = ClientIp  # Match packets destined for the client IP
        Msg.match.in_port = ServerPort  # Match packets arriving on the server's port
        Msg.actions.append(Of.ofp_action_nw_addr.set_src(VirtualIp))  # Modify source IP to the virtual IP for transparency
        Msg.actions.append(Of.ofp_action_output(port=ClientPort))  # Forward the packet to the client's port
        Msg.idle_timeout = 300  # Set flow idle timeout to release the entry after inactivity
        self.Connection.send(Msg)  # Send the flow mod message to the switch

def Launch():
    # Entry point for starting the load balancer application.
    # Returns: None
    def StartSwitch(Event):
        # Callback function that handles new switch connections.
        # Parameters:
        #   Event - The connection event containing details of the new switch.
        # Returns: None
        Log.info("Controlling %s" % (Event.connection,))  # Log information about the new connection
        VirtualIpLoadBalancer(Event.connection)  # Instantiate a load balancer for the newly connected switch

    core.openflow.addListenerByName("ConnectionUp", StartSwitch)  # Register listener for switch connection events
>>>>>>> parent of 01292a0 (revert)

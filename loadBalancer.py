# Import POX Libraries
from pox.core import core  
import pox.openflow.libopenflow_01 as Of  
from pox.lib.addresses import EthAddr, IPAddr  
import pox.lib.packet as Pkt 
import time  

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

    # Process ARP packets to facilitate client-server mapping.
    # Parameters:
    #   Event - The OpenFlow event containing the ARP packet.
    #   Packet - The parsed Ethernet packet.
    #   InPort - The switch port on which the packet was received.
    def HandleArp(self, Event, Packet, InPort):

        ArpPacket = Packet.payload  # Extract the ARP payload from the Ethernet frame

        if ArpPacket.opcode == Pkt.arp.REQUEST:
            if ArpPacket.protodst == VirtualIp:
                Log.info("Received ARP request for virtual IP %s from %s", VirtualIp, ArpPacket.hwsrc)
                
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
            return

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

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
        ArpPacket = Packet.payload  # Extract the ARP payload from the Ethernet frame

        if ArpPacket.opcode == Pkt.arp.REQUEST:
            if ArpPacket.protodst == VirtualIp:
                Log.info("Received ARP request for virtual IP %s from %s", VirtualIp, ArpPacket.hwsrc)
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
                    break

            if ClientIp is not None:
                Log.info("IP packet from server to client: %s -> %s", IpPacket.srcip, IpPacket.dstip)
                ClientPort = self.MacToPort.get(Packet.dst)  # Look up the client’s switch port by destination MAC
                if ClientPort is None:
                    Log.warning("Unknown client port for %s", Packet.dst)
                    return

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

#!/usr/bin/env python3

import argparse
import os
import subprocess
import time
import signal
import sys

# Router and network configuration
ROUTERS = {
    "r1": {
        "interfaces": {
            "eth0": {"network": "net14", "ip": "10.0.14.4/24"},
            "eth1": {"network": "net10", "ip": "10.0.10.3/24"},
            "eth2": {"network": "net13", "ip": "10.0.13.4/24"}
        },
        "router_id": "192.168.1.1",
        "networks": ["10.0.14.0/24", "10.0.10.0/24", "10.0.13.0/24"],
        "north_interface": "eth1",  # Interface to R2
        "south_interface": "eth2"   # Interface to R4
    },
    "r2": {
        "interfaces": {
            "eth0": {"network": "net10", "ip": "10.0.10.4/24"},
            "eth1": {"network": "net11", "ip": "10.0.11.3/24"}
        },
        "router_id": "192.168.1.2",
        "networks": ["10.0.10.0/24", "10.0.11.0/24"],
        "north_interface": "eth0",  # Interface to R1
        "south_interface": "eth1"   # Interface to R3
    },
    "r3": {
        "interfaces": {
            "eth0": {"network": "net11", "ip": "10.0.11.4/24"},
            "eth1": {"network": "net12", "ip": "10.0.12.3/24"},
            "eth2": {"network": "net15", "ip": "10.0.15.4/24"}
        },
        "router_id": "192.168.1.3",
        "networks": ["10.0.11.0/24", "10.0.12.0/24", "10.0.15.0/24"],
        "north_interface": "eth0",  # Interface to R2
        "south_interface": "eth1"   # Interface to R4
    },
    "r4": {
        "interfaces": {
            "eth0": {"network": "net13", "ip": "10.0.13.3/24"},
            "eth1": {"network": "net12", "ip": "10.0.12.4/24"}
        },
        "router_id": "192.168.1.4",
        "networks": ["10.0.13.0/24", "10.0.12.0/24"],
        "north_interface": "eth0",  # Interface to R1
        "south_interface": "eth1"   # Interface to R3
    }
}

HOSTS = {
    "hosta": {
        "ip": "10.0.14.3/24",
        "interface": "eth0",
        "gateway": "10.0.14.4",
        "remote_subnet": "10.0.15.0/24"
    },
    "hostb": {
        "ip": "10.0.15.3/24",
        "interface": "eth0",
        "gateway": "10.0.15.4",
        "remote_subnet": "10.0.14.0/24"
    }
}

# Default OSPF weights
DEFAULT_WEIGHT = 10
HIGH_WEIGHT = 100

def run_command(cmd, container=None):
    """Run a command on the host or in a container"""
    try:
        if container:
            full_cmd = ["docker", "exec", container] + cmd
        else:
            full_cmd = cmd
        
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(full_cmd)}")
        print(f"Exit code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        return None

def start_containers():
    """Start Docker containers according to the docker-compose file"""
    print("Starting containers...")
    run_command(["docker", "compose", "up", "-d"])
    
    # Wait for containers to be ready
    time.sleep(5)
    print("Containers started")

def stop_containers():
    """Stop all running containers"""
    print("Stopping containers...")
    run_command(["docker", "compose", "down"])
    print("Containers stopped")

def install_frr(container):
    """Install FRR on a router container"""
    print(f"Installing FRR on {container}...")
    
    # Install prerequisites
    run_command(["apt-get", "update"], container)
    run_command(["apt", "-y", "install", "curl", "gnupg", "lsb-release"], container)
    
    # Add FRR repository key
    run_command(["bash", "-c", "curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null"], container)
    
    # Add FRR repository
    cmd = 'echo deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable | tee -a /etc/apt/sources.list.d/frr.list'
    run_command(["bash", "-c", cmd], container)
    
    # Install FRR
    run_command(["apt", "update"], container)
    run_command(["apt", "-y", "install", "frr", "frr-pythontools"], container)
    
    # Enable OSPF daemon
    run_command(["sed", "-i", "s/ospfd=no/ospfd=yes/g", "/etc/frr/daemons"], container)
    
    # Restart FRR service
    run_command(["service", "frr", "restart"], container)
    
    # Verify OSPF daemon is running
    output = run_command(["ps", "-ef", "|", "grep", "ospf"], container)
    if not output or "ospfd" not in output:
        print(f"Warning: OSPF daemon may not be running on {container}")
    else:
        print(f"OSPF daemon running on {container}")

def configure_ospf(path="north"):
    """Configure OSPF on all routers"""
    print("Configuring OSPF on all routers...")
    
    # Set weights based on the path
    if path == "north":
        # Prefer northern path (via R2)
        r1_r2_weight = DEFAULT_WEIGHT
        r2_r3_weight = DEFAULT_WEIGHT
        r1_r4_weight = HIGH_WEIGHT
        r3_r4_weight = HIGH_WEIGHT
    else:  # "south"
        # Prefer southern path (via R4)
        r1_r2_weight = HIGH_WEIGHT
        r2_r3_weight = HIGH_WEIGHT
        r1_r4_weight = DEFAULT_WEIGHT
        r3_r4_weight = DEFAULT_WEIGHT
    
    # Configure all routers
    for router, config in ROUTERS.items():
        # Create basic OSPF configuration
        configure_basic_ospf(router, config)
        
        # Set link weights based on which router this is
        if router == "r1":
            set_ospf_weight(router, ROUTERS[router]["north_interface"], r1_r2_weight)  # R1-R2 link
            set_ospf_weight(router, ROUTERS[router]["south_interface"], r1_r4_weight)  # R1-R4 link
        elif router == "r2":
            set_ospf_weight(router, ROUTERS[router]["north_interface"], r1_r2_weight)  # R2-R1 link
            set_ospf_weight(router, ROUTERS[router]["south_interface"], r2_r3_weight)  # R2-R3 link
        elif router == "r3":
            set_ospf_weight(router, ROUTERS[router]["north_interface"], r2_r3_weight)  # R3-R2 link
            set_ospf_weight(router, ROUTERS[router]["south_interface"], r3_r4_weight)  # R3-R4 link
        elif router == "r4":
            set_ospf_weight(router, ROUTERS[router]["north_interface"], r1_r4_weight)  # R4-R1 link
            set_ospf_weight(router, ROUTERS[router]["south_interface"], r3_r4_weight)  # R4-R3 link
    
    # Give OSPF time to converge
    print("Waiting for OSPF convergence...")
    time.sleep(5)
    print("OSPF configuration complete")

def configure_basic_ospf(router, config):
    """Configure basic OSPF settings for a router"""
    # Configure OSPF with router ID and networks
    ospf_config = f"""
    configure terminal
    router ospf
    ospf router-id {config['router_id']}
    """
    
    # Add all networks to OSPF area 0
    for network in config["networks"]:
        ospf_config += f"network {network} area 0.0.0.0\n"
    
    ospf_config += "exit\nend\nwrite memory"
    
    # Apply configuration
    run_command(["vtysh", "-c", ospf_config], router)

def set_ospf_weight(router, interface, weight):
    """Set OSPF weight for a specific interface"""
    # Config command to set OSPF cost
    ospf_weight_cmd = f"""
    configure terminal
    interface {interface}
    ip ospf cost {weight}
    end
    write memory
    """
    
    # Apply configuration
    run_command(["vtysh", "-c", ospf_weight_cmd], router)

def setup_host_routes():
    """Set up routes on the host machines"""
    print("Setting up routes on host machines...")
    
    for host, config in HOSTS.items():
        # Add route to reach the remote subnet through the gateway
        run_command(["ip", "route", "add", config["remote_subnet"], "via", config["gateway"]], host)
    
    print("Host routes configured")

def switch_traffic_path(from_path="north", to_path="south"):
    """Switch traffic path without causing packet drops"""
    print(f"Switching traffic from {from_path} path to {to_path} path...")
    
    # Intelligently switch paths to avoid packet loss
    # We first change the weights in a specific order
    
    if from_path == "north" and to_path == "south":
        # First lower the cost of the southern path
        print("Step 1: Lowering cost of southern path")
        set_ospf_weight("r1", ROUTERS["r1"]["south_interface"], DEFAULT_WEIGHT)  # R1-R4
        set_ospf_weight("r4", ROUTERS["r4"]["north_interface"], DEFAULT_WEIGHT)  # R4-R1
        set_ospf_weight("r3", ROUTERS["r3"]["south_interface"], DEFAULT_WEIGHT)  # R3-R4
        set_ospf_weight("r4", ROUTERS["r4"]["south_interface"], DEFAULT_WEIGHT)  # R4-R3
        
        # Wait for OSPF to converge
        print("Waiting for OSPF to converge...")
        time.sleep(5)
        
        # Then increase the cost of the northern path
        print("Step 2: Increasing cost of northern path")
        set_ospf_weight("r1", ROUTERS["r1"]["north_interface"], HIGH_WEIGHT)     # R1-R2
        set_ospf_weight("r2", ROUTERS["r2"]["north_interface"], HIGH_WEIGHT)     # R2-R1
        set_ospf_weight("r2", ROUTERS["r2"]["south_interface"], HIGH_WEIGHT)     # R2-R3
        set_ospf_weight("r3", ROUTERS["r3"]["north_interface"], HIGH_WEIGHT)     # R3-R2
        
    elif from_path == "south" and to_path == "north":
        # First lower the cost of the northern path
        print("Step 1: Lowering cost of northern path")
        set_ospf_weight("r1", ROUTERS["r1"]["north_interface"], DEFAULT_WEIGHT)  # R1-R2
        set_ospf_weight("r2", ROUTERS["r2"]["north_interface"], DEFAULT_WEIGHT)  # R2-R1
        set_ospf_weight("r2", ROUTERS["r2"]["south_interface"], DEFAULT_WEIGHT)  # R2-R3
        set_ospf_weight("r3", ROUTERS["r3"]["north_interface"], DEFAULT_WEIGHT)  # R3-R2
        
        # Wait for OSPF to converge
        print("Waiting for OSPF to converge...")
        time.sleep(5)
        
        # Then increase the cost of the southern path
        print("Step 2: Increasing cost of southern path")
        set_ospf_weight("r1", ROUTERS["r1"]["south_interface"], HIGH_WEIGHT)     # R1-R4
        set_ospf_weight("r4", ROUTERS["r4"]["north_interface"], HIGH_WEIGHT)     # R4-R1
        set_ospf_weight("r3", ROUTERS["r3"]["south_interface"], HIGH_WEIGHT)     # R3-R4
        set_ospf_weight("r4", ROUTERS["r4"]["south_interface"], HIGH_WEIGHT)     # R4-R3
    
    # Wait for OSPF to fully converge
    print("Waiting for full OSPF convergence...")
    time.sleep(5)
    print(f"Traffic switched to {to_path} path")

def show_routing_tables():
    """Display OSPF routing tables for all routers"""
    for router in ROUTERS.keys():
        print(f"\n=== {router.upper()} Routing Table ===")
        output = run_command(["vtysh", "-c", "show ip route ospf"], router)
        print(output if output else "No OSPF routes found")

def show_ospf_neighbors():
    """Display OSPF neighbors for all routers"""
    for router in ROUTERS.keys():
        print(f"\n=== {router.upper()} OSPF Neighbors ===")
        output = run_command(["vtysh", "-c", "show ip ospf neighbor"], router)
        print(output if output else "No OSPF neighbors found")

def trace_route():
    """Perform traceroute from HostA to HostB to see the path"""
    print("\n=== Traceroute from HostA to HostB ===")
    output = run_command(["traceroute", "-n", "10.0.15.3"], "hosta")
    print(output if output else "Traceroute failed")

def ping_test(count=4):
    """Perform ping test between hosts"""
    print(f"\n=== Ping test from HostA to HostB ({count} packets) ===")
    output = run_command(["ping", "-c", str(count), "10.0.15.3"], "hosta")
    print(output if output else "Ping failed")

def continuous_ping():
    """Start a continuous ping to demonstrate lossless path switching"""
    print("Starting continuous ping from HostA to HostB...")
    print("Press Ctrl+C to stop")
    
    # Start ping in the background
    ping_process = subprocess.Popen(
        ["docker", "exec", "hosta", "ping", "10.0.15.3"],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    def signal_handler(sig, frame):
        print("\nStopping ping...")
        ping_process.terminate()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Print ping output in real-time
    try:
        for line in ping_process.stdout:
            print(line.strip())
    except KeyboardInterrupt:
        print("\nStopping ping...")
        ping_process.terminate()

def main():
    """Main function to parse arguments and execute commands"""
    parser = argparse.ArgumentParser(description="Network orchestrator for traffic management")
    
    # Setup commands
    parser.add_argument("--start", action="store_true", help="Start the network topology")
    parser.add_argument("--stop", action="store_true", help="Stop the network topology")
    parser.add_argument("--setup", action="store_true", help="Set up the full network (start containers, install FRR, configure OSPF, set up routes)")
    
    # Path commands
    parser.add_argument("--use-north", action="store_true", help="Configure traffic to use the northern path (R1-R2-R3)")
    parser.add_argument("--use-south", action="store_true", help="Configure traffic to use the southern path (R1-R4-R3)")
    parser.add_argument("--switch-to-north", action="store_true", help="Switch traffic from southern to northern path")
    parser.add_argument("--switch-to-south", action="store_true", help="Switch traffic from northern to southern path")
    
    # Info commands
    parser.add_argument("--show-routes", action="store_true", help="Display OSPF routing tables")
    parser.add_argument("--show-neighbors", action="store_true", help="Display OSPF neighbors")
    parser.add_argument("--traceroute", action="store_true", help="Perform traceroute from HostA to HostB")
    parser.add_argument("--ping", action="store_true", help="Perform ping test between hosts")
    parser.add_argument("--continuous-ping", action="store_true", help="Start continuous ping (useful for demonstrating lossless path switching)")
    
    args = parser.parse_args()
    
    # Process commands
    if args.start:
        start_containers()
    
    if args.stop:
        stop_containers()
    
    if args.setup:
        start_containers()
        
        # Install FRR on all routers
        for router in ROUTERS.keys():
            install_frr(router)
        
        # Configure OSPF with default northern path
        configure_ospf("north")
        
        # Set up host routes
        setup_host_routes()
        
        print("Network setup complete")
    
    # Path configuration commands
    if args.use_north:
        configure_ospf("north")
    
    if args.use_south:
        configure_ospf("south")
    
    if args.switch_to_north:
        switch_traffic_path("south", "north")
    
    if args.switch_to_south:
        switch_traffic_path("north", "south")
    
    # Info commands
    if args.show_routes:
        show_routing_tables()
    
    if args.show_neighbors:
        show_ospf_neighbors()
    
    if args.traceroute:
        trace_route()
    
    if args.ping:
        ping_test()
    
    if args.continuous_ping:
        continuous_ping()
    
    # If no arguments are provided, show help
    if len(sys.argv) == 1:
        parser.print_help()

if __name__ == "__main__":
    main()

import argparse
import subprocess
import sys
import time

# Mapping of routers to their OSPF configuration
ROUTER_CONFIGS = {
    'r1': {
        'router_id': '1.1.1.1',
        'networks': ['10.0.14.0/24', '10.0.10.0/24', '10.0.13.0/24']
    },
    'r2': {
        'router_id': '2.2.2.2',
        'networks': ['10.0.10.0/24', '10.0.11.0/24']
    },
    'r3': {
        'router_id': '3.3.3.3',
        'networks': ['10.0.11.0/24', '10.0.12.0/24', '10.0.15.0/24']
    },
    'r4': {
        'router_id': '4.4.4.4',
        'networks': ['10.0.13.0/24', '10.0.12.0/24']
    }
}

# Hosts and their intended default gateways
HOST_ROUTES = {
    'hosta': {'del_gw': '10.0.14.1', 'add_gw': '10.0.14.4'},
    'hostb': {'del_gw': '10.0.15.1', 'add_gw': '10.0.15.4'}
}


def run(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running '{cmd}': {result.stderr}", file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout


def construct_topology():
    run('docker compose up -d')


def install_ospf():
    install_cmd = (
        "apt update && apt -y install curl gnupg lsb-release && "
        "curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null && "
        "FRRVER=\"frr-stable\" && "
        "echo 'deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER' \
        "| tee -a /etc/apt/sources.list.d/frr.list && "
        "apt update && apt -y install frr frr-pythontools && "
        "sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons && "
        "service frr restart"
    )

    for router, cfg in ROUTER_CONFIGS.items():
        print(f"Configuring FRR on {router}...")
        run(f"docker exec -i {router} bash -c \"{install_cmd}\"")

        # Build vtysh configuration script
        vtysh_cfg = 'configure terminal\n'
        vtysh_cfg += 'router ospf\n'
        vtysh_cfg += f"ospf router-id {cfg['router_id']}\n"
        for net in cfg['networks']:
            vtysh_cfg += f"network {net} area 0.0.0.0\n"
        vtysh_cfg += 'exit\n'
        vtysh_cfg += 'exit\n'

        # Push the configuration via stdin
        proc = subprocess.Popen(
            ['docker', 'exec', '-i', router, 'vtysh'],
            stdin=subprocess.PIPE,
            text=True
        )
        proc.communicate(vtysh_cfg)
        if proc.returncode != 0:
            print(f"Error configuring OSPF on {router}", file=sys.stderr)
            sys.exit(proc.returncode)


def install_host_routes():
    for host, rinfo in HOST_ROUTES.items():
        # Remove unwanted Docker-injected route (ignore failures)
        run(f"docker exec -i {host} ip route del default via {rinfo['del_gw']} dev eth0 || true")
        # Add the correct gateway
        run(f"docker exec -i {host} ip route add default via {rinfo['add_gw']} dev eth0")


def move_traffic(direction):
    if direction == 'north2south':
        cost = 100
    else:
        cost = 1

    # On R1, adjust cost on interface to R2 (eth1)
    run(f"docker exec -i r1 vtysh -c 'configure terminal' -c 'interface eth1' -c 'ip ospf cost {cost}' -c 'end'")
    # On R3, adjust cost on interface to R2 (eth1)
    run(f"docker exec -i r3 vtysh -c 'configure terminal' -c 'interface eth1' -c 'ip ospf cost {cost}' -c 'end'")

    # Allow time for OSPF to reconverge
    print("Waiting for OSPF to reconverge...")
    time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description='OSPF Orchestrator')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('up', help='Construct network topology')
    subparsers.add_parser('init_ospf', help='Install and configure OSPF daemons')
    subparsers.add_parser('host_routes', help='Install static routes on hosts')

    move_parser = subparsers.add_parser('move', help='Move traffic path')
    move_parser.add_argument(
        'direction',
        choices=['north2south', 'south2north'],
        help='north2south: prefer southern path; south2north: revert to northern path'
    )

    args = parser.parse_args()
    if args.command == 'up':
        construct_topology()
    elif args.command == 'init_ospf':
        install_ospf()
    elif args.command == 'host_routes':
        install_host_routes()
    elif args.command == 'move':
        move_traffic(args.direction)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

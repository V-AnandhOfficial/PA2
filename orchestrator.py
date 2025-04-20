#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time

# Mapping of routers to their OSPF configuration\NROUTER_CONFIGS = {
    'r1': {'router_id': '1.1.1.1', 'networks': ['10.0.14.0/24', '10.0.10.0/24', '10.0.13.0/24']},
    'r2': {'router_id': '2.2.2.2', 'networks': ['10.0.10.0/24', '10.0.11.0/24']},
    'r3': {'router_id': '3.3.3.3', 'networks': ['10.0.11.0/24', '10.0.12.0/24', '10.0.15.0/24']},
    'r4': {'router_id': '4.4.4.4', 'networks': ['10.0.13.0/24', '10.0.12.0/24']}
}

# Hosts and their intended default gateways
HOST_ROUTES = {
    'hosta': {'del_gw': '10.0.14.1', 'add_gw': '10.0.14.4'},
    'hostb': {'del_gw': '10.0.15.1', 'add_gw': '10.0.15.4'}
}


def run(cmd):
    """
    Execute a shell command; exit on failure.
    """
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running '{cmd}':\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}", file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout


def construct_topology():
    run('docker compose up -d')


def install_ospf():
    """
    Sequentially install FRR and configure OSPF on each router to avoid quoting issues.
    """
<<<<<<< HEAD
    for router, cfg in ROUTER_CONFIGS.items():
        print(f"\n--- Configuring FRR on {router} ---")
        # Update and install dependencies
        run(f"docker exec -i {router} apt update")
        run(f"docker exec -i {router} apt -y install curl gnupg lsb-release")
        run(f"docker exec -i {router} curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null")
        run(f"docker exec -i {router} apt -y install lsb-release")
        run(f"docker exec -i {router} bash -c \"echo 'deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable' > /etc/apt/sources.list.d/frr.list\"")
        run(f"docker exec -i {router} apt update")
        run(f"docker exec -i {router} apt -y install frr frr-pythontools")
        # Enable ospfd and restart
        run(f"docker exec -i {router} sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons")
        run(f"docker exec -i {router} service frr restart")
=======
    # Combined install command for FRR
    install_cmd = (
        'apt update && apt -y install curl gnupg lsb-release && '
        'curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg >/dev/null && '
        'FRRVER="frr-stable" && '
        'echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER" '
        '| tee -a /etc/apt/sources.list.d/frr.list && '
        'apt update && apt -y install frr frr-pythontools && '
        'sed -i \'s/ospfd=no/ospfd=yes/\' /etc/frr/daemons && '
        'service frr restart'
    )

    for router, cfg in ROUTER_CONFIGS.items():
        print(f"Configuring FRR on {router}...")
        # Execute install_cmd inside the router container
        run(f'docker exec -i {router} bash -c "{install_cmd}"')
>>>>>>> parent of 34efa90 (Update orchestrator.py)

        # Configure OSPF via vtysh
        vtysh_cmds = [
            'configure terminal',
            'router ospf',
            f"ospf router-id {cfg['router_id']}"
        ] + [f"network {net} area 0.0.0.0" for net in cfg['networks']] + ['end']

        proc = subprocess.Popen(
            ['docker', 'exec', '-i', router, 'vtysh'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = proc.communicate('\n'.join(vtysh_cmds) + '\n')
        if proc.returncode != 0:
            print(f"Error configuring OSPF on {router}:\nSTDOUT: {stdout}\nSTDERR: {stderr}", file=sys.stderr)
            sys.exit(proc.returncode)
        print(f"Completed OSPF config on {router}\n")


def install_host_routes():
    for host, rinfo in HOST_ROUTES.items():
        print(f"Configuring routes on {host}...")
        run(f"docker exec -i {host} ip route del default via {rinfo['del_gw']} dev eth0 || true")
        run(f"docker exec -i {host} ip route add default via {rinfo['add_gw']} dev eth0")


def move_traffic(direction):
    cost = 100 if direction == 'north2south' else 1
    print(f"Setting OSPF cost to {cost} for north path interfaces...")
    run(f"docker exec -i r1 vtysh -c 'configure terminal' -c 'interface eth1' -c 'ip ospf cost {cost}' -c 'end'")
    run(f"docker exec -i r3 vtysh -c 'configure terminal' -c 'interface eth1' -c 'ip ospf cost {cost}' -c 'end'")
    print("Waiting for OSPF to reconverge...")
    time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description='OSPF Orchestrator')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('up', help='Bring up the Docker topology')
    subparsers.add_parser('init_ospf', help='Install and configure FRR/OSPF on routers')
    subparsers.add_parser('host_routes', help='Set correct default routes on hosts')

    move = subparsers.add_parser('move', help='Switch traffic path via OSPF cost manipulation')
    move.add_argument('direction', choices=['north2south', 'south2north'], help='north2south or south2north')

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

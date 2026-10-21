#!/usr/bin/env python3
"""
ARP Spoofing / MITM Detector

Watches ARP traffic (live on a network interface, or replayed from a
log file) and flags the known signatures of ARP cache poisoning: an
IP suddenly claimed by a different MAC address (especially the default
gateway), gratuitous ARP replies nobody asked for, and a single MAC
claiming an unusual number of distinct IPs in a short window.

Live capture requires scapy and the privileges to open a raw socket on
the chosen interface (root on Linux/macOS, or an equivalent capability
grant). Replay mode has no such requirement and is how this tool is
tested.

Usage:
    sudo python3 arpwatch.py --live --iface eth0 --gateway-ip 192.168.1.1
    python3 arpwatch.py --replay capture.jsonl --gateway-ip 192.168.1.1
    python3 arpwatch.py --replay capture.jsonl --json report.json
"""

import sys
import json
import time
import argparse

from detector import ArpMonitor

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def replay_observations(path):
    """Reads newline-delimited JSON ARP events:
    {"ts": 1234.5, "op": "reply", "src_ip": "...", "src_mac": "..."}
    One tool (this one) can both produce this format (from a live
    capture, via --log-to) and consume it (via --replay), so a live
    capture taken once can be re-analyzed offline any number of times."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            yield event["ts"], event["op"], event["src_ip"], event["src_mac"]


def live_observations(iface, log_to=None):
    """Sniffs real ARP packets on `iface` using scapy and yields
    (ts, op, src_ip, src_mac) tuples as they arrive. Imports scapy
    lazily so replay mode works in environments without it installed."""
    from scapy.all import sniff, ARP

    log_file = open(log_to, "a") if log_to else None
    try:
        def handle(pkt):
            if ARP not in pkt:
                return None
            arp = pkt[ARP]
            op = "request" if arp.op == 1 else "reply" if arp.op == 2 else None
            if op is None:
                return None
            ts = time.time()
            if log_file:
                log_file.write(json.dumps({"ts": ts, "op": op, "src_ip": arp.psrc, "src_mac": arp.hwsrc}) + "\n")
                log_file.flush()
            return ts, op, arp.psrc, arp.hwsrc

        # scapy's sniff() is push-based (callback per packet); adapt it
        # to this module's pull-based (ts, op, ip, mac) generator shape
        # by handing observations to a monitor via a callback instead.
        results = []

        def on_packet(pkt):
            obs = handle(pkt)
            if obs:
                results.append(obs)

        sniff(iface=iface, filter="arp", prn=on_packet, store=False)
        for obs in results:
            yield obs
    finally:
        if log_file:
            log_file.close()


def print_finding(f):
    print(f"[{f.severity:<8}] {f.kind:<18} {f.message}")


def main():
    parser = argparse.ArgumentParser(description="Detect ARP spoofing / MITM attacks from live or replayed ARP traffic.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Capture live ARP traffic (requires scapy + raw-socket privileges)")
    mode.add_argument("--replay", metavar="FILE", help="Replay ARP events from a JSONL file instead of capturing live")
    parser.add_argument("--iface", help="Network interface to sniff on (required with --live)")
    parser.add_argument("--log-to", metavar="FILE", help="With --live, also append observed events to this JSONL file for later --replay analysis")
    parser.add_argument("--gateway-ip", help="Your network's default gateway IP - a MAC change for this IP is reported as CRITICAL")
    parser.add_argument("--many-ips-threshold", type=int, default=5, help="Distinct IPs from one MAC within the window to trigger a finding (default: 5)")
    parser.add_argument("--many-ips-window", type=float, default=30, help="Window in seconds for the many-IPs check (default: 30)")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any", "none"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high)")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    args = parser.parse_args()

    if args.live and not args.iface:
        print("Error: --live requires --iface", file=sys.stderr)
        sys.exit(2)

    monitor = ArpMonitor(gateway_ip=args.gateway_ip,
                          many_ips_threshold=args.many_ips_threshold,
                          many_ips_window=args.many_ips_window)

    if args.replay:
        observations = replay_observations(args.replay)
    else:
        try:
            observations = live_observations(args.iface, log_to=args.log_to)
        except ImportError:
            print("Error: --live requires scapy ('pip install scapy') and raw-socket privileges (usually root).", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print("Error: insufficient privileges to open a raw socket on this interface. Try running as root/sudo.", file=sys.stderr)
            sys.exit(2)

    all_findings = []
    count = 0
    try:
        for ts, op, src_ip, src_mac in observations:
            count += 1
            findings = monitor.observe(ts, op, src_ip, src_mac)
            for f in findings:
                print_finding(f)
            all_findings.extend(findings)
    except KeyboardInterrupt:
        print("\nStopped.")

    print(f"\n{count} ARP observation(s) processed, {len(all_findings)} finding(s).")

    if args.json:
        with open(args.json, "w") as f:
            json.dump([{"severity": fd.severity, "kind": fd.kind, "ts": fd.ts, "message": fd.message, **fd.data}
                       for fd in all_findings], f, indent=2)
        print(f"JSON report written to {args.json}")

    if args.fail_on == "none":
        sys.exit(0)
    if args.fail_on == "any":
        sys.exit(1 if all_findings else 0)
    threshold = SEVERITY_RANK[args.fail_on.upper()]
    worst = max((SEVERITY_RANK[f.severity] for f in all_findings), default=0)
    sys.exit(1 if worst >= threshold else 0)


if __name__ == "__main__":
    main()

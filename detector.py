"""
The actual ARP-spoofing detection logic - a pure state machine that
consumes a stream of ARP observations (one per real or replayed packet)
and flags the known signatures of ARP spoofing / MITM attacks. Kept
completely separate from how observations arrive (a live capture or a
replayed log file) so this logic can be unit-tested deterministically.

Detection signatures:

  IP-MAC rebind     An IP address that was already seen mapped to one
                     MAC address is now claimed by a different MAC.
                     This is the core ARP spoofing signature: the
                     attacker sends ARP replies claiming to own an IP
                     (usually the gateway) that really belongs to
                     someone else, so victims start sending traffic to
                     the attacker's MAC instead.

  Gateway rebind    The same signature, but specifically for a
                     configured gateway IP - raised as CRITICAL rather
                     than HIGH, since a MITM on the gateway intercepts
                     *all* of a victim's outbound traffic, not just
                     traffic to one host.

  Gratuitous reply  An ARP reply that was not preceded by a request for
                     that IP from anyone. Legitimate uses exist
                     (failover, DHCP, duplicate-address detection), so
                     this is reported at low confidence on its own -
                     it is far more significant when it also triggers
                     an IP-MAC rebind.

  One MAC, many IPs  A single MAC address claiming an unusual number of
                     distinct IP addresses in a short time window -
                     consistent with an attacker ARP-scanning or
                     spoofing multiple hosts on the segment at once.
"""

import time
from collections import defaultdict, deque


class Finding:
    def __init__(self, severity, kind, ts, message, **data):
        self.severity = severity
        self.kind = kind
        self.ts = ts
        self.message = message
        self.data = data

    def __repr__(self):
        return f"<{self.severity} {self.kind} @{self.ts}: {self.message}>"


class ArpMonitor:
    def __init__(self, gateway_ip=None, many_ips_threshold=5, many_ips_window=30):
        self.gateway_ip = gateway_ip
        self.many_ips_threshold = many_ips_threshold
        self.many_ips_window = many_ips_window

        self.ip_to_mac = {}              # ip -> (mac, last_seen_ts)
        self.requested_ips = set()       # IPs we've seen an ARP *request* for
        self.mac_to_recent_ips = defaultdict(lambda: deque())  # mac -> deque[(ts, ip)]

    def observe(self, ts, op, src_ip, src_mac):
        """op: 'request' or 'reply'. Returns a list of Finding objects
        triggered by this single observation (usually 0 or 1, sometimes
        more)."""
        findings = []

        if op == "request":
            self.requested_ips.add(src_ip)
            # A request also tells us the sender's real IP/MAC binding.

        if src_ip in self.ip_to_mac:
            prev_mac, prev_ts = self.ip_to_mac[src_ip]
            if prev_mac != src_mac:
                if src_ip == self.gateway_ip:
                    findings.append(Finding(
                        "CRITICAL", "gateway_rebind", ts,
                        f"Gateway IP {src_ip} changed MAC from {prev_mac} to {src_mac} - "
                        f"likely ARP spoofing of the default gateway (full MITM on this host's traffic).",
                        ip=src_ip, old_mac=prev_mac, new_mac=src_mac,
                    ))
                else:
                    findings.append(Finding(
                        "HIGH", "ip_mac_rebind", ts,
                        f"{src_ip} changed MAC from {prev_mac} to {src_mac} - "
                        f"a host's IP suddenly being claimed by a different MAC is the core ARP-spoofing signature.",
                        ip=src_ip, old_mac=prev_mac, new_mac=src_mac,
                    ))

        if op == "reply" and src_ip not in self.requested_ips:
            findings.append(Finding(
                "LOW", "gratuitous_reply", ts,
                f"Gratuitous ARP reply from {src_mac} claiming {src_ip} - no request for this IP was observed. "
                f"Can be legitimate (failover/DHCP), but is also how spoofed bindings get pushed onto a LAN unasked.",
                ip=src_ip, mac=src_mac,
            ))

        self.ip_to_mac[src_ip] = (src_mac, ts)

        recent = self.mac_to_recent_ips[src_mac]
        recent.append((ts, src_ip))
        while recent and ts - recent[0][0] > self.many_ips_window:
            recent.popleft()
        distinct_ips = {ip for _, ip in recent}
        if len(distinct_ips) >= self.many_ips_threshold:
            findings.append(Finding(
                "MEDIUM", "one_mac_many_ips", ts,
                f"MAC {src_mac} has claimed {len(distinct_ips)} distinct IPs in the last {self.many_ips_window}s "
                f"({', '.join(sorted(distinct_ips))}) - consistent with ARP scanning or spoofing multiple hosts at once.",
                mac=src_mac, ips=sorted(distinct_ips),
            ))

        return findings

    def observe_many(self, observations):
        """observations: iterable of (ts, op, src_ip, src_mac). Returns
        the combined list of findings across all of them, in order."""
        all_findings = []
        for ts, op, src_ip, src_mac in observations:
            all_findings.extend(self.observe(ts, op, src_ip, src_mac))
        return all_findings

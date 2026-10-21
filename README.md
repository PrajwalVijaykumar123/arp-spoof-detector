# ARP Spoofing / MITM Detector

Watches ARP traffic — live on a network interface, or replayed from a saved capture — and flags the known signatures of ARP cache poisoning: the attack behind most LAN man-in-the-middle tools (arpspoof, Ettercap, Bettercap's ARP module). An IP address suddenly claimed by a different MAC is the core signature; when that IP is the default gateway, every bit of a victim's outbound traffic is at risk of being funneled through the attacker.

**Only run live capture on networks you own or are authorized to monitor.**

## What This Project Does

Four independent detection signatures, run against a stream of ARP observations:

- **Gateway rebind (CRITICAL)** — the configured gateway IP starts being claimed by a MAC address that isn't the one it was previously seen with. This is the specific case that enables a full MITM on a victim's traffic, not just traffic to one host.
- **IP-MAC rebind (HIGH)** — the same signature for any other IP. A host's address being claimed by a new MAC, with no corresponding explanation (a NIC swap, a DHCP lease change), is the textbook ARP-spoofing pattern.
- **Gratuitous reply (LOW)** — an ARP reply for an IP nobody has requested. Legitimate in some cases (failover, DHCP), but it's also exactly how a spoofed binding gets pushed onto a LAN unprompted — reported at low confidence on its own, much more significant alongside a rebind finding.
- **One MAC, many IPs (MEDIUM)** — a single MAC address claiming an unusual number of distinct IPs within a short window, consistent with an attacker ARP-scanning or spoofing several hosts on the segment at once.

**Two ways to feed it ARP traffic:**
- `--live --iface eth0` — real-time capture via `scapy`, for use on your own network (needs raw-socket privileges, i.e. root)
- `--replay capture.jsonl` — replays a saved JSONL capture (which `--live --log-to` can also produce) through the exact same detection logic, with no special privileges needed

## Why detection is decoupled from capture

The actual spoofing-detection logic (`detector.py`) takes a plain `(timestamp, op, ip, mac)` tuple and knows nothing about sockets, interfaces, or scapy. Live capture and replay are just two different ways of producing that stream. This matters for more than code cleanliness: a captured JSONL log from a live session can be re-analyzed offline any number of times (with a different `--gateway-ip`, say), and the detection logic itself can be fully tested without root privileges or a real network interface — which is how this project's own test suite works.

## Example Output

```
[CRITICAL] gateway_rebind     Gateway IP 192.168.1.1 changed MAC from aa:aa:aa:aa:aa:01 to ff:ff:ff:ff:ff:99 - likely ARP spoofing of the default gateway (full MITM on this host's traffic).

12 ARP observation(s) processed, 1 finding(s).
```

(Real output from the test suite's attack-pattern fixture - a gateway rebind matching the exact sequence a tool like arpspoof produces: a clean ARP history, then a gratuitous reply claiming the gateway's IP under a different MAC.)

## Tech Stack

- Python 3.11, standard library only for replay mode
- `scapy` for live packet capture (only needed for `--live`)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # only needed for --live
```

```bash
# Live capture on your own network (needs root/raw-socket privileges):
sudo python3 arpwatch.py --live --iface eth0 --gateway-ip 192.168.1.1

# Save what you capture for later offline analysis:
sudo python3 arpwatch.py --live --iface eth0 --log-to capture.jsonl

# Replay a saved capture (no privileges needed) - try it right now with
# the bundled sample, which contains a real gateway-spoofing pattern:
python3 arpwatch.py --replay test_fixtures/sample_capture.jsonl --gateway-ip 192.168.1.1
```

## Testing

`test_fixtures/make_capture.py` builds a realistic JSONL ARP capture: normal startup traffic for a gateway and a host, then an attacker sending periodic gratuitous ARP replies claiming the gateway's IP under a different MAC — the exact pattern real ARP-spoofing tools produce, not a synthetic edge case invented for the test.

```bash
sh test_fixtures/run_test.sh
```

This runs the real `arpwatch.py --replay` against that capture and checks: the attack is caught and classified as `gateway_rebind` with `CRITICAL` severity when `--gateway-ip` is set, the same rebind is still caught (as `HIGH`/`ip_mac_rebind`) when it isn't, both the old and new MAC addresses are named in the finding, the JSON report is correctly structured, and pure benign traffic with no attack produces zero findings and a clean exit code.

## Architecture

```
Live capture (scapy sniff on --iface)   OR   --replay capture.jsonl
        |                                              |
        v                                              v
   (ts, op="request"/"reply", src_ip, src_mac) observation stream
        |
        v
detector.py ArpMonitor.observe() per event:
  - is this IP already bound to a different MAC? -> rebind finding
    (CRITICAL if it's the configured gateway, HIGH otherwise)
  - is this a reply for an IP nobody requested?   -> gratuitous finding
  - has this MAC claimed too many distinct IPs
    in the configured time window?                -> many-IPs finding
        |
        v
Console findings (as they occur, live or replayed) + optional JSON report
Exit code reflects worst finding against --fail-on threshold
```

## Project Structure

```
arp-spoof-detector/
├── arpwatch.py                    # CLI: live capture / replay, reporting, exit codes
├── detector.py                     # Pure detection logic - the ArpMonitor state machine
├── requirements.txt                  # scapy, only required for --live
└── test_fixtures/
    ├── make_capture.py             # Builds a realistic attack-pattern JSONL capture
    ├── sample_capture.jsonl        # A pre-built capture to try --replay against immediately
    └── run_test.sh                   # Runs arpwatch.py --replay against it, verifies findings
```

## What I Learned

- ARP has no authentication whatsoever built into the protocol - any host on a LAN segment can claim to own any IP address, and nothing in ARP itself distinguishes a legitimate binding from a forged one. Detection has to work entirely from *behavioral* signatures (a binding changing unexpectedly) rather than anything cryptographic, which is a meaningfully different problem shape than most of this portfolio's other tools
- Decoupling detection logic from packet capture isn't just nice architecture here - it's what makes the tool testable at all. There's no practical way to generate real, meaningful ARP broadcast traffic inside a sandboxed/containerized test environment, so building the core logic to consume a replayable event stream (which a live capture also happens to produce) was the only way to get genuine, repeatable test coverage rather than "trust me, it probably works on a real network"
- The gateway-specific severity bump (CRITICAL vs. HIGH for the identical underlying signature) reflects a real asymmetry in impact: spoofing an arbitrary host's IP affects traffic meant for that one host, but spoofing the gateway intercepts everything a victim sends off-LAN - the same detection logic, but the blast radius differs by orders of magnitude depending on which IP got spoofed
- A single spoofed-reply event only produces one finding at the moment of the *rebind* - an attacker that keeps re-sending the same spoofed reply to maintain cache poisoning (which real tools do, periodically) doesn't generate a fresh alert each time under this design, since nothing changed from the previous observation. Worth knowing as a limitation, not a bug: ongoing poisoning after the initial alert needs a separate "is the gateway binding still wrong" periodic check, not just change detection

## Next Steps

- A periodic "current gateway binding is still spoofed" check, rather than only alerting on the moment of change, to catch a detector that starts mid-attack or restarts while poisoning is ongoing
- Cross-reference with a known-good static ARP table (for small, stable networks) rather than only "did this change," to catch an attack present from the very first observation
- Active response: resending correct ARP information to restore a victim's cache (out of scope for a detection-only tool, but the natural next step for defense)
- IPv6 equivalent (NDP spoofing uses a different protocol but the same underlying trust problem)

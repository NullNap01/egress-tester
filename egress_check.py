#!/usr/bin/env python3
"""
egress_check.py — Audit outbound (egress) port filtering from this host.

Attempts TCP connections from THIS host to an external target on a list of
ports. Ports that connect = allowed egress. Ports that time out / are
refused-by-firewall = blocked.

Each port carries a RISK rating for how dangerous it is to allow outbound
in a typical corporate/server environment:

    CRITICAL — known malware C2, remote-admin, or data-store protocol;
               must never egress
    HIGH     — sensitive service or common abuse vector; allow only with
               strong justification
    MEDIUM   — legitimate use exists but risky if unrestricted
    LOW      — required for normal operation (DNS, HTTP, HTTPS, NTP)
    INFO     — unknown / uncatalogued port

Use this to verify that your firewall / security group / cloud NACL is
enforcing a default-deny egress policy and only permitting required ports.

USAGE
    python3 egress_check.py                       # common ports to portquiz.net
    python3 egress_check.py --target 1.1.1.1 --ports 53,80,443
    python3 egress_check.py --full                # sweep 1-1024
    python3 egress_check.py --min-risk HIGH       # only report HIGH+ findings
    python3 egress_check.py --allow 22,53,80,443  # per-engagement allowlist

AUTHORIZATION
    Only run against a target you own or have written permission to probe.
    portquiz.net is a public service that listens on all TCP ports for
    exactly this purpose and is safe to use.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
import sys
from dataclasses import dataclass, field

DEFAULT_TARGET = "portquiz.net"

# Risk levels, ordered low -> high for filtering / sorting.
RISK_ORDER = ["LOW", "INFO", "MEDIUM", "HIGH", "CRITICAL"]
RISK_RANK = {name: i for i, name in enumerate(RISK_ORDER)}


@dataclass(frozen=True)
class PortInfo:
    service: str
    risk: str      # one of RISK_ORDER
    guidance: str  # what to do about it


# Ports worth testing, with service name, risk rating, and guidance.
# Risk reflects the danger of allowing this port OUTBOUND from a typical
# workload — not the danger of running the service itself.
COMMON_PORTS: dict[int, PortInfo] = {
    21:   PortInfo("FTP",              "HIGH",     "Legacy cleartext file transfer — block"),
    22:   PortInfo("SSH",              "HIGH",     "Allow only for admin jump hosts, not general workloads"),
    23:   PortInfo("Telnet",           "CRITICAL", "Cleartext remote shell — always block"),
    25:   PortInfo("SMTP",             "HIGH",     "Spam / mail-relay abuse vector — block unless dedicated mail server"),
    53:   PortInfo("DNS",              "LOW",      "Allow, but force through internal resolvers only"),
    69:   PortInfo("TFTP",             "HIGH",     "Unauthenticated file transfer — block"),
    80:   PortInfo("HTTP",             "LOW",      "Allow via forward proxy; log destinations"),
    110:  PortInfo("POP3",             "HIGH",     "Cleartext mail retrieval — block"),
    111:  PortInfo("RPCbind",          "HIGH",     "RPC portmapper — must not egress"),
    123:  PortInfo("NTP",              "LOW",      "Allow to trusted time sources only"),
    135:  PortInfo("MS-RPC",           "CRITICAL", "Windows RPC — never egress the network"),
    137:  PortInfo("NetBIOS Name",     "CRITICAL", "Windows file/print — never egress"),
    139:  PortInfo("NetBIOS Session",  "CRITICAL", "Windows file/print — never egress"),
    143:  PortInfo("IMAP",             "HIGH",     "Cleartext mail — block"),
    161:  PortInfo("SNMP",             "HIGH",     "Device management — must not egress"),
    389:  PortInfo("LDAP",             "HIGH",     "Directory service — must not egress"),
    443:  PortInfo("HTTPS",            "LOW",      "Allow via forward proxy; log destinations"),
    445:  PortInfo("SMB",              "CRITICAL", "File sharing — must never leave the network (WannaCry vector)"),
    465:  PortInfo("SMTPS",            "MEDIUM",   "Allow only for mail clients"),
    514:  PortInfo("Syslog",           "MEDIUM",   "Allow only to trusted log collector"),
    587:  PortInfo("SMTP submission",  "MEDIUM",   "Allow only for mail clients"),
    636:  PortInfo("LDAPS",            "HIGH",     "Directory service — must not egress"),
    873:  PortInfo("rsync",            "HIGH",     "File sync — block unless explicitly needed"),
    993:  PortInfo("IMAPS",            "MEDIUM",   "Allow only for mail clients"),
    995:  PortInfo("POP3S",            "MEDIUM",   "Allow only for mail clients"),
    1080: PortInfo("SOCKS proxy",      "HIGH",     "Commonly abused for tunneling — block"),
    1433: PortInfo("MSSQL",            "CRITICAL", "Database — never egress"),
    1434: PortInfo("MSSQL Browser",    "CRITICAL", "Database discovery — never egress"),
    1521: PortInfo("Oracle DB",        "CRITICAL", "Database — never egress"),
    2049: PortInfo("NFS",              "CRITICAL", "Network file system — never egress"),
    3306: PortInfo("MySQL",            "CRITICAL", "Database — never egress"),
    3389: PortInfo("RDP",              "CRITICAL", "Remote desktop — never egress"),
    4444: PortInfo("Metasploit",       "CRITICAL", "Well-known malware C2 port — block and alert"),
    5432: PortInfo("PostgreSQL",       "CRITICAL", "Database — never egress"),
    5900: PortInfo("VNC",              "CRITICAL", "Remote desktop — never egress"),
    5985: PortInfo("WinRM HTTP",       "CRITICAL", "Windows remoting — never egress"),
    5986: PortInfo("WinRM HTTPS",      "CRITICAL", "Windows remoting — never egress"),
    6379: PortInfo("Redis",            "CRITICAL", "In-memory DB — never egress"),
    6667: PortInfo("IRC",              "CRITICAL", "Classic botnet C2 — block and alert"),
    8080: PortInfo("HTTP-alt",         "MEDIUM",   "Often proxy or C2 — scrutinize destination"),
    8443: PortInfo("HTTPS-alt",        "MEDIUM",   "Often C2 — scrutinize destination"),
    9001: PortInfo("Tor OR port",      "HIGH",     "Tor relay — block unless anonymity is a requirement"),
    9050: PortInfo("Tor SOCKS",        "HIGH",     "Tor client — block"),
    9200: PortInfo("Elasticsearch",    "CRITICAL", "Datastore — never egress"),
    11211:PortInfo("Memcached",        "CRITICAL", "In-memory cache — never egress (amplification abuse)"),
    27017:PortInfo("MongoDB",          "CRITICAL", "Database — never egress"),
}

# Ports that a hardened egress policy should typically ALLOW.
# 22 (SSH) is included because this tool is used for security auditing —
# clients keep SSH open so the auditor can connect back in.
EXPECTED_ALLOWED = {22, 53, 80, 443}

# Default rating for a port not in the catalog.
UNKNOWN = PortInfo("unknown", "INFO", "Port not in catalog — investigate why egress is open")


@dataclass
class Result:
    port: int
    protocol: str
    open: bool
    info: PortInfo
    error: str = ""


def check_tcp(target: str, port: int, timeout: float) -> Result:
    info = COMMON_PORTS.get(port, UNKNOWN)
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return Result(port, "tcp", True, info)
    except socket.timeout:
        return Result(port, "tcp", False, info, "timeout (likely filtered)")
    except ConnectionRefusedError:
        # Reached the target — nothing was listening. Egress path is OPEN.
        return Result(port, "tcp", True, info, "refused (egress allowed, no listener)")
    except OSError as e:
        return Result(port, "tcp", False, info, f"error: {e}")


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)


def classify(results: list[Result], allowed: set[int]) -> tuple[list[Result], list[Result], list[Result]]:
    """Returns (should_be_allowed_and_are, unexpectedly_open, blocked)."""
    expected_open, unexpected_open, blocked = [], [], []
    for r in results:
        if r.open:
            (expected_open if r.port in allowed else unexpected_open).append(r)
        else:
            blocked.append(r)
    return expected_open, unexpected_open, blocked


def highest_risk(results: list[Result]) -> str:
    if not results:
        return "LOW"
    return max(results, key=lambda r: RISK_RANK[r.info.risk]).info.risk


def main() -> int:
    ap = argparse.ArgumentParser(description="Egress port filtering audit with risk ratings.")
    ap.add_argument("--target", default=DEFAULT_TARGET,
                    help=f"Host to probe (default: {DEFAULT_TARGET})")
    ap.add_argument("--ports", default=",".join(str(p) for p in COMMON_PORTS),
                    help="Comma-separated ports and/or ranges, e.g. 22,80,443,8000-8100")
    ap.add_argument("--full", action="store_true",
                    help="Sweep TCP 1-1024 (overrides --ports)")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="Per-port timeout in seconds (default 3)")
    ap.add_argument("--workers", type=int, default=50,
                    help="Concurrent probes (default 50)")
    ap.add_argument("--min-risk", choices=RISK_ORDER, default="INFO",
                    help="Only report unexpected-open findings at or above this risk")
    ap.add_argument("--allow", default=None,
                    help="Comma-separated allowlist of ports expected to be open "
                         "for this engagement (overrides the built-in "
                         f"{sorted(EXPECTED_ALLOWED)} default)")
    args = ap.parse_args()

    if args.allow is not None:
        try:
            allowed = set(parse_ports(args.allow))
        except ValueError:
            print(f"Invalid --allow value: {args.allow!r}", file=sys.stderr)
            return 2
    else:
        allowed = set(EXPECTED_ALLOWED)

    ports = list(range(1, 1025)) if args.full else parse_ports(args.ports)
    if not ports:
        print("No ports to check.", file=sys.stderr)
        return 2

    print(f"[*] Egress audit: target={args.target}  ports={len(ports)}  "
          f"timeout={args.timeout}s  workers={args.workers}")
    print("[*] 'OPEN' = egress is allowed from this host to that port on the target.")
    print(f"[*] Allowlist: {sorted(allowed)}")
    print(f"[*] Findings threshold: >= {args.min_risk}\n")

    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_tcp, args.target, p, args.timeout): p
                   for p in ports}
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    results.sort(key=lambda r: r.port)

    # Per-port table
    print(f"{'PORT':>6}  {'PROTO':<5} {'STATE':<8} {'RISK':<8} {'SERVICE':<18} GUIDANCE")
    print("-" * 100)
    for r in results:
        state = "OPEN" if r.open else "BLOCKED"
        guidance = r.info.guidance
        if r.error and not r.open:
            guidance = f"{guidance}  [{r.error}]"
        elif r.error and r.open:
            guidance = f"{guidance}  [{r.error}]"
        print(f"{r.port:>6}  {r.protocol:<5} {state:<8} {r.info.risk:<8} "
              f"{r.info.service:<18} {guidance}")

    expected_open, unexpected_open, blocked = classify(results, allowed)

    # Risk breakdown across all OPEN ports
    open_by_risk: dict[str, list[Result]] = {level: [] for level in RISK_ORDER}
    for r in expected_open + unexpected_open:
        open_by_risk[r.info.risk].append(r)

    print("\n=== SUMMARY ===")
    print(f"  Total probed         : {len(results)}")
    print(f"  Blocked              : {len(blocked)}")
    print(f"  Open (all)           : {len(expected_open) + len(unexpected_open)}")
    print(f"  Expected-open (safe) : {len(expected_open)} "
          f"-> {[r.port for r in expected_open]}")
    print(f"  Unexpectedly open    : {len(unexpected_open)} "
          f"-> {[r.port for r in unexpected_open]}")

    print("\n  Open ports by risk:")
    for level in reversed(RISK_ORDER):  # print CRITICAL first
        rs = open_by_risk[level]
        if rs:
            print(f"    {level:<8} : {[r.port for r in rs]}")

    # Findings: unexpected-open ports at or above --min-risk
    threshold = RISK_RANK[args.min_risk]
    findings = [r for r in unexpected_open if RISK_RANK[r.info.risk] >= threshold]
    findings.sort(key=lambda r: (-RISK_RANK[r.info.risk], r.port))

    if findings:
        overall = highest_risk(findings)
        print(f"\n[!] {len(findings)} finding(s) at risk >= {args.min_risk}. "
              f"Highest severity: {overall}")
        print("    In a hardened environment, egress should be default-deny; "
              "review each and remove or justify.")
        for r in findings:
            print(f"      [{r.info.risk:<8}] {r.port}/tcp  {r.info.service:<18} — {r.info.guidance}")
        # Exit code reflects severity: 2 for CRITICAL/HIGH, 1 for lower.
        return 2 if RISK_RANK[overall] >= RISK_RANK["HIGH"] else 1

    print("\n[+] No findings at or above the configured risk threshold.")
    print("    Egress posture looks consistent with a default-deny policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

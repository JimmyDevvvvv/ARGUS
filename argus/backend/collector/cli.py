"""
M1 - CLI entrypoint.

    python -m collector.cli 10.10.20.0/24

Runs ingest_subnet() and prints a short summary. This is the
"zero-config: point at a subnet, get a sector" path for M1, ahead of
app/routers/discovery.py exposing the same thing over HTTP.

Note: nmap's OS detection (-O) requires administrator / root.
  Windows : run PowerShell as Administrator
  Linux   : sudo python -m collector.cli <cidr>
"""

from __future__ import annotations

import sys

from .ingest import ingest_subnet


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m collector.cli <cidr>")
        print("  e.g. python -m collector.cli 192.168.1.0/24")
        raise SystemExit(1)

    cidr = sys.argv[1]

    print(f"[*] Starting ARGUS M1 discovery on {cidr}")
    print("[*] This requires nmap on PATH and may need admin/root for OS detection.")
    print()

    try:
        sector = ingest_subnet(cidr)
    except Exception as exc:
        print(f"[!] Discovery failed: {exc}")
        raise SystemExit(1)

    hosts = sector.get("hosts", [])
    print(f"[+] Sector '{sector['name']}' ({cidr})")
    print(f"[+] {len(hosts)} host(s) discovered and written to Neo4j")
    print()

    # Summary table
    status_counts: dict[str, int] = {}
    for h in hosts:
        s = h.get("status", "normal")
        status_counts[s] = status_counts.get(s, 0) + 1

    for status, count in sorted(status_counts.items()):
        print(f"    {status:<12} {count}")

    if any(h.get("status") == "vulnerable" for h in hosts):
        print()
        print("[!] Vulnerable hosts:")
        for h in hosts:
            if h.get("status") == "vulnerable":
                print(f"    {h['id']:<16} {h['ip']:<16} {h.get('note', '')}")


if __name__ == "__main__":
    main()

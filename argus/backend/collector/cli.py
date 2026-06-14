"""
M1 - CLI entrypoint.

    python -m collector.cli 10.10.20.0/24

Runs ingest_subnet() and prints a short summary. This is the
"zero-config: point at a subnet, get a sector" path for M1, ahead of
app/routers/discovery.py exposing the same thing over HTTP.
"""

from __future__ import annotations

import sys

from .ingest import ingest_subnet


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m collector.cli <cidr>")
        raise SystemExit(1)

    cidr = sys.argv[1]
    sector = ingest_subnet(cidr)
    print(
        f"Discovered {len(sector.get('hosts', []))} host(s) in {cidr} "
        f"-> sector '{sector.get('name')}'"
    )


if __name__ == "__main__":
    main()

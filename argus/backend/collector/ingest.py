"""
M1 - orchestrates discover -> fingerprint -> layout -> Neo4j.

This is the M1 equivalent of app/seed.py, but for real, discovered
data instead of hand-authored seed data. Both the CLI (cli.py) and
the API (app/routers/discovery.py) call this.
"""

from __future__ import annotations

from app.db import session

from .discover import discover_subnet
from .fingerprint import normalize_os
from .layout import layout_sector


def ingest_subnet(cidr: str) -> dict:
    """
    Discover `cidr`, write a Sector + Host nodes + CONTAINS edges
    into Neo4j, and return the resulting sector dict (with hosts
    nested, same shape as /api/topology).

    MERGEs on host id (the host's IP, for now), so re-running this
    on the same subnet updates existing hosts rather than
    duplicating them.
    """
    # TODO (M1):
    #   raw = discover_subnet(cidr)
    #   hosts = [{
    #       "id": h["ip"], "ip": h["ip"], "os": normalize_os(h["osmatches"]),
    #       "owner": "Unassigned", "status": "normal",
    #       "note": "Discovered by ARGUS.",
    #   } for h in raw]
    #   sector = layout_sector(cidr, hosts)
    #   sector["hosts"] = hosts
    #
    #   write sector + hosts + CONTAINS via Cypher (mirrors app/seed.py's
    #   seed_sectors_and_hosts(), but for one sector at a time)
    #
    #   return sector
    raise NotImplementedError

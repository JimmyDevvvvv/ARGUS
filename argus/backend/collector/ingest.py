"""
M1 - orchestrates discover -> fingerprint -> layout -> Neo4j.

This is the M1 equivalent of app/seed.py, but for real, discovered
data instead of hand-authored seed data. Both the CLI (cli.py) and
the API (app/routers/discovery.py) call this.
"""

from __future__ import annotations

from app.db import session

from .discover import discover_subnet
from .fingerprint import fingerprint_host
from .layout import layout_sector


def ingest_subnet(cidr: str) -> dict:
    """
    Discover `cidr`, write Sector + Host nodes + CONTAINS edges
    into Neo4j, and return the resulting sector dict (with hosts
    nested, same shape as /api/topology).

    MERGEs on host id so re-running after a rescan updates existing
    hosts rather than duplicating them.
    """
    # 1. Discover live hosts via nmap
    raw_hosts = discover_subnet(cidr)

    # 2. Fingerprint: OS, host type, risk status
    enriched = [fingerprint_host(h) for h in raw_hosts]

    # 3. Assign map coordinates (mutates hosts in-place, returns sector dict)
    sector = layout_sector(cidr, enriched)

    # 4. Write to Neo4j
    with session() as s:
        # Upsert sector node
        s.run(
            """
            MERGE (sec:Sector {id: $id})
            SET sec.name = $name,
                sec.cidr = $cidr,
                sec.x    = $x,
                sec.y    = $y,
                sec.w    = $w,
                sec.h    = $h
            """,
            id=sector["id"],
            name=sector["name"],
            cidr=sector["cidr"],
            x=sector["x"], y=sector["y"],
            w=sector["w"], h=sector["h"],
        )

        for host in sector["hosts"]:
            # Upsert host node
            s.run(
                """
                MERGE (h:Host {id: $id})
                SET h.ip        = $ip,
                    h.hostname  = $hostname,
                    h.mac       = $mac,
                    h.os        = $os,
                    h.host_type = $host_type,
                    h.owner     = $owner,
                    h.status    = $status,
                    h.note      = $note,
                    h.x         = $x,
                    h.y         = $y,
                    h.last_seen = timestamp()
                """,
                id=host["id"],
                ip=host["ip"],
                hostname=host.get("hostname"),
                mac=host.get("mac"),
                os=host.get("os", "Unknown"),
                host_type=host.get("host_type", "unknown"),
                owner=host.get("owner", "Unassigned"),
                status=host.get("status", "normal"),
                note=host.get("note", ""),
                x=host["x"], y=host["y"],
            )

            # CONTAINS relationship
            s.run(
                """
                MATCH (sec:Sector {id: $sector_id})
                MATCH (h:Host    {id: $host_id})
                MERGE (sec)-[:CONTAINS]->(h)
                """,
                sector_id=sector["id"],
                host_id=host["id"],
            )

    return sector

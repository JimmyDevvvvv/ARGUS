"""
Seed Neo4j with the M0 demo topology (seed_data.py).

Run inside the backend container:
    docker compose exec backend python -m app.seed

Idempotent - clears existing Sector/Host nodes first, so it's safe
to re-run after changing seed_data.py.
"""

from .db import session
from .seed_data import ATTACK_EDGES, SECTORS


def clear():
    with session() as s:
        s.run("MATCH (n) WHERE n:Sector OR n:Host DETACH DELETE n")


def create_constraints():
    with session() as s:
        s.run("CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE")
        s.run("CREATE CONSTRAINT sector_id IF NOT EXISTS FOR (s:Sector) REQUIRE s.id IS UNIQUE")


def seed_sectors_and_hosts():
    with session() as s:
        for sector in SECTORS:
            s.run(
                """
                MERGE (s:Sector {id: $id})
                SET s.name = $name, s.cidr = $cidr,
                    s.x = $x, s.y = $y, s.w = $w, s.h = $h
                """,
                **{k: sector[k] for k in ("id", "name", "cidr", "x", "y", "w", "h")},
            )
            for host in sector["hosts"]:
                s.run(
                    """
                    MERGE (h:Host {id: $id})
                    SET h.ip = $ip, h.os = $os, h.owner = $owner,
                        h.status = $status, h.x = $x, h.y = $y, h.note = $note
                    WITH h
                    MATCH (sec:Sector {id: $sector_id})
                    MERGE (sec)-[:CONTAINS]->(h)
                    """,
                    sector_id=sector["id"],
                    **host,
                )


def seed_attack_edges():
    with session() as s:
        for edge in ATTACK_EDGES:
            s.run(
                """
                MATCH (a:Host {id: $from}), (b:Host {id: $to})
                MERGE (a)-[r:CAN_REACH]->(b)
                SET r.technique = $technique
                """,
                **edge,
            )


def run():
    print("Clearing existing Sector/Host data...")
    clear()
    print("Creating constraints...")
    create_constraints()
    print("Seeding sectors and hosts...")
    seed_sectors_and_hosts()
    print("Seeding attack-path edges...")
    seed_attack_edges()
    print("Done.")


if __name__ == "__main__":
    run()

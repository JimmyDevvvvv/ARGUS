from fastapi import APIRouter

from .. import db
from ..seed_data import ATTACK_EDGES, SECTORS

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "neo4j": db.is_available()}


@router.get("/topology")
def get_topology():
    """
    Returns sectors, each with their hosts nested inside.

    Falls back to the seed dataset (in-process, no DB hit) if Neo4j
    isn't reachable yet - keeps frontend dev unblocked and Compose
    startup-order-independent.
    """
    if not db.is_available():
        return {"source": "seed_fallback", "sectors": SECTORS}

    with db.session() as s:
        result = s.run(
            """
            MATCH (sec:Sector)
            OPTIONAL MATCH (sec)-[:CONTAINS]->(h:Host)
            RETURN sec, collect(h) AS hosts
            ORDER BY sec.id
            """
        )
        sectors = []
        for record in result:
            sec = dict(record["sec"])
            sec["hosts"] = [dict(h) for h in record["hosts"]]
            sectors.append(sec)

    return {"source": "neo4j", "sectors": sectors}


@router.get("/attack-paths")
def get_attack_paths():
    """
    Returns CAN_REACH chains as ordered lists of host ids plus the
    technique for each hop. The frontend resolves ids to coordinates
    using the /topology response it already has.

    The "maximal chain" query below is a placeholder - M4 replaces
    this with shortestPath/allShortestPaths to tagged crown jewels.
    """
    if not db.is_available():
        chain = [ATTACK_EDGES[0]["from"]]
        hops = []
        for edge in ATTACK_EDGES:
            chain.append(edge["to"])
            hops.append({"from": edge["from"], "to": edge["to"], "technique": edge["technique"]})
        return {"source": "seed_fallback", "paths": [{"hosts": chain, "hops": hops}]}

    with db.session() as s:
        result = s.run(
            """
            MATCH p=(a:Host)-[:CAN_REACH*]->(b:Host)
            WHERE NOT ()-[:CAN_REACH]->(a) AND NOT (b)-[:CAN_REACH]->()
            RETURN p
            """
        )
        paths = []
        for record in result:
            p = record["p"]
            hosts = [node["id"] for node in p.nodes]
            hops = [
                {
                    "from": rel.start_node["id"],
                    "to": rel.end_node["id"],
                    "technique": rel.get("technique"),
                }
                for rel in p.relationships
            ]
            paths.append({"hosts": hosts, "hops": hops})

    return {"source": "neo4j", "paths": paths}

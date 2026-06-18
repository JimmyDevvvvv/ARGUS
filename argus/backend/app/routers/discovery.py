"""
M1 - discovery API.

POST /api/discover triggers a scan of a subnet and ingests the
results into Neo4j via collector.ingest. Kept separate from
topology.py so "trigger a scan" doesn't get tangled with "read the
graph".

Note on timing: a -sV scan of a /24 can take 2-5 minutes.
The endpoint currently blocks until the scan completes (fine for M1).
M2 will move this to BackgroundTasks + a polling endpoint.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from collector.discover import NmapNotFound
from collector.ingest import ingest_subnet

router = APIRouter()


class DiscoverRequest(BaseModel):
    cidr: str  # e.g. "10.10.20.0/24"


@router.post("/discover")
def discover(req: DiscoverRequest):
    try:
        sector = ingest_subnet(req.cidr)
    except NmapNotFound as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    hosts = sector.get("hosts", [])
    return {
        "sector":       sector["name"],
        "cidr":         sector["cidr"],
        "hosts_found":  len(hosts),
        "vulnerable":   sum(1 for h in hosts if h.get("status") == "vulnerable"),
        "crown_jewels": sum(1 for h in hosts if h.get("status") == "crownjewel"),
        "data":         sector,
    }

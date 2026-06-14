"""
M1 - discovery API.

POST /api/discover triggers a scan of a subnet and ingests the
results into Neo4j via collector.ingest. Kept separate from
topology.py so "trigger a scan" doesn't get tangled with "read the
graph".
"""

from fastapi import APIRouter
from pydantic import BaseModel

from collector.ingest import ingest_subnet

router = APIRouter()


class DiscoverRequest(BaseModel):
    cidr: str  # e.g. "10.10.20.0/24"


@router.post("/discover")
def discover(req: DiscoverRequest):
    # TODO (M1): an nmap -O -sV scan of a /24 can take well over a
    # minute - consider FastAPI's BackgroundTasks once ingest_subnet
    # is implemented, plus a way to poll for completion.
    sector = ingest_subnet(req.cidr)
    return {"sector": sector}

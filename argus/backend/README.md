# ARGUS backend

## Setup

    pip install -r requirements.txt

Copy `.env.example` to `.env` and adjust if your Neo4j credentials
differ from the defaults (`neo4j` / `argus-dev-pw`).

## Run the API

    uvicorn app.main:app --reload

- `GET /api/health` - reports whether Neo4j is reachable
- `GET /api/topology` - sectors + hosts (falls back to seed data if Neo4j is down)
- `GET /api/attack-paths` - CAN_REACH chains
- `POST /api/discover` - M1, not yet implemented

## Seed demo data (M0)

With Neo4j running:

    python -m app.seed

Loads the 4-sector / 17-host demo topology from `app/seed_data.py`.

## Real discovery (M1, in progress)

    python -m collector.cli 10.10.20.0/24

Currently a stub - `collector/discover.py`, `fingerprint.py`,
`layout.py`, and `ingest.py` have signatures and docstrings but raise
`NotImplementedError`. Filling these in is M1.

## Status

- **M0**: done - this skeleton, real Neo4j integration, seed data, seed-fallback API
- **M1**: structure in place, implementation pending

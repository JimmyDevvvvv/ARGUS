from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import discovery, topology

app = FastAPI(title="ARGUS API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before this leaves localhost
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(topology.router, prefix="/api")
app.include_router(discovery.router, prefix="/api")


@app.get("/")
def root():
    return {"service": "argus-api", "docs": "/docs"}

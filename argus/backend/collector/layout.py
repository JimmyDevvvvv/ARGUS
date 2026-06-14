"""
M1 - placeholder layout for a single, freshly-discovered subnet.

Deliberately dumb on purpose: one sector at a fixed position, hosts
arranged in a simple grid inside it. M3 replaces this with real
algorithmic layout once multiple, differently-sized sectors need to
coexist on the map.
"""

from __future__ import annotations

SECTOR_X, SECTOR_Y, SECTOR_W, SECTOR_H = 60, 60, 700, 460
HOST_MARGIN = 80  # keep grid points away from the bracket framing


def layout_sector(cidr: str, hosts: list[dict]) -> dict:
    """
    hosts: dicts with at least "id" (no x/y yet) - mutated in place
    to add "x"/"y".

    Returns a sector dict: {id, name, cidr, x, y, w, h}.
    """
    # TODO (M1):
    #   cols = ceil(sqrt(len(hosts))) or 1
    #   rows = ceil(len(hosts) / cols)
    #   space hosts evenly within
    #   (SECTOR_X+HOST_MARGIN, SECTOR_Y+HOST_MARGIN,
    #    SECTOR_W-2*HOST_MARGIN, SECTOR_H-2*HOST_MARGIN)
    raise NotImplementedError

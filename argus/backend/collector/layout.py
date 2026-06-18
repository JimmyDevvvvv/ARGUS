"""
M1 - placeholder layout for a single, freshly-discovered subnet.

Deliberately dumb on purpose: one sector at a fixed position, hosts
arranged in a simple grid inside it. M3 replaces this with real
algorithmic layout once multiple, differently-sized sectors need to
coexist on the map.
"""

from __future__ import annotations

import math

SECTOR_X, SECTOR_Y, SECTOR_W, SECTOR_H = 60, 60, 700, 460
HOST_MARGIN = 80  # keep grid points away from the bracket framing


def layout_sector(cidr: str, hosts: list[dict]) -> dict:
    """
    hosts: dicts with at least "id" (no x/y yet) — mutated in place
    to add "x"/"y".

    Returns a sector dict: {id, name, cidr, x, y, w, h, hosts}.
    """
    n = len(hosts)

    if n > 0:
        cols = max(1, math.ceil(math.sqrt(n * 1.4)))  # slightly wider grid
        rows = math.ceil(n / cols)

        usable_w = SECTOR_W - 2 * HOST_MARGIN
        usable_h = SECTOR_H - 2 * HOST_MARGIN
        col_step = usable_w / max(cols, 1)
        row_step = usable_h / max(rows, 1)

        for i, host in enumerate(hosts):
            col = i % cols
            row = i // cols
            host["x"] = SECTOR_X + HOST_MARGIN + int(col * col_step + col_step * 0.5)
            host["y"] = SECTOR_Y + HOST_MARGIN + int(row * row_step + row_step * 0.5)

    # Derive a short readable name from the CIDR's third octet
    # e.g. "10.10.20.0/24" -> "NET-20"
    try:
        third_octet = cidr.split(".")[2]
        name = f"NET-{third_octet}"
    except (IndexError, ValueError):
        name = "DISCOVERED"

    sector_id = name.lower().replace("-", "_")

    return {
        "id":    sector_id,
        "name":  name,
        "cidr":  cidr,
        "x":     SECTOR_X,
        "y":     SECTOR_Y,
        "w":     SECTOR_W,
        "h":     SECTOR_H,
        "hosts": hosts,
    }

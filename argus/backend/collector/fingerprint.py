"""
M1 - turns nmap's osmatch candidates into the normalized "os" string
ARGUS stores on Host nodes (e.g. "Ubuntu 22.04", "Windows Server 2019"),
matching the style used in seed_data.py.
"""

from __future__ import annotations

UNKNOWN_OS = "Unknown"


def normalize_os(osmatches: list[dict]) -> str:
    """
    osmatches: nmap's ranked guesses, e.g.
        [{"name": "Linux 5.0 - 5.14", "accuracy": "95"}, ...]

    Returns a single normalized string, or UNKNOWN_OS if nothing
    crosses a reasonable confidence threshold.
    """
    # TODO (M1): pick the highest-accuracy match above ~85%, and map
    # nmap's free-text naming onto something consistent (e.g. regex
    # "Linux 5.*" -> "Linux", "Microsoft Windows Server 2019" -> "Windows Server 2019").
    raise NotImplementedError

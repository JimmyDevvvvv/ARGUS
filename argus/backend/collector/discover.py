"""
M1 - runs nmap against a subnet and parses its XML output.

This is the only module that talks to nmap directly. If the scan
engine ever changes, this is the file that changes.

discover_subnet(cidr) returns a list of per-host dicts shaped like:
    {
        "ip": "10.10.20.14",
        "mac": "AA:BB:CC:DD:EE:FF" | None,
        "hostnames": ["wkstn-14.corp.local", ...],
        "osmatches": [{"name": "Microsoft Windows 10/11", "accuracy": "95"}, ...],
        "ports": [
            {"port": 445, "protocol": "tcp", "state": "open",
             "service": "microsoft-ds", "product": "Windows SMB", "version": ""},
            ...
        ],
    }
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET


def run_nmap(cidr: str) -> str:
    """Run nmap against `cidr` and return its raw XML output."""
    # TODO (M1):
    #   result = subprocess.run(
    #       ["nmap", "-O", "-sV", "-oX", "-", cidr],
    #       capture_output=True, text=True, check=True,
    #   )
    #   return result.stdout
    raise NotImplementedError


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap's XML into the list-of-dicts shape described above."""
    # TODO (M1): root = ET.fromstring(xml_text); iterate root.findall("host")
    raise NotImplementedError


def discover_subnet(cidr: str) -> list[dict]:
    """Discover live hosts on `cidr` and return parsed nmap results."""
    return parse_nmap_xml(run_nmap(cidr))

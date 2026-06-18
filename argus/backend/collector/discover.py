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

import shutil
import subprocess
import xml.etree.ElementTree as ET


class NmapNotFound(RuntimeError):
    """Raised when nmap is not on PATH."""


def _nmap_binary() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFound(
            "nmap not found on PATH.\n"
            "  Linux : sudo apt install nmap\n"
            "  macOS : brew install nmap\n"
            "  Windows: https://nmap.org/download.html (add to PATH)"
        )
    return path


def run_nmap(cidr: str) -> str:
    """Run nmap against `cidr` and return its raw XML output."""
    result = subprocess.run(
        [
            _nmap_binary(),
            "-sV",              # service / version detection
            "-O",               # OS detection  (needs root/admin)
            "--osscan-guess",   # aggressive OS guess when incomplete
            "-T4",              # faster timing (aggressive)
            "--open",           # only report open ports
            "--host-timeout", "30s",  # don't hang on unresponsive hosts
            "-oX", "-",         # XML to stdout
            cidr,
        ],
        capture_output=True,
        text=True,
        timeout=600,  # overall scan budget (10 min for large subnets)
    )
    # nmap exits 0 on success, 1 when no hosts up — both are fine
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"nmap exited {result.returncode}.\n"
            f"stderr: {result.stderr[:800]}"
        )
    return result.stdout


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap's XML into the list-of-dicts shape described above."""
    if not xml_text.strip():
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed nmap XML: {exc}") from exc

    hosts = []
    for host_el in root.findall("host"):
        # Skip hosts that are down
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        # IP + MAC
        ip = mac = None
        for addr_el in host_el.findall("address"):
            atype = addr_el.get("addrtype")
            if atype == "ipv4":
                ip = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")
        if not ip:
            continue

        # Hostnames (PTR records, etc.)
        hostnames = []
        hn_container = host_el.find("hostnames")
        if hn_container is not None:
            hostnames = [
                hn.get("name")
                for hn in hn_container.findall("hostname")
                if hn.get("name")
            ]

        # OS guesses, sorted best-first
        osmatches = []
        os_el = host_el.find("os")
        if os_el is not None:
            for om in os_el.findall("osmatch"):
                osmatches.append({
                    "name": om.get("name", ""),
                    "accuracy": om.get("accuracy", "0"),
                })
            osmatches.sort(key=lambda m: int(m["accuracy"]), reverse=True)

        # Open ports / services
        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc = port_el.find("service")
                ports.append({
                    "port":     int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  svc.get("name", "")    if svc is not None else "",
                    "product":  svc.get("product", "") if svc is not None else "",
                    "version":  svc.get("version", "") if svc is not None else "",
                })

        hosts.append({
            "ip":        ip,
            "mac":       mac,
            "hostnames": hostnames,
            "osmatches": osmatches,
            "ports":     ports,
        })

    return hosts


def discover_subnet(cidr: str) -> list[dict]:
    """Discover live hosts on `cidr` and return parsed nmap results."""
    return parse_nmap_xml(run_nmap(cidr))

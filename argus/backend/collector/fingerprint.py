"""
M1 - turns nmap's osmatch candidates into the normalized "os" string
ARGUS stores on Host nodes (e.g. "Ubuntu 22.04", "Windows Server 2019"),
matching the style used in seed_data.py.

Also classifies each host's security status and guesses an owner team.
"""

from __future__ import annotations

import re

UNKNOWN_OS = "Unknown"

# ---------------------------------------------------------------------------
# OS normalisation
# ---------------------------------------------------------------------------

# Ordered list of (regex, display_string) pairs.
# First match wins.
_OS_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Windows Server 2022",      re.I), "Windows Server 2022"),
    (re.compile(r"Windows Server 2019",      re.I), "Windows Server 2019"),
    (re.compile(r"Windows Server 2016",      re.I), "Windows Server 2016"),
    (re.compile(r"Windows Server 2012",      re.I), "Windows Server 2012"),
    (re.compile(r"Windows 11",               re.I), "Windows 11"),
    (re.compile(r"Windows 10",               re.I), "Windows 10"),
    (re.compile(r"Windows 7",                re.I), "Windows 7"),
    (re.compile(r"Windows",                  re.I), "Windows"),
    (re.compile(r"Ubuntu 24",                re.I), "Ubuntu 24.04"),
    (re.compile(r"Ubuntu 22",                re.I), "Ubuntu 22.04"),
    (re.compile(r"Ubuntu 20",                re.I), "Ubuntu 20.04"),
    (re.compile(r"Ubuntu",                   re.I), "Ubuntu Linux"),
    (re.compile(r"Debian",                   re.I), "Debian Linux"),
    (re.compile(r"Red Hat|RHEL",             re.I), "RHEL"),
    (re.compile(r"CentOS",                   re.I), "CentOS"),
    (re.compile(r"Fedora",                   re.I), "Fedora"),
    (re.compile(r"Linux",                    re.I), "Linux"),
    (re.compile(r"macOS|Mac OS X|Darwin",    re.I), "macOS"),
    (re.compile(r"FreeBSD",                  re.I), "FreeBSD"),
    (re.compile(r"pfSense",                  re.I), "pfSense"),
    (re.compile(r"Cisco IOS",                re.I), "Cisco IOS"),
    (re.compile(r"Juniper",                  re.I), "Juniper JunOS"),
    (re.compile(r"Android",                  re.I), "Android"),
    (re.compile(r"iOS",                      re.I), "iOS"),
]

_CONFIDENCE_THRESHOLD = 80  # below this we call it Unknown


def normalize_os(osmatches: list[dict]) -> str:
    """
    osmatches: nmap's ranked guesses, e.g.
        [{"name": "Linux 5.0 - 5.14", "accuracy": "95"}, ...]

    Returns a single normalized string, or UNKNOWN_OS if nothing
    crosses a reasonable confidence threshold.
    """
    for match in osmatches:
        accuracy = int(match.get("accuracy", "0"))
        if accuracy < _CONFIDENCE_THRESHOLD:
            continue
        name = match.get("name", "")
        for pattern, display in _OS_RULES:
            if pattern.search(name):
                return display
        # Didn't match a rule but confidence is high — return raw (trimmed)
        return name.strip() or UNKNOWN_OS
    return UNKNOWN_OS


# ---------------------------------------------------------------------------
# Host-type classification
# ---------------------------------------------------------------------------

# Port sets that hint at specific host roles
_DC_PORTS    = {88, 389, 636, 3268}   # Kerberos + LDAP
_DB_PORTS    = {1433, 1521, 3306, 5432, 27017, 6379, 9200}
_WEB_PORTS   = {80, 443, 8080, 8443, 8000}
_RDP_PORTS   = {3389}
_PRINT_PORTS = {515, 631, 9100}
_NET_PORTS   = {161, 179, 520}   # SNMP, BGP, RIP


def _port_set(ports: list[dict]) -> set[int]:
    return {p["port"] for p in ports}


def classify_host_type(ports: list[dict], os_str: str) -> str:
    """Infer a broad host category from open ports and OS string."""
    ps = _port_set(ports)
    os_low = os_str.lower()

    if ps & _NET_PORTS or "cisco" in os_low or "juniper" in os_low or "pfsense" in os_low:
        return "network_device"
    if _DC_PORTS.issubset(ps) or (88 in ps and 389 in ps):
        return "domain_controller"
    if ps & _DB_PORTS:
        return "database"
    if ps & _PRINT_PORTS:
        return "printer"
    if ps & _WEB_PORTS and not (ps & _RDP_PORTS):
        return "web_server"
    if "windows" in os_low or ps & _RDP_PORTS:
        return "workstation"
    if ps & {22}:
        return "server"
    return "unknown"


# ---------------------------------------------------------------------------
# Risk / status assessment
# ---------------------------------------------------------------------------

# Ports that are high-risk when exposed — maps port → short reason
_HIGH_RISK: dict[int, str] = {
    21:    "FTP (cleartext credentials)",
    23:    "Telnet (cleartext)",
    445:   "SMB (ransomware / lateral movement vector)",
    3389:  "RDP exposed (brute-force target)",
    1433:  "MSSQL directly reachable",
    3306:  "MySQL directly reachable",
    5432:  "PostgreSQL directly reachable",
    27017: "MongoDB (often unauthenticated)",
    6379:  "Redis (often unauthenticated)",
}


def classify_status(ports: list[dict], host_type: str) -> tuple[str, str]:
    """
    Return (status, note) where status is one of:
        "crownjewel" | "vulnerable" | "normal"

    "anomaly" is not set here — that requires behavioural data (beaconing,
    unusual traffic patterns) that nmap can't see. M4 will add it.
    """
    ps = _port_set(ports)

    if host_type == "domain_controller":
        return (
            "crownjewel",
            "Domain controller — tagged as a crown jewel. "
            "Full domain compromise if this host is breached.",
        )

    exposed = [desc for port, desc in _HIGH_RISK.items() if port in ps]
    if exposed:
        note = "; ".join(exposed[:3])
        if len(exposed) > 3:
            note += f" (+{len(exposed) - 3} more)"
        return "vulnerable", note

    return "normal", "No high-risk services detected."


# ---------------------------------------------------------------------------
# Owner heuristic
# ---------------------------------------------------------------------------

_OWNER_MAP: dict[str, str] = {
    "domain_controller": "IT Ops",
    "database":          "Data Team",
    "web_server":        "IT Ops",
    "workstation":       "End User",
    "printer":           "Facilities",
    "network_device":    "Network Team",
    "server":            "IT Ops",
    "unknown":           "Unassigned",
}


def guess_owner(host_type: str) -> str:
    return _OWNER_MAP.get(host_type, "Unassigned")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def fingerprint_host(raw: dict) -> dict:
    """
    Enrich a single raw host dict (from discover.py) into the shape
    expected by layout.py / ingest.py:

        {
            "id", "ip", "hostname", "mac",
            "os", "host_type", "owner",
            "status", "note",
            "ports",        # carried through unchanged
        }
    """
    os_str    = normalize_os(raw.get("osmatches", []))
    ports     = raw.get("ports", [])
    host_type = classify_host_type(ports, os_str)
    status, note = classify_status(ports, host_type)
    owner     = guess_owner(host_type)

    # Build a short, map-friendly id
    hostnames = raw.get("hostnames", [])
    ip        = raw["ip"]
    if hostnames:
        host_id = hostnames[0].split(".")[0].lower()[:14]
    else:
        parts   = ip.split(".")
        host_id = f"h-{parts[-2]}-{parts[-1]}"

    return {
        "id":        host_id,
        "ip":        ip,
        "hostname":  hostnames[0] if hostnames else None,
        "mac":       raw.get("mac"),
        "os":        os_str,
        "host_type": host_type,
        "owner":     owner,
        "status":    status,
        "note":      note,
        "ports":     ports,
    }

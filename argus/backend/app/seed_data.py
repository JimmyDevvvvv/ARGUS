"""
Hand-authored M0 demo topology.

This is the same network used in the standalone HTML prototype
(argus-map.html): 4 sectors, 17 hosts, one attack path from an
internet-facing web server to the domain controller.

Used to (a) seed Neo4j via seed.py, and (b) serve as a fallback data
source if Neo4j isn't reachable yet (keeps frontend dev unblocked).
"""

SECTORS = [
    {
        "id": "dmz", "name": "DMZ", "cidr": "203.0.113.0/24",
        "x": 60, "y": 60, "w": 700, "h": 460,
        "hosts": [
            {"id": "web-01", "ip": "203.0.113.10", "os": "Ubuntu 22.04", "owner": "IT Ops",
             "status": "vulnerable", "x": 240, "y": 220,
             "note": "2 known CVEs (CVE-2024-3094 critical, CVE-2023-44487 high). "
                     "Internet-facing. Entry point for the active attack path to DC-01."},
            {"id": "web-02", "ip": "203.0.113.11", "os": "Ubuntu 22.04", "owner": "IT Ops",
             "status": "normal", "x": 480, "y": 200, "note": "No issues detected."},
            {"id": "lb-01", "ip": "203.0.113.2", "os": "FreeBSD 13", "owner": "Network Team",
             "status": "normal", "x": 610, "y": 380, "note": "No issues detected."},
            {"id": "vpn-gw", "ip": "203.0.113.1", "os": "pfSense", "owner": "Network Team",
             "status": "normal", "x": 320, "y": 420, "note": "No issues detected."},
        ],
    },
    {
        "id": "corp", "name": "CORP-LAN", "cidr": "10.10.20.0/24",
        "x": 840, "y": 60, "w": 700, "h": 460,
        "hosts": [
            {"id": "wkstn-14", "ip": "10.10.20.14", "os": "Windows 11", "owner": "Sales",
             "status": "normal", "x": 980, "y": 210, "note": "No issues detected."},
            {"id": "wkstn-22", "ip": "10.10.20.22", "os": "Windows 11", "owner": "Marketing",
             "status": "anomaly", "x": 1220, "y": 190,
             "note": "Beaconing to 198.51.100.42 every 60 seconds since 14:32. "
                     "This destination has not been seen on the network before."},
            {"id": "wkstn-31", "ip": "10.10.20.31", "os": "macOS 14", "owner": "Engineering",
             "status": "normal", "x": 1400, "y": 310, "note": "No issues detected."},
            {"id": "print-01", "ip": "10.10.20.5", "os": "Embedded", "owner": "Facilities",
             "status": "normal", "x": 1080, "y": 420, "note": "No issues detected."},
            {"id": "wkstn-45", "ip": "10.10.20.45", "os": "Windows 11", "owner": "HR",
             "status": "normal", "x": 1320, "y": 440, "note": "No issues detected."},
        ],
    },
    {
        "id": "srv", "name": "SERVER-FARM", "cidr": "10.10.30.0/24",
        "x": 60, "y": 600, "w": 700, "h": 460,
        "hosts": [
            {"id": "db-02", "ip": "10.10.30.12", "os": "PostgreSQL / Linux", "owner": "Data Team",
             "status": "normal", "x": 260, "y": 780,
             "note": "Reuses a local admin credential that is also valid on DC-01. "
                     "Mid-point of the active attack path from WEB-01."},
            {"id": "file-01", "ip": "10.10.30.20", "os": "Linux", "owner": "IT Ops",
             "status": "normal", "x": 500, "y": 750, "note": "No issues detected."},
            {"id": "app-03", "ip": "10.10.30.15", "os": "Linux", "owner": "Engineering",
             "status": "normal", "x": 620, "y": 920, "note": "No issues detected."},
            {"id": "backup-01", "ip": "10.10.30.30", "os": "Linux", "owner": "IT Ops",
             "status": "normal", "x": 340, "y": 960, "note": "No issues detected."},
        ],
    },
    {
        "id": "fin", "name": "FINANCE-VLAN", "cidr": "10.10.40.0/24",
        "x": 840, "y": 600, "w": 700, "h": 460,
        "hosts": [
            {"id": "dc-01", "ip": "10.10.40.5", "os": "Windows Server 2019", "owner": "IT Ops",
             "status": "crownjewel", "x": 1160, "y": 780,
             "note": "Domain controller, tagged as a crown jewel. One active attack path "
                     "terminates here, originating at WEB-01 via DB-02."},
            {"id": "fin-db", "ip": "10.10.40.10", "os": "MS SQL", "owner": "Finance",
             "status": "normal", "x": 1020, "y": 930, "note": "No issues detected."},
            {"id": "fin-app", "ip": "10.10.40.15", "os": "Linux", "owner": "Finance",
             "status": "normal", "x": 1320, "y": 740, "note": "No issues detected."},
            {"id": "jump-01", "ip": "10.10.40.2", "os": "Windows Server 2019", "owner": "IT Ops",
             "status": "normal", "x": 1370, "y": 940, "note": "No issues detected."},
        ],
    },
]

# Edges that make up the attack path web-01 -> db-02 -> dc-01.
# Modeled as CAN_REACH relationships - this is the same edge type
# M4's CVE-correlation step will create automatically.
ATTACK_EDGES = [
    {"from": "web-01", "to": "db-02", "technique": "CVE-2024-3094 (RCE)"},
    {"from": "db-02", "to": "dc-01", "technique": "Credential reuse"},
]

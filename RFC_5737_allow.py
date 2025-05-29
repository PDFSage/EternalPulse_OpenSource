#!/usr/bin/env python3
import json
import ipaddress

# Original configuration (unchanged)
data = {
  "ips": [
    "198.51.100.5",
    "203.0.113.10",
    "192.0.2.1",
    "198.51.100.22",
    "203.0.113.15",
    "192.0.2.45"
  ],
  "cidrs": [
    "203.0.113.0/24",
    "198.51.100.0/24",
    "192.0.2.0/24"
  ],
  "x-permission-reasons": {
    "198.51.100.5": "Authorized pentest target per contractual agreement with ExampleCorp",
    "203.0.113.10": "In-scope for public bug bounty program on HackerOne",
    "192.0.2.1": "Reserved documentation network, free to test (RFC 5737)",
    "198.51.100.22": "Approved via internal Red Team assessment",
    "203.0.113.15": "Listed in Bugcrowd program scope",
    "192.0.2.45": "Reserved documentation network, free to test (RFC 5737)"
  }
}

# Documentation networks (RFC 5737)
doc_nets = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24")
]

# Filter IPs strictly inside the documentation ranges
allowed_ips = [
    ip for ip in data["ips"]
    if any(ipaddress.ip_address(ip) in net for net in doc_nets)
]

# Keep only documentation CIDRs
allowed_cidrs = [
    cidr for cidr in data["cidrs"]
    if cidr in {"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
]

# Replacement “allow-only” configuration
allow_config = {
    "allow": {
        "ips": allowed_ips,
        "cidrs": allowed_cidrs
    }
}

print(json.dumps(allow_config, indent=2))

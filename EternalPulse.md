What the script now does

Accepts individual hosts, CIDR ranges, or a file of targets, then scans them concurrently.

Pings each host to see if any ICMP replies leak through the firewall.

Performs WHOIS look-ups to record the IP’s ASN and organization, useful for correlating firewall behaviour with network owners.

Scans user-selected TCP ports, classifying each as open, closed, filtered, unreachable, or error and fingerprinting exposed services:

SMB v1 / v2+ dialect, signing status

SSH banner

HTTP status & server header with a quick WAF hint (Cloudflare, Akamai, Imperva, Sucuri)

TLS version, certificate CN and issuer

Scans UDP ports and, when a response is possible, probes:

DNS (returns RCODE)

NTP (returns protocol version)

Any other UDP port is still marked open, closed, etc., helping locate silently-dropped packets.

Exposes firewall posture by contrasting ICMP reachability, TCP states, and UDP behaviour, highlighting default-deny rules, stateful filtering, or front-end WAF/CDN shielding.

Outputs either pretty text or structured JSON for further analysis and graphing.
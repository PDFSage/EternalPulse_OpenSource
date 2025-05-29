This script is a flexible, concurrent network scanner focused on discovering and probing hosts—particularly for SMB services—across both individual IPs and CIDR ranges. At a high level, it:

Parses command‑line arguments to determine targets (hosts and/or networks), ports (TCP and UDP), timeouts, concurrency level, scanning strategy, allow‑list file, input/output files, and output format (JSON vs. plain text).

Loads an allow‑list of permitted IPs and networks, ensuring the scan only touches approved targets.

Builds a list of targets by combining explicitly supplied hosts, IPs read from an input file, and all addresses within provided CIDR blocks.

Optionally reuses previously saved scan results and immediately outputs them.

Orders the scan using either a simple round‑robin or a heuristic “MCTS” strategy that shuffles targets to maximize a score based on the numeric value of each IP.

Spawns a thread pool to probe each host in parallel. For each target it:

Sends an ICMP ping (via the system’s ping command).

Scans each specified TCP port, classifying its state (open, closed, filtered, unreachable, etc.).

For open TCP ports, performs protocol‐specific probes:

SMBv1 and SMBv2 dialect negotiation (ports 139, 445).

SSH banner capture (port 22).

HTTP header inspection (ports 80, 8080, 8000).

HTTPS TLS handshake and certificate inspection (ports 443, 8443).

Scans each specified UDP port, similarly classifying its state.

Collects all results into a dictionary keyed by host.

Optionally saves any hosts with successful SMB findings.

Prints the full results, either as formatted JSON or as a readable per‑host report.

This makes it easy to run large‑scale SMB‐focused reconnaissance across many addresses while respecting allow‑lists, reusing prior state, and customizing scan order for performance or randomness.

Detailed Breakdown

1. Shebang and Imports
python
Copy
Edit
#!/usr/bin/env python3
import argparse, socket, struct, uuid, json, concurrent.futures
import ipaddress, sys, ssl, errno, random, subprocess, platform, os
Shebang: Ensures the script runs under the user’s Python 3 environment.

Imports:

argparse for CLI argument parsing.

socket, ssl for raw network connections and TLS.

struct, uuid for binary packet crafting (especially SMB).

json for serialization.

concurrent.futures for threading.

ipaddress to parse and expand IPs/CIDRs.

subprocess, platform to invoke ping.

errno for OS‐level error codes.

random to shuffle targets under MCTS strategy.

sys, os for filesystem and process control.

2. Allow‑List Handling
python
Copy
Edit
def load_allowlist(path):
    nets, ips = [], set()
    if not path:
        return nets, ips
    with open(path) as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
    return nets, ips

def allowed(ip, nets, ips):
    ip = ipaddress.ip_address(ip)
    if ip in ips:
        return True
    return any(ip in net for net in nets)
load_allowlist reads a file of CIDRs and individual IPs, ignoring comments and blank lines. It returns:

nets: list of IPv4Network/IPv6Network objects.

ips: set of IPv4Address/IPv6Address objects.

allowed checks if a given IP string falls within any network in nets or exactly matches any in ips, enforcing the allow‑list.

3. Target Ordering Strategies
python
Copy
Edit
class RoundRobin:
    def __init__(self, targets):
        self.t = list(targets)
    def __iter__(self):
        return iter(self.t)

class MCTS:
    def __init__(self, targets, iters=200):
        self.targets = list(targets)
        self.order = self._mcts(iters)
    def _score(self, ip):
        return int(ipaddress.ip_address(ip)) % 997
    def _mcts(self, iters):
        best, score = None, -1
        for _ in range(iters):
            cand = random.sample(self.targets, len(self.targets))
            s = sum(self._score(x) for x in cand)
            if s > score:
                best, score = cand, s
        return best
    def __iter__(self):
        return iter(self.order)
RoundRobin simply scans targets in supplied order.

MCTS (“Monte Carlo Tree Search”) builds multiple random permutations of the target list, scores each by summing a hash of each IP, and picks the highest‐scoring ordering to maximize entropy in scan order.

4. Low‑Level Networking Helpers
python
Copy
Edit
def _create_conn(host, port, timeout):
    return socket.create_connection((host, port), timeout)

def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf
_create_conn wraps socket.create_connection for consistency.

_recv_n ensures exactly n bytes are read (or until the peer closes), which is critical for parsing binary protocols like SMB.

5. TCP and UDP Port State Detection
python
Copy
Edit
def tcp_state(host, port, timeout):
    s = socket.socket(...)
    # Attempts TCP connect:
    #   success → "open"
    #   timeout → "filtered"
    #   ConnectionRefusedError → "closed"
    #   unreachable errors → "unreachable"
    #   other OSErrors → "error"
    finally: s.close()

def udp_state(host, port, timeout):
    s = socket.socket(...)
    # Sends an empty UDP packet:
    #   recv timeout → "open|filtered"
    #   ConnectionRefusedError → "closed"
    #   unreachable errors → "unreachable"
    #   other OSErrors → "error"
    finally: s.close()
tcp_state performs a TCP handshake to classify port reachability.

udp_state emits a UDP packet and awaits any ICMP “port unreachable” messages to distinguish “closed” from silent “open|filtered.”

6. Protocol‑Specific Probes
ICMP via the system ping command:

python
Copy
Edit
def icmp_probe(host, timeout):
    # Uses "ping -c 1" (Unix) or "-n 1" (Windows), returns
    # {"icmp": "responding"} or {"icmp": "no_reply"}
SMBv2 negotiate request over TCP (ports 139, 445):

python
Copy
Edit
def smbv2_probe(host, port, timeout):
    # Crafts an SMB2 negotiate packet, parses dialect and signing flags,
    # returns e.g. {"smb_v2_plus": True, "smb_dialect": "0x0302", "smb_signing":"required"}
SMBv1 negotiate request:

python
Copy
Edit
def smbv1_probe(host, port, timeout):
    # Sends an SMB1 packet negotiating "NT LM 0.12", returns {"smb_v1": True/False}
SSH banner grab (port 22):

python
Copy
Edit
def ssh_probe(host, port, timeout):
    # Reads up to 255 bytes; if it starts with "SSH-" returns {"ssh_banner": ...}
HTTP header inspection (ports 80, 8080, 8000):

python
Copy
Edit
def http_probe(host, port, timeout):
    # Sends HEAD / HTTP/1.0, parses status line and Server header,
    # attempts to detect a WAF by known vendor strings.
HTTPS certificate inspection (ports 443, 8443):

python
Copy
Edit
def https_probe(host, port, timeout):
    # Performs TLS handshake, extracts certificate subject and issuer common names,
    # returns {"tls_version": "...", "cert_common_name": "...", "cert_issuer": "..."}
7. Per‑Host Probing Routine
python
Copy
Edit
def probe(host, tcp_ports, udp_ports, timeout):
    res = {"host": host, "ports": {}}
    res.update(icmp_probe(host, timeout))
    for port in tcp_ports:
        state = tcp_state(...)
        info = {"protocol": "tcp", "state": state}
        if state == "open":
            # Attach any applicable protocol probes (SMB, SSH, HTTP, HTTPS)
        res["ports"][port] = info
    for port in udp_ports:
        state = udp_state(...)
        info = {"protocol": "udp", "state": state}
        res["ports"][f"U{port}"] = info
    return res
Combines ICMP, TCP, and UDP scans into a single dictionary with protocol details.

8. Target Expansion and Scanning
python
Copy
Edit
def host_iterator(hosts, cidrs):
    # Yields explicit hosts, then every IP in each CIDR

def scan(targets, tcp_ports, udp_ports, timeout, workers, strat_cls):
    strategy = strat_cls(targets)
    ordered = list(strategy)
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(probe, h, ...): h for h in ordered}
        for f in as_completed(fut):
            results[fut[f]] = f.result()  # or capture exceptions
    return results
host_iterator merges explicit host list and expands CIDR blocks into individual IPs.

scan applies the chosen ordering strategy, then executes probe() in parallel threads, collecting all results.

9. Success Criteria for SMB
python
Copy
Edit
def is_success(r):
    # Returns True if either SMB port (139 or 445) is open on a host record
Used to filter hosts when saving only “successful” SMB discoveries.

10. Command‑Line Interface
python
Copy
Edit
def parse_args():
    p = argparse.ArgumentParser(description="Firewall SMB scanner with allow-list, strategies, save/reuse")
    p.add_argument("--host", action="append", default=[])
    p.add_argument("--cidr", action="append", default=[])
    p.add_argument("--input")             # file of hosts
    p.add_argument("--ports", default="22,80,443,445,139,8080,8443,8000")
    p.add_argument("--udp-ports", default="53,123")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p.add_argument("--allowlist")
    p.add_argument("--strategy", choices=["round","mcts"], default="round")
    p.add_argument("--save")
    p.add_argument("--reuse")
    return p.parse_args()
Defines all user‐configurable options, including lists that can be repeated (--host, --cidr) and flags (--json).

11. Main Execution Flow
python
Copy
Edit
def main():
    args = parse_args()
    # 1. Handle --reuse: load past JSON results and print them immediately.
    # 2. Load allow‑list from file or ALLOWLIST env var.
    # 3. Build `hosts` from --host, --input file lines.
    # 4. Ensure at least one host or CIDR is provided.
    # 5. Expand targets via host_iterator.
    # 6. Enforce allow‑list: exit if any target is disallowed.
    # 7. Parse port lists into integers.
    # 8. Choose RoundRobin or MCTS based on --strategy.
    # 9. Call scan() with all parameters.
    # 10. If --save is given: filter open SMB hosts and dump to the save file.
    # 11. Output final results in JSON (if --json) else readable text.
The if __name__ == "__main__": main() boilerplate ensures it runs when executed directly.

In summary, this script is a highly configurable, threaded network scanner with specialized probes for SMB (v1/v2), SSH, HTTP/HTTPS, and raw port state checks. It supports allow‑lists, target reuse, custom strategies for ordering, and both human‑ and machine‑readable output formats.
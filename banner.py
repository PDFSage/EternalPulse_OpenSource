#!/usr/bin/env python3
import argparse, socket, subprocess, platform, concurrent.futures, requests, ssl, json, select

# --- helpers ---
def icmp_ping(host: str, timeout: int) -> bool:
    cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host] if platform.system().lower() == "windows" \
          else ["ping", "-c", "1", "-W", str(timeout), host]
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def tcp_connect(host: str, port: int, timeout: int):
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(1)
        banner = ""
        try:
            banner = s.recv(128).decode(errors="ignore").strip()
        except Exception:
            pass
        s.close()
        return True, banner
    except Exception:
        return False, ""

def udp_probe(host: str, port: int, timeout: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (host, port))
        sock.recvfrom(1024)
        sock.close()
        return True
    except Exception:
        return False

def http_probe(host: str, port: int, timeout: int):
    try:
        r = requests.get(f"http://{host}:{port}", timeout=timeout)
        if r.status_code < 400:
            return {"code": r.status_code, "server": r.headers.get("Server", "")}
    except Exception:
        pass
    return None

def https_probe(host: str, port: int, timeout: int):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert()
        return {"issuer": cert.get("issuer"), "subject": cert.get("subject")}
    except Exception:
        return None

# --- main test ---
def success_test(host: str, tcp_ports, udp_ports, timeout: int):
    res = {}
    if icmp_ping(host, timeout):
        res["icmp"] = True

    tcp_open = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(tcp_connect, host, p, timeout): p for p in tcp_ports}
        for f in concurrent.futures.as_completed(futs):
            ok, banner = f.result()
            if ok:
                entry = {}
                if banner:
                    entry["banner"] = banner
                tcp_open[futs[f]] = entry
    if tcp_open:
        res["tcp"] = tcp_open

    udp_open = [p for p in udp_ports if udp_probe(host, p, timeout)]
    if udp_open:
        res["udp"] = udp_open

    http_ok = {}
    for p in tcp_open:
        if p in (80, 8080):
            r = http_probe(host, p, timeout)
            if r:
                http_ok[p] = r
    if http_ok:
        res["http"] = http_ok

    if 443 in tcp_open:
        r = https_probe(host, 443, timeout)
        if r:
            res["https"] = {443: r}

    return res

# --- cli ---
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--tcp-ports", default="21,22,25,53,80,110,143,443,445,993,995,3306,3389,8080")
    p.add_argument("--udp-ports", default="53,123")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    tcp_ports = [int(x) for x in a.tcp_ports.split(",") if x]
    udp_ports = [int(x) for x in a.udp_ports.split(",") if x]
    res = success_test(a.host, tcp_ports, udp_ports, a.timeout)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(res if res else "No successful tests")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse, socket, struct, uuid, json, concurrent.futures, ipaddress, sys, ssl, errno, random, time, subprocess, platform

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

def tcp_state(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "unreachable"
        return "error"
    finally:
        s.close()

def udp_state(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"", (host, port))
        s.recvfrom(1024)
        return "open"
    except socket.timeout:
        return "open|filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "unreachable"
        return "error"
    finally:
        s.close()

def icmp_probe(host, timeout):
    try:
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", flag, "1", "-W", str(timeout), host]
        return {"icmp": "responding" if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0 else "no_reply"}
    except Exception:
        return None

def dns_probe(host, port, timeout):
    try:
        txn = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", txn, 0x0100, 1, 0, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack(">HH", 1, 1)
        pkt = header + question
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(512)
        if len(data) >= 12:
            rcode = data[3] & 0x0F
            return {"dns_rcode": rcode}
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def ntp_probe(host, port, timeout):
    try:
        pkt = b"\x1b" + b"\0" * 47
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(48)
        if len(data) >= 48:
            vn = (data[0] >> 3) & 7
            return {"ntp_version": vn}
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def whois_probe(host, timeout):
    try:
        ip = socket.gethostbyname(host)
        with socket.create_connection(("whois.cymru.com", 43), timeout) as s:
            s.sendall(b"begin\n" + ip.encode() + b"\nend\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        lines = data.decode().strip().split("\n")
        if len(lines) >= 2:
            parts = [p.strip() for p in lines[1].split("|")]
            if len(parts) >= 5:
                return {"asn": parts[0], "asn_org": parts[4]}
    except Exception:
        return None

def smbv2_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            s.settimeout(timeout)
            guid = uuid.uuid4().bytes
            dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
            negotiate = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0, guid, 0, 0, 0) + b"".join(struct.pack("<H", d) for d in dialects)
            smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x01\x00" + b"\x00\x00\x00\x00" + b"\x00" * 8 + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16
            pkt = smb2_hdr + negotiate
            s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
            hdr = _recv_n(s, 4)
            if len(hdr) != 4:
                return None
            length = int.from_bytes(hdr[1:], "big")
            data = _recv_n(s, length)
            if len(data) < 70 or data[:4] != b"\xfeSMB":
                return None
            dialect = int.from_bytes(data[68:70], "little")
            sec = int.from_bytes(data[66:68], "little")
            signing = "required" if sec & 2 else ("enabled" if sec & 1 else "disabled")
            return {"smb_v2_plus": True, "smb_dialect": hex(dialect), "smb_signing": signing}
    except Exception:
        return None

def smbv1_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            s.settimeout(timeout)
            hdr = b"\xFFSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\x53\xC8" + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
            dialects = b"\x02NT LM 0.12\x00"
            body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
            pkt = hdr + b"\x00" + struct.pack("<H", len(body)) + body
            s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
            hdr = _recv_n(s, 4)
            if len(hdr) != 4:
                return None
            length = int.from_bytes(hdr[1:], "big")
            data = _recv_n(s, length)
            if len(data) < 36 or data[:4] != b"\xFFSMB":
                return None
            status = struct.unpack("<I", data[5:9])[0]
            return {"smb_v1": status == 0}
    except Exception:
        return None

def ssh_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            s.settimeout(timeout)
            banner = _recv_n(s, 255)
            if banner.startswith(b"SSH-"):
                return {"ssh_banner": banner.strip().decode(errors="ignore")}
    except Exception:
        return None

def http_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            s.settimeout(timeout)
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            s.sendall(req)
            data = _recv_n(s, 1024)
            if data.startswith(b"HTTP/"):
                headers = data.split(b"\r\n")
                status_line = headers[0].decode(errors="ignore")
                server = ""
                for h in headers:
                    if h.lower().startswith(b"server:"):
                        server = h.split(b":", 1)[1].strip().decode(errors="ignore")
                        break
                waf = "waf" if any(w in server.lower() for w in ("cloudflare", "akamai", "imperva", "sucuri")) else ""
                return {"http_status": status_line, "http_server": server, "possible_waf": waf}
    except Exception:
        return None

def https_probe(host, port, timeout):
    try:
        ctx = ssl.create_default_context()
        with _create_conn(host, port, timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {"tls_version": ss.version(), "cert_common_name": subject.get("commonName", ""), "cert_issuer": issuer.get("commonName", "")}
    except Exception:
        return None

def probe(host, tcp_ports, udp_ports, timeout):
    res = {"host": host, "ports": {}}
    icmp = icmp_probe(host, timeout)
    if icmp:
        res.update(icmp)
    asn = whois_probe(host, timeout)
    if asn:
        res.update(asn)
    for port in tcp_ports:
        state = tcp_state(host, port, timeout)
        info = {"protocol": "tcp", "state": state}
        if state == "open":
            if port in (445, 139):
                v1 = smbv1_probe(host, port, timeout)
                v2 = smbv2_probe(host, port, timeout)
                if v1:
                    info.update(v1)
                if v2:
                    info.update(v2)
            if port == 22:
                ssh = ssh_probe(host, port, timeout)
                if ssh:
                    info.update(ssh)
            if port in (80, 8080, 8000):
                http = http_probe(host, port, timeout)
                if http:
                    info.update(http)
            if port in (443, 8443):
                https = https_probe(host, port, timeout)
                if https:
                    info.update(https)
        res["ports"][port] = info
    for port in udp_ports:
        state = udp_state(host, port, timeout)
        info = {"protocol": "udp", "state": state}
        if state in ("open", "open|filtered"):
            if port == 53:
                dns = dns_probe(host, port, timeout)
                if dns:
                    info.update(dns)
            if port == 123:
                ntp = ntp_probe(host, port, timeout)
                if ntp:
                    info.update(ntp)
        res["ports"][f"U{port}"] = info
    return res

def host_iterator(hosts, cidrs):
    for h in hosts:
        yield h
    for c in cidrs:
        for ip in ipaddress.ip_network(c, strict=False):
            yield str(ip)

def scan(targets, tcp_ports, udp_ports, timeout, workers):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(probe, h, tcp_ports, udp_ports, timeout): h for h in targets}
        for f in concurrent.futures.as_completed(fut):
            h = fut[f]
            try:
                results[h] = f.result()
            except Exception as e:
                results[h] = {"error": str(e)}
    return results

def parse_args():
    p = argparse.ArgumentParser(description="Comprehensive network scanner for public IP firewall research")
    p.add_argument("--host", action="append", default=[], help="single host")
    p.add_argument("--cidr", action="append", default=[], help="CIDR block")
    p.add_argument("--input", help="file with hosts")
    p.add_argument("--ports", default="22,80,443,445,139,8080,8443,8000", help="comma-separated TCP ports")
    p.add_argument("--udp-ports", default="53,123", help="comma-separated UDP ports")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--json", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    hosts = args.host
    if args.input:
        with open(args.input) as f:
            hosts.extend([l.strip() for l in f if l.strip()])
    if not hosts and not args.cidr:
        sys.exit("No targets supplied")
    targets = list(host_iterator(hosts, args.cidr))
    tcp_ports = [int(p) for p in args.ports.split(",") if p]
    udp_ports = [int(p) for p in args.udp_ports.split(",") if p]
    out = scan(targets, tcp_ports, udp_ports, args.timeout, args.workers)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for h, r in out.items():
            print(f"{h}:")
            if "icmp" in r:
                print(f"  ICMP: {r['icmp']}")
            if "asn" in r:
                print(f"  ASN: {r['asn']} ({r.get('asn_org', '')})")
            for port, info in r["ports"].items():
                print(f"  {port}: {info}")

if __name__ == "__main__":
    main()

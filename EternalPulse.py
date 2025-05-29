#!/usr/bin/env python3
import argparse, socket, struct, uuid, json, concurrent.futures, ipaddress, sys, ssl, errno, random, subprocess, platform, os

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
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", flag, "1", "-W", str(timeout), host]
    return {"icmp": "responding" if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0 else "no_reply"}

def smbv2_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            guid = uuid.uuid4().bytes
            dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
            negotiate = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0, guid, 0, 0, 0) + b"".join(struct.pack("<H", d) for d in dialects)
            smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x01\x00" + b"\x00\x00\x00\x00" + b"\x00"*8 + b"\x00"*4 + b"\x00"*4 + b"\x00"*8 + b"\x00"*16
            pkt = smb2_hdr + negotiate
            s.sendall(b"\x00" + len(pkt).to_bytes(3,"big") + pkt)
            hdr = _recv_n(s,4)
            if len(hdr)!=4:
                return None
            length = int.from_bytes(hdr[1:],"big")
            data = _recv_n(s,length)
            if len(data)<70 or data[:4]!=b"\xfeSMB":
                return None
            dialect = int.from_bytes(data[68:70],"little")
            sec = int.from_bytes(data[66:68],"little")
            signing = "required" if sec & 2 else ("enabled" if sec & 1 else "disabled")
            return {"smb_v2_plus":True,"smb_dialect":hex(dialect),"smb_signing":signing}
    except Exception:
        return None

def smbv1_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            hdr = b"\xFFSMB\x72\x00\x00\x00\x00\x18\x53\xC8\x00\x00" + b"\x00"*8 + b"\x00\x00"*2 + b"\x00\x00"*2
            dialects = b"\x02NT LM 0.12\x00"
            body = b"\x00" + struct.pack("<H",len(dialects)) + dialects
            pkt = hdr + b"\x00" + struct.pack("<H",len(body)) + body
            s.sendall(b"\x00"+len(pkt).to_bytes(3,"big")+pkt)
            hdr = _recv_n(s,4)
            if len(hdr)!=4:
                return None
            length=int.from_bytes(hdr[1:],"big")
            data=_recv_n(s,length)
            if len(data)<36 or data[:4]!=b"\xFFSMB":
                return None
            status=struct.unpack("<I",data[5:9])[0]
            return {"smb_v1":status==0}
    except Exception:
        return None

def ssh_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            banner=_recv_n(s,255)
            if banner.startswith(b"SSH-"):
                return {"ssh_banner":banner.strip().decode(errors="ignore")}
    except Exception:
        return None

def http_probe(host, port, timeout):
    try:
        with _create_conn(host, port, timeout) as s:
            req=f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            s.sendall(req)
            data=_recv_n(s,1024)
            if data.startswith(b"HTTP/"):
                headers=data.split(b"\r\n")
                status_line=headers[0].decode(errors="ignore")
                server=""
                for h in headers:
                    if h.lower().startswith(b"server:"):
                        server=h.split(b":",1)[1].strip().decode(errors="ignore")
                        break
                waf="waf" if any(w in server.lower() for w in ("cloudflare","akamai","imperva","sucuri")) else ""
                return {"http_status":status_line,"http_server":server,"possible_waf":waf}
    except Exception:
        return None

def https_probe(host, port, timeout):
    try:
        ctx=ssl.create_default_context()
        with _create_conn(host, port, timeout) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                cert=ss.getpeercert()
                subject=dict(x[0] for x in cert.get("subject",[]))
                issuer=dict(x[0] for x in cert.get("issuer",[]))
                return {"tls_version":ss.version(),"cert_common_name":subject.get("commonName",""),"cert_issuer":issuer.get("commonName","")}
    except Exception:
        return None

def probe(host, tcp_ports, udp_ports, timeout):
    res={"host":host,"ports":{}}
    res.update(icmp_probe(host,timeout))
    for port in tcp_ports:
        state=tcp_state(host,port,timeout)
        info={"protocol":"tcp","state":state}
        if state=="open":
            if port in (445,139):
                info.update({k:v for k,v in (smbv1_probe(host,port,timeout) or {}).items()})
                info.update({k:v for k,v in (smbv2_probe(host,port,timeout) or {}).items()})
            if port==22:
                info.update(ssh_probe(host,port,timeout) or {})
            if port in (80,8080,8000):
                info.update(http_probe(host,port,timeout) or {})
            if port in (443,8443):
                info.update(https_probe(host,port,timeout) or {})
        res["ports"][port]=info
    for port in udp_ports:
        state=udp_state(host,port,timeout)
        info={"protocol":"udp","state":state}
        res["ports"][f"U{port}"]=info
    return res

def host_iterator(hosts, cidrs):
    for h in hosts:
        yield h
    for c in cidrs:
        for ip in ipaddress.ip_network(c,strict=False):
            yield str(ip)

def scan(targets, tcp_ports, udp_ports, timeout, workers, strat_cls):
    strategy=strat_cls(targets)
    ordered=list(strategy)
    results={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fut={ex.submit(probe,h,tcp_ports,udp_ports,timeout):h for h in ordered}
        for f in concurrent.futures.as_completed(fut):
            h=fut[f]
            try:
                results[h]=f.result()
            except Exception as e:
                results[h]={"error":str(e)}
    return results

def is_success(r):
    for p,info in r["ports"].items():
        if p in (445,139) and isinstance(p,int) and info.get("state")=="open":
            return True
    return False

def parse_args():
    p=argparse.ArgumentParser(description="Firewall SMB scanner with allow-list, strategies, save/reuse")
    p.add_argument("--host",action="append",default=[])
    p.add_argument("--cidr",action="append",default=[])
    p.add_argument("--input")
    p.add_argument("--ports",default="22,80,443,445,139,8080,8443,8000")
    p.add_argument("--udp-ports",default="53,123")
    p.add_argument("--timeout",type=int,default=2)
    p.add_argument("--workers",type=int,default=100)
    p.add_argument("--json",action="store_true")
    p.add_argument("--allowlist")
    p.add_argument("--strategy",choices=["round","mcts"],default="round")
    p.add_argument("--save",help="file to save successful SMB results")
    p.add_argument("--reuse",help="file with previously saved results")
    return p.parse_args()

def main():
    args=parse_args()
    if args.reuse and os.path.isfile(args.reuse):
        with open(args.reuse) as f:
            data=json.load(f)
        print(json.dumps(data,indent=2) if args.json else data)
        return
    nets, ips = load_allowlist(args.allowlist or os.getenv("ALLOWLIST"))
    hosts=args.host or []
    if args.input:
        with open(args.input) as f:
            hosts.extend([l.strip() for l in f if l.strip()])
    if not hosts and not args.cidr:
        sys.exit("No targets supplied")
    targets=list(host_iterator(hosts,args.cidr))
    allowed_targets=[t for t in targets if allowed(t,nets,ips)]
    if len(allowed_targets)!=len(targets):
        sys.exit("Targets outside allow-list")
    tcp_ports=[int(p) for p in args.ports.split(",") if p]
    udp_ports=[int(p) for p in args.udp_ports.split(",") if p]
    strat_cls=MCTS if args.strategy=="mcts" else RoundRobin
    out=scan(allowed_targets,tcp_ports,udp_ports,args.timeout,args.workers,strat_cls)
    if args.save:
        succ={h:r for h,r in out.items() if is_success(r)}
        if succ:
            with open(args.save,"w") as f:
                json.dump(succ,f,indent=2)
    if args.json:
        print(json.dumps(out,indent=2))
    else:
        for h,r in out.items():
            print(f"{h}:")
            for port,info in r["ports"].items():
                print(f"  {port}: {info}")

if __name__=="__main__":
    main()
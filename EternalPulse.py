#!/usr/bin/env python3
import argparse, socket, struct, uuid, json, concurrent.futures, ipaddress, sys, platform, os, random, errno, subprocess

# Sample allowlist.json:
# {
#   "ips": ["198.51.100.5", "203.0.113.10"],
#   "cidrs": ["203.0.113.0/24", "198.51.100.0/24"]
# }

class PublicIPFirewallSMB:
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

    def __init__(self, allowlist, strategy="round", timeout=2, workers=100):
        self.nets, self.ips = self._load_allowlist(allowlist)
        self.strat_cls = self.MCTS if strategy == "mcts" else self.RoundRobin
        self.timeout = timeout
        self.workers = workers
        self.tcp_ports = [139, 445]
        self.results = {}

    @staticmethod
    def _load_allowlist(path):
        nets, ips = [], set()
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            entries = list(data.get("ips", [])) + list(data.get("cidrs", []))
        else:
            entries = list(data)
        for t in entries:
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        ip = ipaddress.ip_address(ip)
        if ip in ips:
            return True
        return any(ip in net for net in nets)

    @staticmethod
    def _create_conn(host, port, timeout):
        return socket.create_connection((host, port), timeout)

    @staticmethod
    def _recv_n(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _tcp_state(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
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

    def _icmp_probe(self, host):
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", flag, "1", "-W", str(self.timeout), host]
        status = "responding" if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0 else "no_reply"
        return {"icmp": status}

    def _smbv2_probe(self, host, port):
        try:
            with self._create_conn(host, port, self.timeout) as s:
                guid = uuid.uuid4().bytes
                dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
                negotiate = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0, guid, 0, 0, 0) + b"".join(struct.pack("<H", d) for d in dialects)
                smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x01\x00" + b"\x00\x00\x00\x00" + b"\x00"*8 + b"\x00"*4 + b"\x00"*4 + b"\x00"*8 + b"\x00"*16
                pkt = smb2_hdr + negotiate
                s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
                hdr = self._recv_n(s, 4)
                if len(hdr) != 4:
                    return None
                length = int.from_bytes(hdr[1:], "big")
                data = self._recv_n(s, length)
                if len(data) < 70 or data[:4] != b"\xfeSMB":
                    return None
                dialect = int.from_bytes(data[68:70], "little")
                sec = int.from_bytes(data[66:68], "little")
                signing = "required" if sec & 2 else ("enabled" if sec & 1 else "disabled")
                return {"smb_v2_plus": True, "smb_dialect": hex(dialect), "smb_signing": signing}
        except Exception:
            return None

    def _smbv1_probe(self, host, port):
        try:
            with self._create_conn(host, port, self.timeout) as s:
                hdr = b"\xFFSMB\x72\x00\x00\x00\x00\x18\x53\xC8\x00\x00" + b"\x00"*8 + b"\x00\x00"*2 + b"\x00\x00"*2
                dialects = b"\x02NT LM 0.12\x00"
                body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
                pkt = hdr + b"\x00" + struct.pack("<H", len(body)) + body
                s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
                hdr = self._recv_n(s, 4)
                if len(hdr) != 4:
                    return None
                length = int.from_bytes(hdr[1:], "big")
                data = self._recv_n(s, length)
                if len(data) < 36 or data[:4] != b"\xFFSMB":
                    return None
                status = struct.unpack("<I", data[5:9])[0]
                return {"smb_v1": status == 0}
        except Exception:
            return None

    def _probe_host(self, host):
        res = {"host": host, "ports": {}}
        res.update(self._icmp_probe(host))
        for port in self.tcp_ports:
            state = self._tcp_state(host, port)
            info = {"protocol": "tcp", "state": state}
            if state == "open":
                info.update({k: v for k, v in (self._smbv1_probe(host, port) or {}).items()})
                info.update({k: v for k, v in (self._smbv2_probe(host, port) or {}).items()})
            res["ports"][port] = info
        return res

    @staticmethod
    def _host_iterator(hosts, cidrs):
        for h in hosts:
            yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False):
                yield str(ip)

    def _filter_targets(self, targets):
        allowed_targets = [t for t in targets if self._allowed(t, self.nets, self.ips)]
        if len(allowed_targets) != len(targets):
            raise ValueError("Targets outside allow-list")
        return allowed_targets

    @staticmethod
    def _is_success(r):
        for p in (445, 139):
            info = r["ports"].get(p)
            if info and info.get("state") == "open":
                return True
        return False

    def scan(self, hosts=None, cidrs=None):
        hosts = hosts or []
        cidrs = cidrs or []
        targets = list(self._host_iterator(hosts, cidrs))
        targets = self._filter_targets(targets)
        strategy = self.strat_cls(targets)
        ordered = list(strategy)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            fut = {ex.submit(self._probe_host, h): h for h in ordered}
            for f in concurrent.futures.as_completed(fut):
                h = fut[f]
                try:
                    self.results[h] = f.result()
                except Exception as e:
                    self.results[h] = {"error": str(e)}
        return self.results

    def successful_routes(self):
        succ = []
        for h, r in self.results.items():
            if self._is_success(r):
                for port in (445, 139):
                    info = r["ports"].get(port)
                    if info and info.get("state") == "open":
                        succ.append({"id": f"{h}:{port}", "host": h, "port": port, "details": r})
                        break
        return succ

    def save_routes(self, path):
        if not path:
            return
        succ = self.successful_routes()
        if succ:
            with open(path, "w") as f:
                json.dump(succ, f, indent=2)

    def load_routes(self, path):
        if path and os.path.isfile(path):
            with open(path) as f:
                return json.load(f)
        return None

def parse_args():
    p = argparse.ArgumentParser(description="Public IP firewall SMB scanner")
    p.add_argument("--host", action="append", default=[])
    p.add_argument("--cidr", action="append", default=[])
    p.add_argument("--input")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p.add_argument("--allowlist", required=True, help="Path to JSON allow-list")
    p.add_argument("--strategy", choices=["round", "mcts"], default="round")
    p.add_argument("--save")
    p.add_argument("--reuse")
    return p.parse_args()

def main():
    args = parse_args()
    scanner = PublicIPFirewallSMB(
        allowlist=args.allowlist,
        strategy=args.strategy,
        timeout=args.timeout,
        workers=args.workers
    )
    if args.reuse:
        data = scanner.load_routes(args.reuse)
        if data is not None:
            print(json.dumps(data, indent=2) if args.json else data)
            return
    hosts = args.host or []
    if args.input:
        with open(args.input) as f:
            hosts.extend([l.strip() for l in f if l.strip()])
    if not hosts and not args.cidr:
        sys.exit("No targets supplied")
    out = scanner.scan(hosts, args.cidr)
    scanner.save_routes(args.save)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for h, r in out.items():
            print(f"{h}:")
            for port, info in r["ports"].items():
                print(f"  {port}: {info}")

if __name__ == "__main__":
    main()

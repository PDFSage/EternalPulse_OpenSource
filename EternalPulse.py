#!/usr/bin/env python3
import argparse
import socket
import struct
import uuid
import json
import concurrent.futures
import ipaddress
import sys
import platform
import os
import random
import errno
import subprocess
import shutil
from datetime import datetime, timezone
import asyncio

class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, targets): self._targets = list(targets)
        def __iter__(self): return iter(self._targets)

    class MCTS:
        def __init__(self, targets, iters: int = 200):
            self._targets = list(targets); self._order = self._mcts(iters)
        @staticmethod
        def _score(ip): return int(ipaddress.ip_address(ip)) % 997
        def _mcts(self, iters):
            best, score = None, -1
            for _ in range(iters):
                cand = random.sample(self._targets, len(self._targets))
                s = sum(self._score(x) for x in cand)
                if s > score: best, score = cand, s
            return best
        def __iter__(self): return iter(self._order)

    def __init__(self, allowlist, strategy: str = "round", timeout: int = 2,
                 workers: int = 100, generalize: bool = False):
        self._nets, self._ips, self._reasons = self._load_allowlist(allowlist)
        self._strategy_cls = self.MCTS if strategy == "mcts" else self.RoundRobin
        self._timeout = timeout; self._workers = workers
        self._tcp_ports = [139, 445]; self._results = {}
        self._generalize = generalize

    @staticmethod
    def _load_allowlist(path):
        nets, ips, reasons = [], set(), {}
        with open(path) as f: data = json.load(f)
        if isinstance(data, dict):
            entries = list(data.get("ips", [])) + list(data.get("cidrs", []))
            reasons = {str(ipaddress.ip_address(k)): v
                       for k, v in data.get("x-permission-reasons", {}).items() if k}
        else: entries = list(data)
        for t in entries:
            try:
                if "/" in t: nets.append(ipaddress.ip_network(t, strict=False))
                else: ips.add(ipaddress.ip_address(t))
            except ValueError: pass
        return nets, ips, reasons

    @staticmethod
    def _allowed(ip, nets, ips):
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr in ips or any(ip_addr in net for net in nets)

    def _permission_reason(self, ip): return self._reasons.get(str(ipaddress.ip_address(ip)))

    @staticmethod
    def _addr_family(ip): return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _create_conn(self, host, port, timeout):
        return socket.create_connection((host, port), timeout, family=self._addr_family(host))

    @staticmethod
    def _recv_n(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk: break
            buf += chunk
        return buf

    def _tcp_state(self, host, port):
        fam = self._addr_family(host)
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(self._timeout)
        try:
            s.connect((host, port)); return "open"
        except socket.timeout: return "filtered"
        except ConnectionRefusedError: return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH): return "unreachable"
            return "error"
        finally: s.close()

    def _icmp_probe(self, host):
        v6 = ipaddress.ip_address(host).version == 6
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping6" if v6 and shutil.which("ping6") else "ping",
               flag, "1", "-W", str(self._timeout), host]
        status = "responding" if subprocess.call(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0 else "no_reply"
        return {"icmp": status}

    def _smbv2_probe(self, host, port):
        try:
            with self._create_conn(host, port, self._timeout) as s:
                guid = uuid.uuid4().bytes; dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
                negotiate = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0,
                                        0, guid, 0, 0, 0) + b"".join(struct.pack("<H", d) for d in dialects)
                smb2_hdr = (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" +
                            b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x01\x00" +
                            b"\x00\x00\x00\x00" + b"\x00"*8 + b"\x00"*4 +
                            b"\x00"*4 + b"\x00"*8 + b"\x00"*16)
                pkt = smb2_hdr + negotiate
                s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
                hdr = self._recv_n(s, 4)
                if len(hdr) != 4: return None
                length = int.from_bytes(hdr[1:], "big")
                data = self._recv_n(s, length)
                if len(data) < 70 or data[:4] != b"\xfeSMB": return None
                dialect = int.from_bytes(data[68:70], "little")
                sec = int.from_bytes(data[66:68], "little")
                signing = "required" if sec & 2 else ("enabled" if sec & 1 else "disabled")
                return {"smb_v2_plus": True, "smb_dialect": hex(dialect), "smb_signing": signing}
        except Exception: return None

    def _smbv1_probe(self, host, port):
        try:
            with self._create_conn(host, port, self._timeout) as s:
                hdr = b"\xFFSMB\x72\x00\x00\x00\x00\x18\x53\xC8\x00\x00" + b"\x00"*8 + b"\x00\x00"*2 + b"\x00\x00"*2
                dialects = b"\x02NT LM 0.12\x00"
                body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
                pkt = hdr + b"\x00" + struct.pack("<H", len(body)) + body
                s.sendall(b"\x00" + len(pkt).to_bytes(3, "big") + pkt)
                hdr = self._recv_n(s, 4)
                if len(hdr) != 4: return None
                length = int.from_bytes(hdr[1:], "big")
                data = self._recv_n(s, length)
                if len(data) < 36 or data[:4] != b"\xFFSMB": return None
                status = struct.unpack("<I", data[5:9])[0]
                return {"smb_v1": status == 0}
        except Exception: return None

    def _probe_host(self, host):
        res = {"host": host, "allow_reason": self._permission_reason(host), "ports": {}}
        res.update(self._icmp_probe(host))
        for port in self._tcp_ports:
            state = self._tcp_state(host, port); info = {"protocol": "tcp", "state": state}
            if state == "open":
                info.update(self._smbv1_probe(host, port) or {})
                info.update(self._smbv2_probe(host, port) or {})
            res["ports"][port] = info
        return res

    @staticmethod
    def _host_iterator(hosts, cidrs):
        for h in hosts: yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False): yield str(ip)

    def _filter_targets(self, targets):
        allowed = [t for t in targets if self._allowed(t, self._nets, self._ips)]
        if len(allowed) != len(targets): raise ValueError("Targets outside allow-list")
        return allowed

    @staticmethod
    def _is_success(r):
        for p in (445, 139):
            info = r["ports"].get(p)
            if info and info.get("state") == "open": return True
        return False

    async def _async_scan(self, ordered):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in ordered]
        for h, res in zip(ordered, await asyncio.gather(*futs, return_exceptions=True)):
            self._results[h] = res if not isinstance(res, Exception) else {"error": str(res)}
        return self._results

    def scan(self, hosts=None, cidrs=None, async_mode=False):
        hosts = hosts or []; cidrs = cidrs or []
        targets = list(self._host_iterator(hosts, cidrs))
        targets = self._filter_targets(targets)
        ordered = list(self._strategy_cls(targets))
        if async_mode:
            return asyncio.run(self._async_scan(ordered))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as executor:
            fut = {executor.submit(self._probe_host, h): h for h in ordered}
            for f in concurrent.futures.as_completed(fut):
                h = fut[f]
                try: self._results[h] = f.result()
                except Exception as e: self._results[h] = {"error": str(e)}
        return self._results

    def successful_routes(self):
        succ = []
        ts = datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                for port in (445, 139):
                    info = r["ports"].get(port)
                    if info and info.get("state") == "open":
                        host_field = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0") \
                                     if self._generalize else h
                        succ.append({"id": f"{host_field}:{port}", "host": host_field,
                                     "port": port, "details": r, "ts": ts})
                        break
        return succ

    def save_routes(self, path):
        if not path: return
        succ = self.successful_routes()
        if not succ: return
        existing = self.load_routes(path) or []
        by_id = {r["id"]: r for r in existing}
        for r in succ: by_id[r["id"]] = r
        with open(path, "w") as f: json.dump(list(by_id.values()), f, indent=2)

    @staticmethod
    def load_routes(path):
        if path and os.path.isfile(path):
            with open(path) as f: return json.load(f)
        return None

    @staticmethod
    def _wildcard(host):
        return host.lower() in ("any", "0.0.0.0/0", "::/0")

    @staticmethod
    def _build_fw_cmd(host, port, direction):
        sysname = platform.system().lower()
        v6 = ipaddress.ip_address("::1").version == 6 if PublicIPFirewallSMB._wildcard(host) \
             else ipaddress.ip_address(host).version == 6
        cmds = []
        if "windows" in sysname and shutil.which("netsh"):
            base = ["netsh", "advfirewall", "firewall", "add",
                    f"name=SMB{host}{port}", "dir=" + direction, "action=allow",
                    "protocol=TCP", f"localport={port}"]
            if not PublicIPFirewallSMB._wildcard(host):
                base.append(("remoteip=" if direction == "in" else "destip=") + host)
            cmds.append(base)
        elif sysname == "linux":
            chain = "INPUT" if direction == "in" else "OUTPUT"
            if shutil.which("firewall-cmd"):
                fam = "ipv6" if v6 else "ipv4"
                rule = ('rule family="%s" ' % fam)
                if not PublicIPFirewallSMB._wildcard(host):
                    rule += ("source address" if direction == "in" else "destination address") \
                            + f'="{host}" '
                rule += f'port protocol="tcp" port="{port}" accept'
                cmds.append(["firewall-cmd", "--permanent", "--add-rich-rule", rule])
            elif shutil.which("iptables"):
                tbl4 = ["iptables", "-I", chain, "-p", "tcp",
                        "--dport" if direction == "in" else "--sport", str(port), "-j", "ACCEPT"]
                tbl6 = ["ip6tables", "-I", chain, "-p", "tcp",
                        "--dport" if direction == "in" else "--sport", str(port), "-j", "ACCEPT"]
                if not PublicIPFirewallSMB._wildcard(host):
                    target = "-s" if direction == "in" else "-d"
                    tbl4[4:4] = [target, host]
                    tbl6[4:4] = [target, host]
                cmds.extend([tbl4, tbl6])
        elif sysname == "darwin" and shutil.which("pfctl"):
            rule = "pass " + direction + " proto tcp "
            if not PublicIPFirewallSMB._wildcard(host):
                rule += ("from" if direction == "in" else "to") + " " + host + " "
            rule += "port " + str(port)
            cmds.append(["sh", "-c", f'echo "{rule}" | pfctl -a com.openai.smb -f -'])
        return cmds

    def apply_firewall(self, routes, dry_run: bool = False, direction: str = "in"):
        for r in routes:
            for cmd in self._build_fw_cmd(r["host"], r["port"], direction):
                if dry_run: print(" ".join(cmd))
                else: subprocess.call(cmd)

def parse_args():
    p = argparse.ArgumentParser(description="Public IP firewall SMB scanner with IPv6 & async support")
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
    p.add_argument("--reload", dest="reuse", help=argparse.SUPPRESS)
    p.add_argument("--firewall", action="store_true", help="Apply firewall rules for successful routes")
    p.add_argument("--dry-run", action="store_true", help="Print firewall commands without executing")
    p.add_argument("--direction", choices=["in", "out"], default="in", help="Firewall rule direction")
    p.add_argument("--asyncio", action="store_true", help="Use asyncio for high concurrency")
    p.add_argument("--generalize", action="store_true", help="Save routes with wildcard host for any IP")
    return p.parse_args()

def main():
    args = parse_args()
    scanner = PublicIPFirewallSMB(allowlist=args.allowlist, strategy=args.strategy,
                                  timeout=args.timeout, workers=args.workers,
                                  generalize=args.generalize)
    if args.reuse:
        data = scanner.load_routes(args.reuse)
        if data is not None:
            if args.firewall: scanner.apply_firewall(data, args.dry_run, args.direction)
            print(json.dumps(data, indent=2) if args.json else data); return
    hosts = args.host or []
    if args.input:
        with open(args.input) as f: hosts.extend(l.strip() for l in f if l.strip())
    if not hosts and not args.cidr: sys.exit("No targets supplied")
    out = scanner.scan(hosts, args.cidr, async_mode=args.asyncio)
    save_path = args.save or args.reuse or "smb_routes.json"
    scanner.save_routes(save_path)
    if args.firewall: scanner.apply_firewall(scanner.successful_routes(),
                                             args.dry_run, args.direction)
    if args.json: print(json.dumps(out, indent=2))
    else:
        for h, r in out.items():
            print(f"{h}:")
            for port, info in r["ports"].items(): print(f"  {port}: {info}")

if __name__ == "__main__":
    main()

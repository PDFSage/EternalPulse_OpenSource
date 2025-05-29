#!/usr/bin/env python3
import argparse, socket, json, concurrent.futures, ipaddress, sys, os, errno, random, asyncio, select, struct, time, math, itertools
from datetime import datetime, timezone
try:
    from scapy.all import IP, IPv6, TCP, sr1, conf
    _SCAPY = True
except ImportError:
    _SCAPY = False

DEFAULT_ALLOWLIST = {
    "ips": [
        "198.51.100.5", "203.0.113.10", "192.0.2.1",
        "198.51.100.22", "203.0.113.15", "192.0.2.45"
    ],
    "cidrs": ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"]
}

class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self): return iter(self._t)

    class MCTS:
        def __init__(self, t, n: int = 400):
            self._t = list(t); self._o = self._mcts(n)
        @staticmethod
        def _s(ip): a = int(ipaddress.ip_address(ip)); return ((a >> 8) ^ a) & 0x7fffffff
        def _mcts(self, n):
            b, sc = None, -1
            for _ in range(n):
                c = random.sample(self._t, len(self._t))
                s = sum(self._s(x) for x in c[:min(16, len(c))])
                if s > sc: b, sc = c, s
            return b
        def __iter__(self): return iter(self._o)

    class Weighted:
        def __init__(self, t):
            self._o = sorted(t, key=self._w, reverse=True)
        @staticmethod
        def _w(ip):
            a = int(ipaddress.ip_address(ip)); return ((a >> 12) ^ (a >> 4) ^ a) & 0x7fffffff
        def __iter__(self): return iter(self._o)

    class SimulatedAnnealing:
        def __init__(self, t, n: int = 1000, temp: float = 1.0, alpha: float = 0.995):
            self._t = list(t); self._o = self._sa(n, temp, alpha)
        @staticmethod
        def _s(ip): a = int(ipaddress.ip_address(ip)); return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr): return sum(self._s(x) for x in arr[:min(16, len(arr))])
        def _sa(self, n, t, a):
            best = cur = self._t[:]; best_s = cur_s = self._score(cur)
            for _ in range(n):
                i = random.randrange(len(cur)); j = random.randrange(len(cur))
                while j == i: j = random.randrange(len(cur))
                cur[i], cur[j] = cur[j], cur[i]
                ns = self._score(cur)
                if ns > cur_s or random.random() < math.exp((ns - cur_s) / max(t, 1e-9)):
                    cur_s = ns
                    if ns > best_s: best, best_s = cur[:], ns
                else:
                    cur[i], cur[j] = cur[j], cur[i]
                t *= a
            return best
        def __iter__(self): return iter(self._o)

    class GeneticAlgorithm:
        def __init__(self, t, pop: int = 30, gen: int = 120, mut: float = 0.1):
            self._t = list(t); self._o = self._ga(pop, gen, mut)
        @staticmethod
        def _s(ip): a = int(ipaddress.ip_address(ip)); return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr): return sum(self._s(x) for x in arr[:min(16, len(arr))] if x is not None)
        def _select(self, pop, k=10):
            pop.sort(key=self._score, reverse=True)
            return pop[:k]
        def _crossover(self, p1, p2):
            a, b = sorted(random.sample(range(len(p1)), 2))
            child = [None]*len(p1)
            child[a:b] = p1[a:b]
            ptr = b
            for x in itertools.chain(p2[b:], p2[:b]):
                if x not in child:
                    if ptr == len(p1): ptr = 0
                    child[ptr] = x; ptr += 1
            if None in child:
                missing = [x for x in self._t if x not in child]
                it = iter(missing)
                for i, v in enumerate(child):
                    if v is None:
                        child[i] = next(it, random.choice(self._t))
            return child
        def _mutate(self, arr, rate):
            for i in range(len(arr)):
                if random.random() < rate:
                    j = random.randrange(len(arr))
                    arr[i], arr[j] = arr[j], arr[i]
        def _ga(self, pop_size, generations, mut):
            pop = [random.sample(self._t, len(self._t)) for _ in range(pop_size)]
            for _ in range(generations):
                parents = self._select(pop)
                children = []
                while len(children) < pop_size:
                    p1, p2 = random.sample(parents, 2)
                    c = self._crossover(p1, p2)
                    self._mutate(c, mut)
                    children.append(c)
                pop = children
            best = max(pop, key=self._score)
            return [x for x in best if x is not None]
        def __iter__(self): return iter(self._o)

    class HillClimb:
        def __init__(self, t, n: int = 5000):
            self._t = list(t); self._o = self._hc(n)
        @staticmethod
        def _s(ip): a = int(ipaddress.ip_address(ip)); return ((a >> 8) ^ a) & 0x7fffffff
        def _score(self, arr): return sum(self._s(x) for x in arr[:min(16, len(arr))])
        def _hc(self, n):
            cur = best = self._t[:]; best_s = self._score(best)
            for _ in range(n):
                i, j = random.sample(range(len(cur)), 2)
                cur[i], cur[j] = cur[j], cur[i]
                s = self._score(cur)
                if s > best_s:
                    best, best_s = cur[:], s
                else:
                    cur[i], cur[j] = cur[j], cur[i]
            return best
        def __iter__(self): return iter(self._o)

    class Combined:
        def __init__(self, t):
            self._seen = set()
            self._strategies = [
                PublicIPFirewallSMB.Weighted(t),
                PublicIPFirewallSMB.MCTS(t),
                PublicIPFirewallSMB.SimulatedAnnealing(t),
                PublicIPFirewallSMB.GeneticAlgorithm(t),
                PublicIPFirewallSMB.HillClimb(t),
                PublicIPFirewallSMB.RoundRobin(t)
            ]
        def __iter__(self):
            for strat in self._strategies:
                for ip in strat:
                    if ip not in self._seen:
                        self._seen.add(ip)
                        yield ip

    def __init__(self, allowlist=None, strategy="combo", timeout=2,
                 workers=100, generalize=True, verbose=True, retries=1):
        self._nets, self._ips, self._reasons = self._load_allowlist(allowlist)
        st_map = {
            "round": self.RoundRobin,
            "mcts": self.MCTS,
            "weighted": self.Weighted,
            "anneal": self.SimulatedAnnealing,
            "genetic": self.GeneticAlgorithm,
            "hill": self.HillClimb,
            "combo": self.Combined
        }
        self._strategy_cls = st_map.get(strategy, self.RoundRobin)
        self._timeout = timeout; self._workers = workers; self._retries = retries
        self._tcp_ports = [445, 139]; self._udp_ports = [137, 138]
        self._results, self._generalize, self._verbose = {}, generalize, verbose
        self._skipped = []

    def _log(self, *m):
        if self._verbose: print("[DBG]", *m, file=sys.stderr, flush=True)

    @staticmethod
    def _load_allowlist(src):
        if src is None: d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict): d = src.get("allow", src)
        else:
            with open(src) as f: d = json.load(f).get("allow", json.load(f))
        nets, ips = [], set()
        for t in list(d.get("ips", [])) + list(d.get("cidrs", [])):
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
        rs = {str(ipaddress.ip_address(k)): v for k, v in d.get("x-permission-reasons", {}).items()} if isinstance(d, dict) else {}
        return nets, ips, rs

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

    def _permission_reason(self, ip): return self._reasons.get(str(ipaddress.ip_address(ip)))

    @staticmethod
    def _fam(ip): return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _tcp_connect(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_STREAM); s.settimeout(self._timeout)
        try:
            s.connect((h, p)); return "open"
        except socket.timeout: return "filtered"
        except ConnectionRefusedError: return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH): return "unreachable"
            return "error"
        finally: s.close()

    def _tcp_syn(self, h, p):
        if not _SCAPY: return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="S")) if ipaddress.ip_address(h).version == 6 else (IP(dst=h)/TCP(dport=p, flags="S"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x12: return "open"
                if fl & 0x14: return "closed"
            return "filtered"
        except PermissionError: return "unavailable"
        except Exception as e:
            self._log("syn err", h, p, e); return "error"

    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM); s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            ready = select.select([s], [], [], self._timeout)
            if ready[0]:
                data, _ = s.recvfrom(1024)
                return "open" if data else "open|filtered"
            return "open|filtered"
        except socket.timeout: return "open|filtered"
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH): return "closed"
            return "error"
        finally: s.close()

    def _probe_port(self, h, p, proto):
        for _ in range(self._retries):
            if proto == "tcp":
                st = self._tcp_connect(h, p)
                if st != "open":
                    st_syn = self._tcp_syn(h, p)
                    if st_syn == "open": st = "open"
                    elif st == "filtered" and st_syn in ("closed", "error"): st = st_syn
                return st
            return self._udp_state(h, p)
        return "error"

    def _probe_host(self, h):
        res = {"host": h, "allow_reason": self._permission_reason(h), "ports": {}}
        for p in self._tcp_ports:
            res["ports"][p] = {"protocol": "tcp", "state": self._probe_port(h, p, "tcp")}
        for p in self._udp_ports:
            res["ports"][p] = {"protocol": "udp", "state": self._probe_port(h, p, "udp")}
        return res

    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts: yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False): yield str(ip)

    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen: continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips):
                self._log("ALLOWED", x)
                a.append(x)
            else:
                self._log("SKIPPED", x)
                self._skipped.append(x)
        return a

    def _is_success(self, r):
        for p in (445, 139):
            if r["ports"].get(p, {}).get("state") == "open": return True
        return False

    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for h, r in zip(order, await asyncio.gather(*futs, return_exceptions=True)):
            res = r if not isinstance(r, Exception) else {"error": str(r)}
            self._results[h] = res
            status = "success" if self._is_success(res) else "fail"
            self._log("RESULT", h, status, res.get("ports", res))
        return self._results

    def scan(self, hosts=None, cidrs=None, async_mode=False):
        t = list(self._iter_targets(hosts or [], cidrs or []))
        t = self._filter_targets(t)
        if not t:
            self._log("No targets after filtering")
            return {}
        order = list(self._strategy_cls(t))
        if async_mode:
            asyncio.run(self._async_scan(order))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
                fs = {ex.submit(self._probe_host, h): h for h in order}
                for f in concurrent.futures.as_completed(fs):
                    h = fs[f]
                    try:
                        res = f.result()
                        self._results[h] = res
                    except Exception as e:
                        self._results[h] = {"error": str(e)}
                    status = "success" if self._is_success(self._results[h]) else "fail"
                    self._log("RESULT", h, status, self._results[h].get("ports", self._results[h]))
        self._log("Scan finished", len(self._results), "scanned", len(self._skipped), "skipped", len(self.successful_routes()), "successful")
        return self._results

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                for p in (445, 139):
                    if r["ports"].get(p, {}).get("state") == "open":
                        hf = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0") if self._generalize else h
                        s.append({"id": f"{hf}:{p}", "host": hf, "port": p, "details": r, "ts": ts}); break
        self._log("Filter successful" if s else "Filter unsuccessful", len(s), "routes")
        return s

    def save_routes(self, path):
        if not path: return
        d = self.successful_routes()
        if not d: return
        e = self.load_routes(path) or []
        m = {r["id"]: r for r in e}
        for r in d: m[r["id"]] = r
        with open(path, "w") as f: json.dump(list(m.values()), f, indent=2)

    @staticmethod
    def load_routes(path):
        if path and os.path.isfile(path):
            with open(path) as f: return json.load(f)
        return None

def parse_args():
    p = argparse.ArgumentParser(description="Public IP SMB scanner (successful routes only)")
    p.add_argument("--host", action="append", default=[])
    p.add_argument("--cidr", action="append", default=[])
    p.add_argument("--input")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p.add_argument("--allowlist")
    p.add_argument("--strategy", choices=["round", "mcts", "weighted", "anneal", "genetic", "hill", "combo"], default="combo")
    p.add_argument("--save")
    p.add_argument("--reload")
    p.add_argument("--asyncio", action="store_true")
    p.add_argument("--no-generalize", action="store_false", dest="generalize")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(generalize=True)
    return p.parse_args()

def main():
    a = parse_args()
    s = PublicIPFirewallSMB(allowlist=a.allowlist, strategy=a.strategy,
                            timeout=a.timeout, workers=a.workers,
                            generalize=a.generalize, verbose=not a.quiet)
    h = a.host or []
    if a.input:
        with open(a.input) as f: h.extend(l.strip() for l in f if l.strip())
    c = a.cidr or []
    if a.reload:
        d = s.load_routes(a.reload)
        if d:
            for r in d:
                x = r.get("details", {}).get("host") or r.get("host")
                if x and x not in h: h.append(x)
    if not h and not c:
        h = [str(x) for x in s._ips]; c = [str(n) for n in s._nets]
    s.scan(h, c, async_mode=a.asyncio)
    if a.save or a.reload: s.save_routes(a.save or a.reload)
    ok = s.successful_routes()
    if a.json: print(json.dumps(ok, indent=2))
    else:
        for r in ok: print(f"{r['host']}:{r['port']} open")

if __name__ == "__main__":
    main()

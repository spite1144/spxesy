#!/usr/bin/env python3
"""
PROXY SCANNER v6.0 — Turbo Edition (CLI Version for Linux)
  • Integrated Handshake (No TCP Pre-check)
  • Parallel Protocol Racing (First-Wins logic)
  • 4 Modes: Discover, Check, Fetch, Hunt
  • Persistent JSON Storage
"""

import socket, concurrent.futures, threading
import urllib.request, os, time, re, random, json, sys, argparse

# ─────────────────────────────────────────────
#  DEFAULT CONFIG & DATA
# ─────────────────────────────────────────────
CONFIG_FILE = "proxy_scanner_config.json"
DEFAULT_PORTS = [80, 8080, 3128, 1080, 10800, 8800, 443, 7890]
COMMON_PORTS = list(DEFAULT_PORTS)

DEFAULT_FEEDS = {
    "ProxyScrape HTTP" : "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all",
    "Proxifly HTTP"    : "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "TheSpeedX HTTP"   : "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "ProxyScrape SOCKS4": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all",
    "TheSpeedX SOCKS4"  : "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "ProxyScrape SOCKS5": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all",
    "TheSpeedX SOCKS5"  : "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
}
PUBLIC_FEEDS = dict(DEFAULT_FEEDS)

RESERVED_IPS = [
    (167772160, 184549375),    (2130706432, 2147483647),
    (2851995648, 2852061183),  (2886729728, 2887778303),
    (3221225472, 3221225727),  (3232235520, 3232301055),
    (3758096384, 4026531839),
]

def load_config():
    global COMMON_PORTS, PUBLIC_FEEDS
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "ports" in data and isinstance(data["ports"], list):
                    COMMON_PORTS.clear(); COMMON_PORTS.extend(data["ports"])
                if "feeds" in data and isinstance(data["feeds"], dict):
                    PUBLIC_FEEDS.clear(); PUBLIC_FEEDS.update(data["feeds"])
    except Exception as e:
        cprint(f"[!] Error loading config: {e}")

def save_config():
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({"ports": COMMON_PORTS, "feeds": PUBLIC_FEEDS}, f, indent=4)
    except: pass

# ─────────────────────────────────────────────
#  THREAD-SAFE CONSOLE PRINTING
# ─────────────────────────────────────────────
print_lock = threading.Lock()
cancel_ev  = threading.Event()

def cprint(msg, end="\n"):
    with print_lock:
        sys.stdout.write(f"{msg}{end}")
        sys.stdout.flush()

# ─────────────────────────────────────────────
#  CORE PROXY LOGIC (v6.0 Engine)
# ─────────────────────────────────────────────
def random_ipv4():
    while True:
        val = random.getrandbits(32); is_bad = False
        for start, end in RESERVED_IPS:
            if start <= val <= end: is_bad = True; break
        if not is_bad: return socket.inet_ntoa(val.to_bytes(4, 'big'))

def _fam(ip):
    try:    socket.inet_pton(socket.AF_INET6, ip); return socket.AF_INET6
    except: return socket.AF_INET

def _d(ip): return f"[{ip}]" if _fam(ip)==socket.AF_INET6 else ip

def _proto_race(proto, fam, tgt, timeout, res_list, stop_ev):
    if stop_ev.is_set(): return
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout)
            s.connect(tgt)
            
            if proto == "socks5":
                s.sendall(b'\x05\x01\x00')
                r = s.recv(2)
                if r and r[:2] == b'\x05\x00': 
                    if not stop_ev.is_set(): res_list.append("socks5"); stop_ev.set()
            elif proto == "socks4":
                s.sendall(b'\x04\x01\x00\x50\x01\x01\x01\x01\x00')
                r = s.recv(8)
                if r and len(r) >= 2 and r[0] == 0 and r[1] == 0x5a: 
                    if not stop_ev.is_set(): res_list.append("socks4"); stop_ev.set()
            elif proto == "http":
                s.sendall(b'CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n')
                r = s.recv(512)
                if b'HTTP/' in r and any(x in r for x in [b'200', b'403', b'407']): 
                    if not stop_ev.is_set(): res_list.append("http"); stop_ev.set()
    except: pass

def detect_proxy(ip, port, timeout):
    fam, tgt, d = _fam(ip), (ip, port), _d(ip)
    res_list = []
    stop_ev = threading.Event()
    threads = []
    
    for p in ["socks5", "socks4", "http"]:
        t = threading.Thread(target=_proto_race, args=(p, fam, tgt, timeout, res_list, stop_ev), daemon=True)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join(timeout=timeout + 0.2)
        
    if res_list: return "alive", f"{res_list[0]}://{d}:{port}"
    return "dead", f"{d}:{port}"

def check_known(uri, timeout):
    uri = uri.strip()
    m = re.match(r'^(socks5|socks4|http)://\[?([^\]:/]+)\]?:(\d+)$', uri, re.I)
    if not m:
        m2 = re.match(r'^\[?([^\]:/]+)\]?:(\d+)$', uri)
        if not m2: return "dead", uri, None
        st, res = detect_proxy(m2.group(1), int(m2.group(2)), timeout)
        return st, res, None
        
    proto, ip, port = m.group(1).lower(), m.group(2), int(m.group(3))
    fam, tgt, d = _fam(ip), (ip, port), _d(ip)
    t0 = time.perf_counter()
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout); s.connect(tgt)
            if proto == "socks5":
                s.sendall(b'\x05\x01\x00'); r = s.recv(16)
                if len(r) >= 2 and r[:2] == b'\x05\x00': return "alive", f"socks5://{d}:{port}", round((time.perf_counter()-t0)*1000, 1)
            elif proto == "socks4":
                s.sendall(b'\x04\x01\x00\x50\x01\x01\x01\x01\x00'); r = s.recv(16)
                if len(r) >= 2 and r[0] == 0 and r[1] == 0x5a: return "alive", f"socks4://{d}:{port}", round((time.perf_counter()-t0)*1000, 1)
            else:
                s.sendall(b'CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n'); r = s.recv(512)
                if b'HTTP/' in r and any(x in r for x in [b'200', b'403', b'407']): return "alive", f"http://{d}:{port}", round((time.perf_counter()-t0)*1000, 1)
    except: pass
    return "dead", f"{proto}://{d}:{port}", None

def parse_ip(line):
    line = line.strip()
    if not line or line.startswith('#'): return None, None
    m = re.match(r'^\[(.+)\]:(\d+)$', line)
    if m: return m.group(1), int(m.group(2))
    if line.count(':') >= 2 and not line.startswith('['):
        try: socket.inet_pton(socket.AF_INET6, line); return line, None
        except: pass
    if ':' in line:
        p = line.rsplit(':', 1)
        if p[1].isdigit():
            ip = p[0].strip('[]')
            if ip.count(':') == 0: return ip, int(p[1])
    return line.strip('[]'), None

def _save(path, lines):
    with open(path, 'w', encoding='utf-8') as f: f.write('\n'.join(lines))

def _scan_loop(targets, fn, timeout, max_threads):
    total = len(targets)
    threads = min(int(max_threads), max(1, total), 2000)
    alive, dead, sc = [], [], 0
    t0 = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fs = {ex.submit(fn, t, timeout): t for t in targets}
        try:
            for f in concurrent.futures.as_completed(fs):
                if cancel_ev.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    cprint("\n[!] Scan cancelled by user.")
                    break
                sc += 1
                try: res = f.result()
                except: res = ("dead", "error", None)
                
                st, uri = res[0], res[1]
                lat_s = f" {res[2]:.0f}ms" if len(res) > 2 and res[2] else ""
                
                if st == "alive":
                    alive.append(uri)
                    cprint(f" [+] ALIVE: {uri}{lat_s}")
                else:
                    dead.append(uri)
                
                if sc % 50 == 0 or sc == total:
                    rate = sc / (time.time() - t0 + 1e-9)
                    cprint(f" [*] Progress: {sc}/{total} | Alive: {len(alive)} | Dead: {len(dead)} | Rate: {rate:.0f}/s", end="\r")
        except KeyboardInterrupt:
            cancel_ev.set()
            ex.shutdown(wait=False, cancel_futures=True)
            
    cprint("") # New line after progress bar
    return alive, dead, time.time() - t0

# ─────────────────────────────────────────────
#  WORKERS (CLI Adaptations)
# ─────────────────────────────────────────────
def cmd_discover(args):
    try:
        with open(args.input, 'r', encoding='utf-8', errors='replace') as f:
            raw = [l.strip() for l in f if l.strip()]
    except Exception as e:
        cprint(f"[!] Error reading file: {e}"); return

    unique = list(dict.fromkeys(raw))
    tgts = set()
    for line in unique:
        ip, port = parse_ip(line)
        if not ip: continue
        for p in ([port] if port else COMMON_PORTS): tgts.add((ip, p))
    tgts = list(tgts)
    
    cprint(f"[*] Port Discovery Mode")
    cprint(f"[-] Loaded {len(raw)} IPs -> {len(unique)} Unique -> {len(tgts)} Targets")
    
    fn = lambda tgt, to: detect_proxy(tgt[0], tgt[1], to)
    alive, dead, el = _scan_loop(tgts, fn, args.timeout, args.threads)
    
    base = os.path.splitext(args.input)[0]
    dead_ips = sorted(set(re.sub(r'^(\w+://)?([^:]+)(:\d+)?$', r'\2', u) for u in dead))
    _save(f"{base}_alive.txt", alive)
    _save(f"{base}_dead.txt", dead_ips)
    
    cprint(f"[=] Done in {el:.1f}s | ALIVE: {len(alive)} | DEAD IPs: {len(dead_ips)}")

def cmd_check(args):
    try:
        with open(args.input, 'r', encoding='utf-8', errors='replace') as f:
            raw = [l.strip() for l in f if l.strip()]
    except Exception as e:
        cprint(f"[!] Error reading file: {e}"); return

    unique = list(dict.fromkeys(raw))
    cprint(f"[*] Protocol Check Mode")
    cprint(f"[-] Target Protocols: {len(unique)}")
    
    alive, dead, el = _scan_loop(unique, check_known, args.timeout, args.threads)
    
    base = os.path.splitext(args.input)[0]
    _save(f"{base}_alive.txt", alive)
    _save(f"{base}_dead.txt", dead)
    
    cprint(f"[=] Done in {el:.1f}s | ALIVE: {len(alive)} | DEAD: {len(dead)}")

def cmd_fetch(args):
    cprint(f"[*] Fetching Public Feeds...")
    proxies = []
    feeds_to_fetch = list(PUBLIC_FEEDS.keys()) if args.feeds.lower() == 'all' else [f.strip() for f in args.feeds.split(',')]
    
    for name in feeds_to_fetch:
        if cancel_ev.is_set(): break
        if name not in PUBLIC_FEEDS: continue
        url = PUBLIC_FEEDS[name]
        cprint(f"[-] Downloading from {name}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ProxyScanner/6.0-CLI"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode('utf-8', 'replace')
            nl, ph = name.lower(), "http"
            if "socks5" in nl: ph = "socks5"
            elif "socks4" in nl: ph = "socks4"
            
            tagged = []
            for l in text.splitlines():
                l = l.strip()
                if not l: continue
                if re.match(r'^(socks5|socks4|http)://', l, re.I): tagged.append(l)
                elif re.match(r'^\[?[\w:.]+\]?:\d+$', l): tagged.append(f"{ph}://{l}")
            proxies.extend(tagged)
            cprint(f" [+] Fetched {len(tagged)} items.")
        except Exception as e:
            cprint(f" [!] Error fetching {name}: {e}")
            
    if not proxies:
        cprint("[!] No proxies fetched."); return
        
    unique = list(dict.fromkeys(proxies))
    cprint(f"[*] Starting scan for {len(unique)} fetched proxies...")
    alive, dead, el = _scan_loop(unique, check_known, args.timeout, args.threads)
    
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(args.outdir, f"public_alive_{ts}.txt")
    _save(out, alive)
    cprint(f"[=] Done in {el:.1f}s | Saved to {out} | ALIVE: {len(alive)}")

def cmd_hunt(args):
    cprint(f"[*] Global IP Hunt Mode")
    cprint(f"[-] Target Alive Amount: {args.goal}")
    
    ports = [int(p.strip()) for p in args.ports.split(',')] if args.ports else COMMON_PORTS
    cprint(f"[-] Target Ports: {ports}")
    
    alive_proxies = []
    scanned_total = 0
    t0 = time.time()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            while len(alive_proxies) < args.goal and not cancel_ev.is_set():
                batch_size = args.threads * 2
                futures = []
                for _ in range(batch_size):
                    ip = random_ipv4()
                    for p in ports: futures.append(ex.submit(detect_proxy, ip, p, args.timeout))
                
                for f in concurrent.futures.as_completed(futures):
                    if cancel_ev.is_set(): break
                    scanned_total += 1
                    try:
                        status, res = f.result()
                        if status == "alive" and len(alive_proxies) < args.goal:
                            alive_proxies.append(res)
                            cprint(f"\n [+] HUNTED: {res}")
                    except: pass
                    
                    if scanned_total % 200 == 0:
                        rate = scanned_total / (time.time() - t0 + 1e-9)
                        cprint(f" [*] IPs Scanned: {scanned_total} | Found: {len(alive_proxies)}/{args.goal} | Rate: {rate:.0f}/s", end="\r")
                    
                    if len(alive_proxies) >= args.goal: break
            ex.shutdown(wait=False, cancel_futures=True)
    except KeyboardInterrupt:
        cancel_ev.set()
        cprint("\n[!] Hunt cancelled.")
        
    cprint("")
    if alive_proxies:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_file = f"global_alive_hunt_{ts}.txt"
        _save(out_file, alive_proxies)
        cprint(f"[=] Hunt successful! Found {len(alive_proxies)} alive proxies. Saved to {out_file}.")
    else:
        cprint("[!] No IPs found or process aborted.")

# ─────────────────────────────────────────────
#  MAIN CLI ROUTER
# ─────────────────────────────────────────────
def main():
    load_config()
    
    parser = argparse.ArgumentParser(description="PROXY SCANNER v6.0 (CLI Edition)")
    subparsers = parser.add_subparsers(dest="mode", help="Execution modes", required=True)
    
    # Mode: discover
    p_discover = subparsers.add_parser("discover", help="Port Discovery from IP list")
    p_discover.add_argument("-i", "--input", required=True, help="Input text file containing IPs")
    p_discover.add_argument("-t", "--timeout", type=float, default=2.5, help="Timeout in seconds (default: 2.5)")
    p_discover.add_argument("-w", "--threads", type=int, default=300, help="Max worker threads (default: 300)")
    p_discover.set_defaults(func=cmd_discover)
    
    # Mode: check
    p_check = subparsers.add_parser("check", help="Protocol Check from IP:Port list")
    p_check.add_argument("-i", "--input", required=True, help="Input text file containing proxy lists")
    p_check.add_argument("-t", "--timeout", type=float, default=2.5, help="Timeout in seconds")
    p_check.add_argument("-w", "--threads", type=int, default=300, help="Max worker threads")
    p_check.set_defaults(func=cmd_check)
    
    # Mode: fetch
    p_fetch = subparsers.add_parser("fetch", help="Fetch & scan from public feeds")
    p_fetch.add_argument("-f", "--feeds", default="all", help="Comma-separated feed names or 'all'")
    p_fetch.add_argument("-o", "--outdir", default=".", help="Output directory path")
    p_fetch.add_argument("-t", "--timeout", type=float, default=2.5, help="Timeout in seconds")
    p_fetch.add_argument("-w", "--threads", type=int, default=300, help="Max worker threads")
    p_fetch.set_defaults(func=cmd_fetch)
    
    # Mode: hunt
    p_hunt = subparsers.add_parser("hunt", help="Global IP Hunt (Random Generator)")
    p_hunt.add_argument("-g", "--goal", type=int, default=100, help="Target amount of alive IPs to find")
    p_hunt.add_argument("-p", "--ports", default="", help="Comma-separated ports (leave blank for config defaults)")
    p_hunt.add_argument("-t", "--timeout", type=float, default=2.5, help="Timeout in seconds")
    p_hunt.add_argument("-w", "--threads", type=int, default=300, help="Max worker threads")
    p_hunt.set_defaults(func=cmd_hunt)

    args = parser.parse_args()
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        cancel_ev.set()
        cprint("\n[!] Exiting...")

if __name__ == "__main__":
    main()
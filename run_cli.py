#!/usr/bin/env python3
"""
PROXY SCANNER v6.0 — Fetch Only Edition (HTTPS Supported)
  • Integrated Handshake (No TCP Pre-check)
  • Parallel Protocol Racing (SOCKS5, SOCKS4, HTTPS, HTTP)
  • Public Feed Fetcher -> proxy.txt
"""

import socket, concurrent.futures, threading
import urllib.request, os, time, re, json, sys, argparse

CONFIG_FILE = "proxy_scanner_config.json"
DEFAULT_FEEDS = {
    # ------------------ HTTP FEEDS ------------------
    "TheSpeedX HTTP": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "Proxifly HTTP": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
    "ClearProxy HTTP": "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt",
    "Jetkai HTTP": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "Monosans HTTP": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "ShiftyTR HTTP": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "Proxy4Parsing HTTP": "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "Zaeem20 HTTP": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "ALIILAPRO HTTP": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "B4RC0DE HTTP": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
    "ErcinDedeoglu HTTP": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "HyperBeats HTTP": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "Volodichev HTTP": "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "Andigwandi HTTP": "https://raw.githubusercontent.com/andigwandi/free-proxy/main/http.txt",
    "ProxyScrape API HTTP": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "PubProxy API HTTP": "https://pubproxy.com/api/proxy?limit=50&format=txt&type=http",

    # ------------------ HTTPS FEEDS ------------------
    "Rooster HTTPS": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "Proxifly HTTPS": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
    "ShiftyTR HTTPS": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "ErcinDedeoglu HTTPS": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "Javadbazokar HTTPS": "https://raw.githubusercontent.com/javadbazokar/PROXY-List/main/https.txt",
    "Aslisk HTTPS": "https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
    "GFPcom HTTPS": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt",
    "ProxyScrape API HTTPS": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=yes&anonymity=all",

    # ------------------ SOCKS4 FEEDS ------------------
    "TheSpeedX SOCKS4": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "Proxifly SOCKS4": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
    "ClearProxy SOCKS4": "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks4/raw/all.txt",
    "Jetkai SOCKS4": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "Rooster SOCKS4": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "Monosans SOCKS4": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "R00tee SOCKS4": "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",
    "ShiftyTR SOCKS4": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "Zaeem20 SOCKS4": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "ALIILAPRO SOCKS4": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "B4RC0DE SOCKS4": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
    "HyperBeats SOCKS4": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks4.txt",
    "Volodichev SOCKS4": "https://raw.githubusercontent.com/Volodichev/proxy-list/main/socks4.txt",
    "Andigwandi SOCKS4": "https://raw.githubusercontent.com/andigwandi/free-proxy/main/socks4.txt",
    "ProxyScrape API SOCKS4": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
    "Proxyscan API SOCKS4": "https://www.proxyscan.io/download?type=socks4",

    # ------------------ SOCKS5 FEEDS ------------------
    "TheSpeedX SOCKS5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "Proxifly SOCKS5": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "ClearProxy SOCKS5": "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt",
    "Jetkai SOCKS5": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "Rooster SOCKS5": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "Hookzof SOCKS5": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "Monosans SOCKS5": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "Prxchk SOCKS5": "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "R00tee SOCKS5": "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
    "ShiftyTR SOCKS5": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "Zaeem20 SOCKS5": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "ALIILAPRO SOCKS5": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "B4RC0DE SOCKS5": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
    "ErcinDedeoglu SOCKS5": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "HyperBeats SOCKS5": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks5.txt",
    "Volodichev SOCKS5": "https://raw.githubusercontent.com/Volodichev/proxy-list/main/socks5.txt",
    "Andigwandi SOCKS5": "https://raw.githubusercontent.com/andigwandi/free-proxy/main/socks5.txt",
    "ProxyScrape API SOCKS5": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
    "PubProxy API SOCKS5": "https://pubproxy.com/api/proxy?limit=50&format=txt&type=socks5",
    "Proxyscan API SOCKS5": "https://www.proxyscan.io/download?type=socks5",
}
PUBLIC_FEEDS = dict(DEFAULT_FEEDS)

def load_config():
    global PUBLIC_FEEDS
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "feeds" in data and isinstance(data["feeds"], dict):
                    PUBLIC_FEEDS.clear(); PUBLIC_FEEDS.update(data["feeds"])
    except Exception as e:
        cprint(f"[!] Error loading config: {e}")

print_lock = threading.Lock()
cancel_ev  = threading.Event()

def cprint(msg, end="\n"):
    with print_lock:
        sys.stdout.write(f"{msg}{end}")
        sys.stdout.flush()

def _fam(ip):
    try:    socket.inet_pton(socket.AF_INET6, ip); return socket.AF_INET6
    except: return socket.AF_INET

def _d(ip): return f"[{ip}]" if _fam(ip)==socket.AF_INET6 else ip

def _proto_race(proto, fam, tgt, timeout, res_list, stop_ev):
    """ส่ง Payload แยกตาม Protocol แข่งกันเข้าเส้นชัย"""
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
            elif proto == "https":
                # เช็ก HTTPS Proxy ด้วยการขอเชื่อมต่อผ่านพอร์ต 443
                s.sendall(b'CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n')
                r = s.recv(512)
                if b'HTTP/' in r and any(x in r for x in [b'200', b'403', b'407']): 
                    if not stop_ev.is_set(): res_list.append("https"); stop_ev.set()
            elif proto == "http":
                # เช็ก HTTP Proxy ด้วยการขอเชื่อมต่อผ่านพอร์ต 80
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
    
    # วิ่งแข่ง 4 โปรโตคอลพร้อมกัน
    for p in ["socks5", "socks4", "https", "http"]:
        t = threading.Thread(target=_proto_race, args=(p, fam, tgt, timeout, res_list, stop_ev), daemon=True)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join(timeout=timeout + 0.2)
        
    if res_list: return "alive", f"{res_list[0]}://{d}:{port}"
    return "dead", f"{d}:{port}"

def check_known(uri, timeout):
    uri = uri.strip()
    # อัปเดต Regex ให้รองรับการอ่าน https://
    m = re.match(r'^(socks5|socks4|https|http)://\[?([^\]:/]+)\]?:(\d+)$', uri, re.I)
    if not m:
        m2 = re.match(r'^\[?([^\]:/]+)\]?:(\d+)$', uri)
        if not m2: return "dead", uri
        st, res = detect_proxy(m2.group(1), int(m2.group(2)), timeout)
        return st, res
        
    proto, ip, port = m.group(1).lower(), m.group(2), int(m.group(3))
    fam, tgt, d = _fam(ip), (ip, port), _d(ip)
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout); s.connect(tgt)
            if proto == "socks5":
                s.sendall(b'\x05\x01\x00'); r = s.recv(16)
                if len(r) >= 2 and r[:2] == b'\x05\x00': return "alive", f"socks5://{d}:{port}"
            elif proto == "socks4":
                s.sendall(b'\x04\x01\x00\x50\x01\x01\x01\x01\x00'); r = s.recv(16)
                if len(r) >= 2 and r[0] == 0 and r[1] == 0x5a: return "alive", f"socks4://{d}:{port}"
            elif proto == "https":
                s.sendall(b'CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n'); r = s.recv(512)
                if b'HTTP/' in r and any(x in r for x in [b'200', b'403', b'407']): return "alive", f"https://{d}:{port}"
            else:
                s.sendall(b'CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n'); r = s.recv(512)
                if b'HTTP/' in r and any(x in r for x in [b'200', b'403', b'407']): return "alive", f"http://{d}:{port}"
    except: pass
    return "dead", f"{proto}://{d}:{port}"

def _save(path, lines):
    with open(path, 'w', encoding='utf-8') as f: f.write('\n'.join(lines))

def _scan_loop(targets, fn, timeout, max_threads):
    total = len(targets)
    threads = min(int(max_threads), max(1, total), 2000)
    alive, sc = [], 0
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
                except: res = ("dead", "error")
                
                st, uri = res[0], res[1]
                
                if st == "alive":
                    alive.append(uri)
                    cprint(f" [+] ALIVE: {uri}")
                
                if sc % 50 == 0 or sc == total:
                    rate = sc / (time.time() - t0 + 1e-9)
                    cprint(f" [*] Progress: {sc}/{total} | Alive: {len(alive)} | Rate: {rate:.0f}/s", end="\r")
        except KeyboardInterrupt:
            cancel_ev.set()
            ex.shutdown(wait=False, cancel_futures=True)
            
    cprint("") # New line after progress bar
    return alive, time.time() - t0

def main():
    load_config()
    
    parser = argparse.ArgumentParser(description="PROXY SCANNER v6.0 (Fetch Only Edition + HTTPS)")
    parser.add_argument("-f", "--feeds", default="all", help="Comma-separated feed names or 'all' (default: all)")
    parser.add_argument("-t", "--timeout", type=float, default=5, help="Timeout in seconds (default: 5)")
    parser.add_argument("-w", "--threads", type=int, default=1000, help="Max worker threads (default: 1000)")
    args = parser.parse_args()
    
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
            elif "https" in nl: ph = "https" # จับ Keyword HTTPS จากชื่อ Feed
            
            tagged = []
            for l in text.splitlines():
                l = l.strip()
                if not l: continue
                # รองรับการดึงบรรทัดที่มี https:// ตรงๆ ออกมาจาก Raw Data
                if re.match(r'^(socks5|socks4|https|http)://', l, re.I): tagged.append(l)
                elif re.match(r'^\[?[\w:.]+\]?:\d+$', l): tagged.append(f"{ph}://{l}")
            proxies.extend(tagged)
            cprint(f" [+] Fetched {len(tagged)} items.")
        except Exception as e:
            cprint(f" [!] Error fetching {name}: {e}")
            
    if not proxies:
        cprint("[!] No proxies fetched.")
        return
        
    unique = list(dict.fromkeys(proxies))
    cprint(f"[*] Starting scan for {len(unique)} fetched proxies...")
    
    try:
        alive, el = _scan_loop(unique, check_known, args.timeout, args.threads)
    except KeyboardInterrupt:
        cancel_ev.set()
        cprint("\n[!] Exiting...")
        return
    
    out = "proxy.txt"
    if alive:
        _save(out, alive)
        cprint(f"[=] Done in {el:.1f}s | Saved to {out} | ALIVE: {len(alive)}")
    else:
        _save(out, [])
        cprint(f"[=] Done in {el:.1f}s | No alive proxies found. {out} is empty.")

if __name__ == "__main__":
    main()
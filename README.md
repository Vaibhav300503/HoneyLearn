# 🛡️ Honeypot v2 — SOC-Grade AI Threat Detection Platform

A production-grade, AI-powered web honeypot platform that tracks attacker sessions deeply, classifies attacks automatically, generates threat intelligence, maps to MITRE ATT&CK, and provides real-time SOC analytics.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Premium Warm Dashboard** | A highly aesthetic, card-based dashboard with a warm cream/amber palette, smooth micro-animations, and dynamic SVG gauges. Pure HTML/CSS/JS (no heavy frontend frameworks). |
| **Comprehensive Attack Simulator** | A built-in Python script (`tests/attack_simulator.py`) to safely fire realistic payloads (SQLi, XSS, RCE, Brute Force, Scanners, etc.) at your local instance to verify detection and UI updates. |
| **Attacker Fingerprinting** | Unique ID per visitor using IP + UA + header patterns + optional browser fingerprinting. |
| **AI Attack Classification** | Uses `scikit-learn` (TF-IDF + LinearSVC/Isolation Forest) to classify incoming traffic into 7 exact attack categories with statistical confidence scores. |
| **Session Replay Timeline** | Ordered attacker journey tracking with timestamps, payloads, and time deltas. |
| **MITRE ATT&CK Mapping** | Auto-maps detected attacks to MITRE techniques (T1190, T1110, T1059, etc.). |
| **Honeytokens (Decoys)** | Fake API keys, JWTs, AWS keys embedded in trap HTML pages — actively triggers HIGH RISK alerts upon reuse. |
| **Threat Intelligence Export** | JSON, CSV, and STIX 2.1 data export formatting for SOC incident response systems. |
| **Multi-Tier Auto Blocking** | Local database blocks + Cloudflare API + Nginx deny rules auto-generation. |
| **Real-time Alerting** | Integrations for Telegram, Email (SMTP), and Discord webhooks. |
| **Incident Reports** | Markdown incident reports with full attacker analysis generated per session. |

## 🏗️ Architecture Flow

```text
Request → [IP Check] → [Fingerprint] → [Session Track] → [Honeytoken Check]
                                                               ↓
                                              [AI Anomaly Score + Attack Classify]
                                                               ↓
                                              [MITRE Map] → [Alert?] → [Block?]
                                                               ↓
                                                          [Log to DB]
```

## 📂 Project Structure

```text
HoneyPOt/
├── app/
│   ├── main.py                # FastAPI app with request-parsing middleware
│   ├── config.py              # Centralized environment configuration
│   ├── database.py            # SQLAlchemy engine + SQLite/Postgres session
│   ├── models.py              # 9 database tables (logs, fingerprints, sessions, etc.)
│   ├── fingerprint.py         # Attacker fingerprint engine
│   ├── session_tracker.py     # Session replay timeline builder
│   ├── honeytokens.py         # Honeytoken decoy generation
│   ├── mitre.py               # MITRE ATT&CK mapping engine
│   ├── sanitizer.py           # Payload sanitization and XSS escape utilities
│   ├── blocking.py            # IP block manager (Local + Next-gen Firewalls)
│   ├── cloudflare_blocker.py  # Cloudflare integration for hard WAF blocking
│   ├── nginx_blocker.py       # Nginx deny rules generator
│   ├── alerting.py            # Telemetry/alert dispatcher (Discord, Email, TG)
│   ├── incident_report.py     # Markdown incident report generator
│   ├── export.py              # STIX 2.1 / JSON / CSV Exports
│   ├── ml/
│   │   ├── anomaly_detector.py    # IsolationForest threat scoring module
│   │   ├── train.py               # Anomaly model continuous training
│   │   ├── attack_classifier.py   # TF-IDF + LinearSVC ML classifier
│   │   ├── classifier_train.py    # Retraining scripts over synthetic datasets
│   │   └── feature_extractor.py   # Token extraction heuristics
│   └── static/
│       ├── index.html         # Aesthetically premium 8-tab SPA dashboard
│       ├── styles.css         # Warm card-based UI Design System (No Tailwind)
│       ├── app.js             # Client logic (animations, charts, API fetches)
│       └── fingerprint.js     # Browser-level fingerprinting JS logic
├── tests/
│   ├── test_honeypot.py       # Unit test suite for core modules
│   ├── integration_test.py    # Local integration testing
│   └── attack_simulator.py    # 🚨 Local Attack Payload Generation Tool (Simulations)
├── docker-compose.yml         # Container stack configurations
├── .env.example               # Config template
└── requirements.txt           # Python dependencies
```

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites & Environment
Ensure you have Python 3.9+ installed and running. Create a virtual environment and load requirements:
```powershell
python -m venv venv
.\venv\Scripts\activate       # On Windows
source venv/bin/activate      # On Linux/Mac
pip install -r requirements.txt
```

### 2. Run the Honeypot Server
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
On the first startup, the system automatically initializes an SQLite database (`honeypot.db`) and trains the synthetic ML models.

### 3. Access Premium Dashboard
Navigate to: **[http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)**

---

## 🧪 Testing the Platform (Attack Simulator)

To truly see the platform in action, you can safely blast your own honeypot instance using the built-in **Attack Simulator**. This will populate the dashboard with realistic security threats, trigger MITRE mappings, calculate anomaly scores, and initiate autoblocking functionality.

Open a **separate terminal** and run the simulator script.

### Using the Attack Simulator
Run the Python simulator script located in `tests/attack_simulator.py`:

```powershell
# Run ALL attack scenarios (Recommended to fully populate dashboard)
python tests/attack_simulator.py --scenario all

# Test specific attack payloads
python tests/attack_simulator.py --scenario sql
python tests/attack_simulator.py --scenario xss
python tests/attack_simulator.py --scenario rce
python tests/attack_simulator.py --scenario brute
python tests/attack_simulator.py --scenario scanner
python tests/attack_simulator.py --scenario credential
python tests/attack_simulator.py --scenario honeytoken
python tests/attack_simulator.py --scenario traversal
python tests/attack_simulator.py --scenario recon
```

**What the Simulator Does:**
1. It spoofs various attacker IP addresses using the `X-Forwarded-For` header.
2. It sends realistic exploit attempts matched to common CVEs and typical attack patterns.
3. Once completed, your dashboard will light up with attacks under the `Attacks` tab, session replays, and visually populate the `Overview` counter animations.

---

## 🐳 Docker Deployment (Production)

### 1. Configure the `.env` settings
```bash
cp .env.example .env
# Remember to adjust any WEBHOOK URLs or BLOCK Thresholds!
```

### 2. Start Services
```bash
docker-compose up -d --build
```
This initializes a robust Docker stack containing **PostgreSQL** (persistent storage replacing SQLite in production mode) and the **Honeypot app layer**. 

---

## 📊 Dashboard Panes

| Dashboard Tab | Purpose |
|-----|-------------|
| **📊 Overview** | High-level widgets, attack distribution chart, SVG Threat Gauge, and scrolling activity logs. |
| **👁️ Sessions** | Track session connections linking identical IPs and Header patterns across multiple interaction timestamps. |
| **🕐 Replay** | An exact timeline showing every request path, payload, and chronological behavior progression of an attacker. |
| **⚔️ Attacks** | Grouped ML classification analytics separated into the 7 primary attack dimensions. |
| **🗺️ MITRE** | Maps observed activity to recognized MITRE ATT&CK techniques with relative confidence bars. |
| **🚫 Blocked** | Active Block List. Threat actors exceeding 85 threat blocks are automatically suspended. Manage unblocks here. |
| **🍯 Tokens** | Deploy and monitor decoy credentials (Keys/JWTs) implanted into exposed HTML components. |
| **📤 Export** | Download JSON, CSV, and SOC-compatible STIX 2.1 Threat Intel files. |

---

## 🗺️ MITRE ATT&CK Coverage Map

| Attack | Tactic | Technique |
|--------|--------|-----------|
| **SQL Injection** | Initial Access | T1190 — Exploit Public-Facing Application |
| **Cross Site Scripting** | Initial Access | T1189 — Drive-by Compromise |
| **Brute Force** | Credential Access | T1110 — Brute Force |
| **Credential Stuffing** | Credential Access | T1110.004 — Credential Stuffing |
| **Directory Traversal** | Discovery | T1083 — File and Directory Discovery |
| **Remote Code Exe** | Execution | T1059 — Command and Scripting Interpreter |
| **Bot Scanner** | Reconnaissance | T1595 — Active Scanning |
| **Honeytoken Theft** | Collection | T1528 — Steal Application Access Token |

---

## 🔌 Optional Auto-Integrations

Append these combinations into your `.env` to unlock extra capabilities:

* **Cloudflare Threat Blocking Integration** `CLOUDFLARE_API_TOKEN` & `CLOUDFLARE_ZONE_ID`
* **Telegram Webhooks** `TELEGRAM_BOT_TOKEN` & `TELEGRAM_CHAT_ID`
* **Email Threat Dispatching** `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`
* **Discord Ping Analytics** `DISCORD_WEBHOOK_URL` 

---

*Built as a SOC-grade defensive honeypot platform. For educational and authorized security research purposes only. Never utilize this tool for outbound attacks.*

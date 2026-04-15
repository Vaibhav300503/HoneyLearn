# 🛡️ Honeypot v2 — SOC-Grade AI Threat Detection Platform

A production-grade, AI-powered web honeypot platform that tracks attacker sessions deeply, classifies attacks automatically, generates threat intelligence, maps to MITRE ATT&CK, and provides real-time SOC analytics.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Attacker Fingerprinting** | Unique ID per visitor using IP + UA + header patterns + optional browser fingerprint |
| **AI Attack Classification** | TF-IDF + LinearSVC classifies into 7 attack categories with confidence scores |
| **Session Replay Timeline** | Ordered attacker journey with timestamps, payloads, and time deltas |
| **MITRE ATT&CK Mapping** | Auto-maps detected attacks to MITRE techniques (T1190, T1110, etc.) |
| **Honeytokens** | Fake API keys, JWTs, AWS keys embedded in trap pages — triggers HIGH RISK on reuse |
| **Threat Intelligence Export** | JSON, CSV, and STIX 2.1 export for SOC integration |
| **Auto Blocking** | Cloudflare API + Nginx deny rules generation |
| **Alerting** | Telegram, Email (SMTP), and Discord webhook alerts |
| **Incident Reports** | Markdown incident reports with full attacker analysis |
| **Premium Dashboard** | 8-tab glassmorphism UI with Chart.js analytics |

## 🏗️ Architecture

```
Request → [IP Check] → [Fingerprint] → [Session Track] → [Honeytoken Check]
                                                               ↓
                                              [AI Anomaly Score + Attack Classify]
                                                               ↓
                                              [MITRE Map] → [Alert?] → [Block?]
                                                               ↓
                                                          [Log to DB]
```

## 📂 Project Structure

```
HoneyPOt/
├── app/
│   ├── main.py              # FastAPI app with middleware pipeline
│   ├── config.py             # Centralized environment configuration
│   ├── database.py           # SQLAlchemy engine + session
│   ├── models.py             # 9 database tables (logs, fingerprints, sessions, etc.)
│   ├── blocking.py           # Multi-backend IP blocking (local + Cloudflare + Nginx)
│   ├── fingerprint.py        # Attacker fingerprinting engine
│   ├── session_tracker.py    # Session replay timeline builder
│   ├── honeytokens.py        # Honeytoken generation + validation
│   ├── mitre.py              # MITRE ATT&CK mapping engine
│   ├── alerting.py           # Multi-channel alert dispatcher
│   ├── incident_report.py    # Markdown incident report generator
│   ├── export.py             # JSON/CSV/STIX 2.1 export
│   ├── sanitizer.py          # Payload sanitization utilities
│   ├── cloudflare_blocker.py # Cloudflare API integration
│   ├── nginx_blocker.py      # Nginx deny rules generator
│   ├── ml/
│   │   ├── anomaly_detector.py    # IsolationForest threat scoring
│   │   ├── train.py               # Anomaly model training
│   │   ├── attack_classifier.py   # TF-IDF + LinearSVC classifier
│   │   ├── classifier_train.py    # Classifier training with synthetic data
│   │   └── feature_extractor.py   # Shared pattern detection library
│   └── static/
│       ├── index.html         # Dashboard (8-tab SPA)
│       ├── app.js             # Dashboard logic + charts
│       └── fingerprint.js     # Browser-side fingerprinting
├── tests/
│   └── test_honeypot.py       # Test suite
├── Dockerfile                 # Production container
├── docker-compose.yml         # PostgreSQL + App stack
├── .env.example               # Environment variable template
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.9+ installed

### 1. Setup Virtual Environment
```powershell
cd HoneyPOt
python -m venv venv
.\venv\Scripts\activate
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run the Server
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

On first startup, the system will:
- Create the SQLite database (`honeypot.db`) automatically
- Train the attack classifier on synthetic data (~200 samples)
- Train the anomaly detector if data exists

### 4. Access Dashboard
Open **[http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)**

---

## 🐳 Docker Deployment (Production)

### 1. Copy Environment File
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start Services
```bash
docker-compose up -d --build
```

This starts:
- **PostgreSQL 16** database with persistent storage
- **Honeypot v2** application on port 8000

### 3. Access
- Dashboard: `http://your-server:8000/dashboard/`
- API: `http://your-server:8000/api/admin/stats`

---

## 🧪 Testing

### Run Tests
```powershell
python tests/test_honeypot.py
```

### Simulate Attacks (curl commands)

**1. Normal user (low threat)**
```bash
curl -X GET http://localhost:8000/api/users
```

**2. SQL Injection on fake login**
```bash
curl -X POST http://localhost:8000/admin-login -d "username=admin' OR 1=1 --&password=test"
```

**3. Scanner probing PHPMyAdmin**
```bash
curl -X GET http://localhost:8000/phpmyadmin
```

**4. Malicious scanner with XSS payload**
```bash
curl -H "User-Agent: sqlmap/1.5.2" -X GET "http://localhost:8000/?q=<script>alert(1)</script>"
```

**5. Environment file probe**
```bash
curl -X GET http://localhost:8000/.env
```

**6. Directory traversal attempt**
```bash
curl -X GET "http://localhost:8000/download?file=../../etc/passwd"
```

**7. RCE attempt**
```bash
curl -X POST http://localhost:8000/api/exec -d "cmd=; cat /etc/passwd"
```

**8. Brute force login**
```bash
for i in $(seq 1 5); do curl -X POST http://localhost:8000/admin-login -d "username=admin&password=pass$i"; done
```

After running these, check the dashboard to see:
- Attack classifications in the **Attacks** tab
- MITRE ATT&CK mappings in the **MITRE** tab
- Session replay in the **Replay** tab
- Honeytokens in the **Tokens** tab

---

## 📊 Dashboard Pages

| Tab | Description |
|-----|-------------|
| **📊 Overview** | Stats cards, attack distribution chart, recent activity log |
| **👁️ Sessions** | Live/historical attacker sessions with session details |
| **🕐 Replay** | Session timeline replay showing the full attacker journey |
| **⚔️ Attacks** | Attack classification analytics with pie chart |
| **🗺️ MITRE** | MITRE ATT&CK technique grid with confidence bars |
| **🚫 Blocked** | Blocked IP management with unblock controls |
| **🍯 Tokens** | Honeytoken status — dormant vs triggered tokens |
| **📤 Export** | Download JSON/CSV/STIX 2.1 exports + alert history |

---

## 🔌 Optional Integrations

### Cloudflare Auto-Blocking
Set in `.env`:
```
CLOUDFLARE_API_TOKEN=your_token_here
CLOUDFLARE_ZONE_ID=your_zone_id
```
IPs exceeding the threat threshold will be automatically blocked via Cloudflare firewall rules.

### Telegram Alerts
```
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

### Email Alerts
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your_app_password
ALERT_EMAIL_TO=soc-team@company.com
```

### Discord Alerts
```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## 🔒 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/stats` | Dashboard statistics |
| GET | `/api/admin/logs` | Recent request logs |
| GET | `/api/admin/blocked` | Blocked IPs |
| POST | `/api/admin/block` | Block an IP |
| POST | `/api/admin/unblock` | Unblock an IP |
| GET | `/api/admin/sessions` | All sessions |
| GET | `/api/admin/sessions/active` | Active sessions |
| GET | `/api/admin/sessions/{id}/timeline` | Session replay |
| GET | `/api/admin/fingerprints` | Attacker fingerprints |
| GET | `/api/admin/mitre` | MITRE ATT&CK summary |
| GET | `/api/admin/honeytokens` | Honeytoken status |
| GET | `/api/admin/attack-types` | Attack classification stats |
| GET | `/api/admin/export/{json\|csv\|stix}` | Export intelligence |
| GET | `/api/admin/incident/{session_id}` | Incident report (Markdown) |
| GET | `/api/admin/alerts` | Alert history |
| POST | `/api/admin/retrain` | Retrain anomaly model |
| POST | `/api/admin/retrain-classifier` | Retrain attack classifier |

---

## ⚠️ Security Warnings

1. **Payload Handling**: The honeypot intentionally accepts malicious payloads. They are sanitized before display using HTML escaping to prevent stored XSS.
2. **Dashboard Access**: The `/dashboard` route should be protected by firewall rules in production. Only allow access from trusted IPs/VPN.
3. **No Offensive Use**: This tool is strictly defensive — it logs, detects, and classifies. It never executes attacks.
4. **No Real Credentials**: All tokens and keys are fake honeytokens. No real secrets are stored or exposed.
5. **Database Security**: For production, use PostgreSQL with strong credentials. The default SQLite is for development only.

---

## 📋 Attack Categories

| Category | Detection Method |
|----------|-----------------|
| SQL Injection | Pattern matching (UNION, OR 1=1, etc.) + ML |
| XSS | Script tags, event handlers, JS URIs + ML |
| Brute Force | Repeated POST to login endpoints |
| Directory Traversal | `../` patterns, config file probes |
| RCE Attempt | Command chaining, backticks, eval() |
| Bot Scanner | Known scanner user agents (sqlmap, nmap, etc.) |
| Credential Stuffing | Automated login with leaked credential patterns |

---

## 🗺️ MITRE ATT&CK Coverage

| Attack | Tactic | Technique |
|--------|--------|-----------|
| SQL Injection | Initial Access | T1190 — Exploit Public-Facing Application |
| XSS | Initial Access | T1189 — Drive-by Compromise |
| Brute Force | Credential Access | T1110 — Brute Force |
| Credential Stuffing | Credential Access | T1110.004 — Credential Stuffing |
| Directory Traversal | Discovery | T1083 — File and Directory Discovery |
| RCE | Execution | T1059 — Command and Scripting Interpreter |
| Bot Scanner | Reconnaissance | T1595 — Active Scanning |
| Honeytoken Theft | Collection | T1528 — Steal Application Access Token |

---

*Built as a SOC-grade defensive honeypot platform. For educational and authorized security research purposes only.*

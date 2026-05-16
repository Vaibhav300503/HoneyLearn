# 🧠 HoneyLearn — The AI Honeypot That Learns From YOUR Attacks

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?style=for-the-badge&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-LIVE-brightgreen?style=for-the-badge)

**An adaptive, AI-powered honeypot that gets smarter with every attack it receives.**

[🎯 Attack It Now](#-try-to-hack-me) · [🧠 How It Learns](#-how-honeylearn-learns) · [📖 Setup Guide](#-quick-start) · [📊 Features](#-features)

</div>

---

## 💡 What is HoneyLearn?

Most honeypots are **static** — they detect known attacks using fixed rules. HoneyLearn is different.

**HoneyLearn is an adaptive honeypot that learns from every real attack it receives.** It starts with a synthetic-trained ML classifier, but as real attackers probe it, the AI ingests their payloads, discovers new attack patterns, and periodically retrains itself to become a better detector.

```
Real Attack → AI Classifies → Buffer Samples → Auto-Retrain → Smarter AI
     ↑                                                              ↓
     └──────────────── Better Detection Next Time ←─────────────────┘
```

## 🎯 Try to Hack Me!

**I'm inviting my network to attack this honeypot.** The more creative your attacks, the smarter the AI becomes.

> 📡 **Live Target:** `https://honeylearn.onrender.com`  
> 📖 **Attack Guide:** See [CONTRIBUTING.md](CONTRIBUTING.md) for copy-paste curl commands

**What to try:**
- 💉 SQL Injection (`' OR 1=1 --`)
- ⚡ Cross-Site Scripting (`<script>alert(1)</script>`)
- 💀 Remote Code Execution (`; cat /etc/passwd`)
- 🔨 Brute Force (try common passwords on `/admin-login`)
- 📁 Directory Traversal (`../../etc/passwd`)
- 🤖 Bot Scanning (use scanner user-agents)
- 🔑 Credential Stuffing (try leaked-looking credentials)

Every attack you send is **classified**, **fingerprinted**, and **fed into the learning pipeline**.

---

## 🧠 How HoneyLearn Learns

### The Adaptive Learning Loop

```
┌──────────────────────────────────────────────────────────┐
│                   HONEYLEARN PIPELINE                     │
│                                                           │
│  Request → IP Check → Fingerprint → Session Track         │
│                                          ↓                │
│                              AI Classify + Anomaly Score   │
│                                          ↓                │
│                              MITRE Map → Alert → Block     │
│                                          ↓                │
│                     ┌─── Ingest Sample ───┐               │
│                     │   Learning Buffer   │               │
│                     │  (real attack data)  │               │
│                     └────────┬────────────┘               │
│                              ↓                            │
│                    Buffer Full (50+ samples)?             │
│                         YES ↓                             │
│                  ┌── Hybrid Retrain ──┐                   │
│                  │ Synthetic + Real   │                   │
│                  │ → New Model vN+1   │                   │
│                  └───────┬────────────┘                   │
│                          ↓                                │
│                  Classifier Reloaded!                      │
│                  Accuracy Tracked ↗                        │
└──────────────────────────────────────────────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Sample Ingestion** | Every classified request is buffered as a real-world training sample |
| **Hybrid Training** | Retraining mixes synthetic data + real attacks (3x weighted) for robust models |
| **Model Versioning** | Each retrain produces a new model version with tracked accuracy |
| **Pattern Discovery** | Novel attack signatures are detected and logged in real-time |
| **Learning Dashboard** | 🧠 tab shows accuracy trends, retrain events, and discovered patterns |

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🧠 Adaptive ML** | Learns from real attacks — classifier improves over time |
| **🎯 7 Attack Categories** | SQLi, XSS, RCE, Brute Force, Dir Traversal, Bot Scanner, Credential Stuffing |
| **👤 Attacker Fingerprinting** | Unique ID per visitor (IP + UA + header hash) |
| **🕐 Session Replay** | Full attacker journey with timestamps and payloads |
| **🗺️ MITRE ATT&CK** | Auto-maps to MITRE techniques (T1190, T1110, T1059, etc.) |
| **🍯 Honeytokens** | Fake API keys/JWTs that trigger alerts when reused |
| **🚫 Auto-Blocking** | IPs exceeding threat threshold are auto-blocked |
| **📤 Threat Intel Export** | JSON, CSV, STIX 2.1 formats |
| **🔔 Alerting** | Telegram, Email, Discord integrations |
| **📊 SOC Dashboard** | Premium warm-palette dashboard (hidden, token-protected) |

---

## 🚀 Quick Start

### Local Development

```bash
# Clone the repo
git clone https://github.com/vaibhav300503/HoneyLearn.git
cd HoneyLearn

# Create virtual environment
python -m venv venv
source venv/bin/activate    # Linux/Mac
.\venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run the honeypot
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On first startup, the AI models auto-train on synthetic data.

### Access Dashboard (Token-Protected)

```
http://127.0.0.1:8000/dashboard/?token=honeylearn-local-dev-2026
```

### Test with Attack Simulator

```bash
python tests/attack_simulator.py --scenario all
```

---

## 🌐 Deploy to Render (Free)

1. Fork this repo
2. Go to [render.com](https://render.com) → Sign up with GitHub
3. New → **Web Service** → Connect your fork
4. Settings:
   - **Build:** `pip install -r requirements.txt`
   - **Start:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add env var: `ADMIN_SECRET_TOKEN` = (your secret)
6. Deploy!

Your dashboard: `https://your-app.onrender.com/dashboard/?token=YOUR_SECRET`

---

## 📂 Project Structure

```
HoneyLearn/
├── app/
│   ├── main.py                 # FastAPI app with auth + learning pipeline
│   ├── config.py               # Environment configuration
│   ├── database.py             # SQLAlchemy engine
│   ├── models.py               # 12 DB tables (incl. learning tables)
│   ├── ml/
│   │   ├── adaptive_learner.py # 🧠 Adaptive Learning Engine (NEW)
│   │   ├── attack_classifier.py# TF-IDF + LinearSVC classifier
│   │   ├── classifier_train.py # Synthetic + hybrid training
│   │   ├── anomaly_detector.py # IsolationForest scoring
│   │   └── feature_extractor.py# Pattern detection heuristics
│   └── static/
│       ├── index.html          # 9-tab SPA dashboard (incl. Learning tab)
│       ├── styles.css           # Warm premium design system
│       └── app.js              # Dashboard logic + learning UI
├── tests/
│   └── attack_simulator.py     # Built-in attack simulation tool
├── render.yaml                 # Render deployment blueprint
├── CONTRIBUTING.md             # 🎯 Attack guide for challengers
└── SECURITY.md                 # Security policy
```

---

## 🗺️ MITRE ATT&CK Coverage

| Attack | Technique |
|--------|-----------|
| SQL Injection | T1190 — Exploit Public-Facing Application |
| XSS | T1189 — Drive-by Compromise |
| Brute Force | T1110 — Brute Force |
| Credential Stuffing | T1110.004 — Credential Stuffing |
| Directory Traversal | T1083 — File and Directory Discovery |
| RCE | T1059 — Command and Scripting Interpreter |
| Bot Scanner | T1595 — Active Scanning |
| Honeytoken Theft | T1528 — Steal Application Access Token |

---

## ⚖️ License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
<strong>Built by <a href="https://github.com/vaibhav300503">Vaibhav</a> | 🧠 The AI that learns from YOUR attacks</strong>
</div>

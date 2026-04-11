# Defensive Web Honeypot & AI Anomaly Detection System

This is a complete, standalone Python FastAPI application that acts as a honeypot, tracking suspicious behaviors and utilizing an AI module (Scikit-Learn Isolation Forest) to dynamically score and defend against malicious traffic.

## Features Included
1. **Fake Endpoints (Honeypot)**: Catches scanners on `/wp-admin`, `.env`, `/phpmyadmin`, etc.
2. **Behavioral AI Tracker**: `IsolationForest` model dynamically scores requests based on path, headers, payloads, and request signatures.
3. **Database Integration**: SQLite tracking logs and blocked IPs. Can easily be switched to PostgreSQL.
4. **Active Blocking**: Dynamically drops requests turning them to `403 Forbidden` if threat score > 85.
5. **Dashboard**: A premium, aesthetically modern TailwindCSS dashboard served at `/dashboard`.

---

## 🚀 Step-by-Step Deployment (No Docker Required)

### 1. Prerequisites
Ensure you have **Python 3.9+** installed on your windows machine.

### 2. Setup Virtual Environment
Open your PowerShell/Terminal in this project folder:
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Run the Server
Start the Uvicorn FastAPI server locally:
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
*Note: The SQLite database (`honeypot.db`) will be created automatically in the root folder on the first run.*

---

## 📊 Access Dashboard & Honeypots

1. **The Admin Dashboard**: Open your browser to [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/).
2. **Fake Admin Form**: Open [http://localhost:8000/admin-login](http://localhost:8000/admin-login)

---

## 🛑 Test Attacker Scenarios (Run in a separate terminal)

Try running these `curl` commands to simulate attackers and watch the Dashboard update in real-time.

**1. Simulating a normal user browsing the API (Low Threat)**
```bash
curl -X GET http://localhost:8000/api/users
```

**2. Attack 1: Classic SQL Injection attempt on a Fake Login**
```bash
curl -X POST http://localhost:8000/admin-login -d "username=admin' OR 1=1 --&password=test"
```

**3. Attack 2: Scanner looking for PHPMyAdmin (Suspicious Path)**
```bash
curl -X GET http://localhost:8000/phpmyadmin
```

**4. Attack 3: LFI / Payload Dropper using automated tools (Nmap/Curl UA)**
```bash
# Using a malicious user-agent with an XSS attempt
curl -H "User-Agent: sqlmap/1.5.2#dev (http://sqlmap.org)" -X GET "http://localhost:8000/?q=<script>alert(1)</script>"
```

**5. Attack 4: Scanner looking for Environment Variables**
```bash
curl -X GET http://localhost:8000/.env
```

---

## ⚠️ Security Warnings

1. **Payload Handling**: This honeypot accepts **malicious payloads** intentionally to log them. The payloads are **sanitized** in the Admin dashboard using `escapeHTML()` to prevent stored XSS targeting the admin. 
2. **Do Not Evaluate**: Never use `eval()` or pass the captured payloads into an SQL execution block other than the raw parameterized logging via SQLAlchemy. The provided code handles it safely.
3. **Database Switch**: Currently it uses an embedded SQLite database. For high load, set the `DATABASE_URL` environment variable properly in `app/database.py` with PostgreSQL `postgresql://user:pass@host/db`.
4. **Dashboard Security**: Ensure that the `/dashboard` route is protected by a secure firewall rule in production, or move the `is_whitelisted` logic in `app/blocking.py` to only allow specific VPN IPs to access `/dashboard`. By default it expects local access (`127.0.0.1`).

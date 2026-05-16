# Security Policy

## ⚠️ This is an Intentional Honeypot

HoneyLearn is a **deliberately vulnerable application** designed to attract and analyze attack traffic. It is deployed as a cybersecurity research tool.

**Attacking the live HoneyLearn instance is expected and encouraged** — see [CONTRIBUTING.md](CONTRIBUTING.md) for instructions.

## Reporting Actual Bugs

If you discover a security vulnerability in the HoneyLearn **codebase itself** (not in the intentional trap endpoints), please report it responsibly:

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email: vaibhav300503@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact

## Scope

| In Scope | Out of Scope |
|----------|-------------|
| Bugs in the learning engine | Attacking the intentional trap endpoints |
| Auth bypass on the admin dashboard | SQL injection on honeypot routes |
| Data leakage of admin credentials | XSS on fake login pages |
| Server-side code execution (real) | Directory traversal on trap paths |

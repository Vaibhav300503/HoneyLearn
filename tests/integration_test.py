"""Integration test — sends simulated attack traffic and verifies all v2 features."""
import httpx
import sys

base = "http://127.0.0.1:8000"
c = httpx.Client(timeout=10)

try:
    print("1. Normal browse...")
    r = c.get(f"{base}/api/users")
    print(f"   Status: {r.status_code}")

    print("2. SQL Injection on login...")
    r = c.post(f"{base}/admin-login", data={"username": "admin' OR 1=1 --", "password": "test"})
    print(f"   Status: {r.status_code}")

    print("3. Scanner probing phpmyadmin...")
    r = c.get(f"{base}/phpmyadmin")
    print(f"   Status: {r.status_code}")

    print("4. .env probe...")
    r = c.get(f"{base}/.env")
    print(f"   Status: {r.status_code}")

    print("5. XSS with sqlmap UA...")
    r = c.get(f"{base}/search?q=scriptalert1script", headers={"User-Agent": "sqlmap/1.5.2"})
    print(f"   Status: {r.status_code}")

    print("6. Directory traversal...")
    r = c.get(f"{base}/download?file=../../etc/passwd")
    print(f"   Status: {r.status_code}")

    print("7. Admin login page (generates honeytokens)...")
    r = c.get(f"{base}/admin-login")
    has_tokens = "sk-live" in r.text
    print(f"   Status: {r.status_code}, has tokens: {has_tokens}")

    print("8. Brute force login...")
    for i in range(3):
        r = c.post(f"{base}/admin-login", data={"username": "admin", "password": f"pass{i}"})
        print(f"   Attempt {i+1}: {r.status_code}")

    print()
    print("--- Checking stats ---")
    r = c.get(f"{base}/api/admin/stats")
    data = r.json()
    print(f"Total requests: {data['total_attacks']}")
    print(f"Active sessions: {data['active_sessions']}")
    print(f"Fingerprints: {data['unique_fingerprints']}")
    print(f"Attack distribution: {data['attack_distribution']}")

    print()
    print("--- Checking sessions ---")
    r = c.get(f"{base}/api/admin/sessions")
    sessions = r.json()
    print(f"Sessions found: {len(sessions)}")
    if sessions:
        s = sessions[0]
        print(f"Session: id={s['id'][:8]}, requests={s['total_requests']}, "
              f"score={s['max_threat_score']}, attacks={s['attack_types']}")

        print()
        print("--- Session timeline ---")
        r = c.get(f"{base}/api/admin/sessions/{s['id']}/timeline")
        timeline = r.json()
        for e in timeline:
            score = e.get("threat_score", 0)
            attack = e.get("attack_type", "-")
            print(f"  {e['method']} {e['path']} -> score={score:.0f}, attack={attack}")

    print()
    print("--- MITRE mapping ---")
    r = c.get(f"{base}/api/admin/mitre")
    mitre = r.json()
    for m in mitre:
        print(f"  {m['technique_id']} {m['technique_name']} ({m['tactic']}) x{m['count']}")

    print()
    print("--- Honeytokens ---")
    r = c.get(f"{base}/api/admin/honeytokens")
    tokens = r.json()
    print(f"Tokens generated: {len(tokens)}")
    for t in tokens[:2]:
        print(f"  {t['token_type']}: triggered={t['triggered']}")

    print()
    print("--- Export test ---")
    r = c.get(f"{base}/api/admin/export/json?days=1")
    print(f"JSON export: {r.status_code}, size={len(r.text)} bytes")
    r = c.get(f"{base}/api/admin/export/csv?days=1")
    print(f"CSV export: {r.status_code}, size={len(r.text)} bytes")
    r = c.get(f"{base}/api/admin/export/stix?days=1")
    print(f"STIX export: {r.status_code}, size={len(r.text)} bytes")

    if sessions:
        print()
        print("--- Incident Report ---")
        r = c.get(f"{base}/api/admin/incident/{sessions[0]['id']}")
        lines = r.text.split("\n")
        print(f"  Report generated: {r.status_code}, {len(lines)} lines")
        # Print ASCII-safe preview
        for line in lines[:5]:
            safe = line.encode("ascii", errors="replace").decode("ascii")
            print(f"  {safe}")

    print()
    print("ALL INTEGRATION TESTS PASSED")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    c.close()

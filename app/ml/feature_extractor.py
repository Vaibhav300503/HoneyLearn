"""
Shared feature extraction module.
Used by both the Isolation Forest anomaly detector and the attack classifier.
"""
import re
from typing import Dict, List, Tuple


# ──────────────────────────────────────────────
# PATTERN DEFINITIONS
# ──────────────────────────────────────────────

SQLI_PATTERNS = [
    (r"(?i)(\bunion\b.*\bselect\b)", "UNION SELECT"),
    (r"(?i)(\bselect\b.*\bfrom\b)", "SELECT FROM"),
    (r"(?i)(\binsert\b.*\binto\b)", "INSERT INTO"),
    (r"(?i)(\bdrop\b.*\btable\b)", "DROP TABLE"),
    (r"(?i)(\bdelete\b.*\bfrom\b)", "DELETE FROM"),
    (r"(?i)('\s*(or|and)\s+[\d'\"]+\s*=\s*[\d'\"]+)", "OR/AND tautology"),
    (r"(?i)(--\s*$|/\*|\*/)", "SQL comment"),
    (r"(?i)(\bwaitfor\b.*\bdelay\b)", "Time-based SQLi"),
    (r"(?i)(\bbenchmark\b\s*\()", "Benchmark SQLi"),
    (r"(?i)(\bsleep\b\s*\()", "Sleep SQLi"),
    (r"(?i)(\bexec\b.*\bxp_)", "xp_ procedure"),
    (r"(?i)(0x[0-9a-f]{8,})", "Hex encoding"),
]

XSS_PATTERNS = [
    (r"(?i)(<\s*script)", "<script> tag"),
    (r"(?i)(javascript\s*:)", "javascript: URI"),
    (r"(?i)(on(error|load|click|mouseover|focus|blur)\s*=)", "Event handler injection"),
    (r"(?i)(<\s*img[^>]+onerror)", "IMG onerror"),
    (r"(?i)(<\s*iframe)", "iframe injection"),
    (r"(?i)(<\s*svg[^>]+onload)", "SVG onload"),
    (r"(?i)(document\.(cookie|location|write))", "DOM manipulation"),
    (r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()", "JS dialog function"),
]

DIR_TRAVERSAL_PATTERNS = [
    (r"(\.\./){2,}", "Directory traversal (../)"),
    (r"(?i)(etc/(passwd|shadow|hosts))", "/etc/ file access"),
    (r"(?i)(proc/self)", "/proc/self access"),
    (r"(?i)(windows/(system32|win\.ini))", "Windows system file"),
    (r"(?i)(\bboot\.ini\b)", "boot.ini access"),
    (r"%2e%2e[/%5c]", "URL-encoded traversal"),
    (r"(?i)(\.env|config\.(php|json|yml|yaml|ini|xml))", "Config file probe"),
]

RCE_PATTERNS = [
    (r"(?i)(;\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)", "Command chaining"),
    (r"(?i)(\|\s*(ls|cat|id|whoami|uname|pwd))", "Pipe command"),
    (r"(?i)(`[^`]+`)", "Backtick command execution"),
    (r"(?i)(\$\([^)]+\))", "Subshell execution"),
    (r"(?i)(eval\s*\(|exec\s*\(|system\s*\(|passthru\s*\()", "Code eval function"),
    (r"(?i)(os\.(system|popen|exec))", "Python os command"),
    (r"(?i)(__import__\s*\()", "Python __import__"),
]

BOT_SCANNER_UAS = [
    "nmap", "sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz",
    "hydra", "masscan", "zmap", "nuclei", "acunetix", "burp",
    "nessus", "openvas", "w3af", "arachni", "skipfish",
    "python-requests", "python-urllib", "wget", "java/",
    "libwww-perl", "lwp-trivial", "go-http-client"
]

BAD_PATHS = [
    "/admin", "/wp-admin", "/wp-login", "/phpmyadmin", "/myadmin",
    "/mysql", "/config", "/.env", "/.git", "/backup", "/db",
    "/shell", "/cmd", "/console", "/debug", "/actuator",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/cgi-bin", "/manager", "/jmx-console", "/web-console",
    "/xmlrpc.php", "/wp-content/uploads", "/wp-includes"
]


# ──────────────────────────────────────────────
# FEATURE EXTRACTION
# ──────────────────────────────────────────────

def detect_patterns(text: str, patterns: List[Tuple[str, str]]) -> List[str]:
    """Find all matching pattern names in text."""
    found = []
    for regex, name in patterns:
        if re.search(regex, text):
            found.append(name)
    return found


def extract_all_patterns(path: str, payload: str, user_agent: str) -> Dict[str, List[str]]:
    """
    Run all pattern detectors against path + payload + UA.
    Returns dict of category → list of matched pattern names.
    """
    combined = f"{path} {payload}"
    return {
        "sqli": detect_patterns(combined, SQLI_PATTERNS),
        "xss": detect_patterns(combined, XSS_PATTERNS),
        "directory_traversal": detect_patterns(combined, DIR_TRAVERSAL_PATTERNS),
        "rce": detect_patterns(combined, RCE_PATTERNS),
        "bot_scanner": [ua for ua in BOT_SCANNER_UAS if ua in user_agent.lower()],
    }


def is_bad_path(path: str) -> bool:
    """Check if the request path targets a known honeypot/sensitive endpoint."""
    path_lower = path.lower()
    return any(bp in path_lower for bp in BAD_PATHS)


def extract_numeric_features(
    path: str, method: str, headers: str, payload: str
) -> List[float]:
    """
    Extract numerical features for the Isolation Forest anomaly detector.
    Backward-compatible with v1 feature vector.
    """
    payload = str(payload or "").lower()
    path = str(path or "").lower()
    headers = str(headers or "").lower()

    bad_path = float(is_bad_path(path))

    sqli_count = float(len(detect_patterns(f"{path} {payload}", SQLI_PATTERNS)))
    xss_lfi_count = float(
        len(detect_patterns(f"{path} {payload}", XSS_PATTERNS))
        + len(detect_patterns(f"{path} {payload}", DIR_TRAVERSAL_PATTERNS))
    )

    payload_length = float(len(payload))

    suspicious_method = 1.0 if method in ["OPTIONS", "PUT", "DELETE", "TRACE"] else 0.0

    bad_ua = float(any(ua in headers for ua in BOT_SCANNER_UAS))

    rce_count = float(len(detect_patterns(f"{path} {payload}", RCE_PATTERNS)))

    return [bad_path, sqli_count, xss_lfi_count, payload_length, suspicious_method, bad_ua, rce_count]

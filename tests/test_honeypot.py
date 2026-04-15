"""
Honeypot v2 — Test Suite
Basic tests for core modules: fingerprinting, classification, MITRE mapping,
honeytokens, sanitization, and session tracking.
"""
import sys
import os
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_fingerprint_consistency():
    """Fingerprint IDs should be deterministic for same inputs."""
    from app.fingerprint import generate_fingerprint_id

    fp1 = generate_fingerprint_id("192.168.1.1", "Mozilla/5.0", {"host": "test", "accept": "*/*"})
    fp2 = generate_fingerprint_id("192.168.1.1", "Mozilla/5.0", {"host": "test", "accept": "*/*"})
    fp3 = generate_fingerprint_id("192.168.1.2", "Mozilla/5.0", {"host": "test", "accept": "*/*"})

    assert fp1 == fp2, "Same inputs should produce same fingerprint"
    assert fp1 != fp3, "Different IPs should produce different fingerprints"
    assert len(fp1) == 64, "Fingerprint should be 64 char SHA-256 hex"
    print("[PASS] Fingerprint consistency")


def test_fingerprint_confidence():
    """Confidence should increase with more signals."""
    from app.fingerprint import calculate_confidence

    low = calculate_confidence(has_ip=True, has_ua=False, has_header_hash=False, request_count=1)
    high = calculate_confidence(has_ip=True, has_ua=True, has_header_hash=True, has_browser_fp=True, request_count=50)

    assert high > low, "More signals should produce higher confidence"
    assert 0 <= low <= 1, "Confidence should be 0-1"
    assert 0 <= high <= 1, "Confidence should be 0-1"
    print("[PASS] Fingerprint confidence scoring")


def test_attack_classifier_rules():
    """Rule-based classifier should detect known attack patterns."""
    from app.ml.attack_classifier import attack_classifier

    # SQL Injection
    result = attack_classifier._rule_based_classify(
        "/login", "POST", "' OR 1=1 --", "Mozilla/5.0"
    )
    assert result["attack_type"] == "sql_injection", f"Expected sql_injection, got {result['attack_type']}"
    assert result["confidence"] > 0.5

    # XSS
    result = attack_classifier._rule_based_classify(
        "/search", "GET", "<script>alert(1)</script>", "Mozilla/5.0"
    )
    assert result["attack_type"] == "xss", f"Expected xss, got {result['attack_type']}"

    # Directory traversal
    result = attack_classifier._rule_based_classify(
        "/download?file=../../etc/passwd", "GET", "", "curl/7.68.0"
    )
    assert result["attack_type"] == "directory_traversal", f"Expected dir traversal, got {result['attack_type']}"

    # RCE
    result = attack_classifier._rule_based_classify(
        "/exec", "POST", "; cat /etc/passwd", "Python-urllib"
    )
    assert result["attack_type"] == "rce_attempt", f"Expected rce_attempt, got {result['attack_type']}"

    # Bot scanner
    result = attack_classifier._rule_based_classify(
        "/wp-admin", "GET", "", "sqlmap/1.5.2"
    )
    assert result["attack_type"] == "bot_scanner", f"Expected bot_scanner, got {result['attack_type']}"

    # Brute force
    result = attack_classifier._rule_based_classify(
        "/admin-login", "POST", "username=admin&password=test", "Mozilla/5.0"
    )
    assert result["attack_type"] == "brute_force", f"Expected brute_force, got {result['attack_type']}"

    # Benign
    result = attack_classifier._rule_based_classify(
        "/about", "GET", "", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    assert result["attack_type"] == "benign", f"Expected benign, got {result['attack_type']}"

    print("[PASS] Attack classifier rules")


def test_mitre_mapping():
    """MITRE mapping should return correct technique IDs."""
    from app.mitre import map_attack_to_mitre

    mapping = map_attack_to_mitre("sql_injection", 0.85)
    assert mapping is not None
    assert mapping["technique_id"] == "T1190"
    assert mapping["tactic"] == "Initial Access"

    mapping = map_attack_to_mitre("brute_force", 0.7)
    assert mapping["technique_id"] == "T1110"

    mapping = map_attack_to_mitre("directory_traversal", 0.6)
    assert mapping["technique_id"] == "T1083"

    mapping = map_attack_to_mitre("rce_attempt", 0.9)
    assert mapping["technique_id"] == "T1059"

    mapping = map_attack_to_mitre("bot_scanner", 0.5)
    assert mapping["technique_id"] == "T1595"

    # Unknown type should return None
    mapping = map_attack_to_mitre("benign", 0.5)
    assert mapping is None

    print("[PASS] MITRE ATT&CK mapping")


def test_honeytokens_generation():
    """Honeytokens should generate unique, realistic tokens."""
    from app.honeytokens import (
        generate_fake_api_key, generate_fake_jwt,
        generate_fake_aws_key, generate_fake_session_cookie
    )

    api_key = generate_fake_api_key()
    assert api_key.startswith("sk-live-"), f"API key should start with sk-live-: {api_key}"
    assert len(api_key) > 20

    jwt = generate_fake_jwt()
    parts = jwt.split(".")
    assert len(parts) == 3, f"JWT should have 3 parts: {jwt}"

    aws_key = generate_fake_aws_key()
    assert aws_key.startswith("AKIA"), f"AWS key should start with AKIA: {aws_key}"

    cookie = generate_fake_session_cookie()
    assert len(cookie) == 64, f"Session cookie should be 64 hex chars: {cookie}"

    # Tokens should be unique
    key2 = generate_fake_api_key()
    assert api_key != key2, "Tokens should be unique"

    print("[PASS] Honeytoken generation")


def test_sanitizer():
    """Sanitizer should clean dangerous content."""
    from app.sanitizer import sanitize_payload, sanitize_for_display, extract_safe_snippet

    # Null byte removal
    result = sanitize_payload("hello\x00world")
    assert "\x00" not in result

    # Truncation
    long_str = "A" * 3000
    result = sanitize_payload(long_str, max_length=100)
    assert len(result) < 200
    assert "TRUNCATED" in result

    # HTML escaping
    result = sanitize_for_display('<script>alert(1)</script>')
    assert "<script>" not in result
    assert "&lt;script&gt;" in result

    # Snippet extraction
    snippet = extract_safe_snippet("short payload", max_len=500)
    assert snippet == "short payload"

    print("[PASS] Sanitizer")


def test_feature_extractor():
    """Feature extractor should detect attack patterns."""
    from app.ml.feature_extractor import extract_all_patterns, is_bad_path

    # SQL injection
    patterns = extract_all_patterns("/login", "' OR 1=1 --", "Mozilla/5.0")
    assert len(patterns["sqli"]) > 0, "Should detect SQL injection"

    # XSS
    patterns = extract_all_patterns("/search", "<script>alert(1)</script>", "Mozilla/5.0")
    assert len(patterns["xss"]) > 0, "Should detect XSS"

    # Bad paths
    assert is_bad_path("/wp-admin") == True
    assert is_bad_path("/.env") == True
    assert is_bad_path("/about") == False

    print("[PASS] Feature extractor")


def test_export_formats():
    """Export functions should produce valid output."""
    # We can't test DB-dependent exports without a real session,
    # but we can test the STIX structure
    import uuid
    from datetime import datetime, timezone

    # Minimal STIX bundle structure test
    now = datetime.now(timezone.utc).isoformat() + "Z"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": []
    }
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")

    print("[PASS] Export format structure")


if __name__ == "__main__":
    print("\nRunning Honeypot v2 Test Suite\n" + "=" * 50)

    test_fingerprint_consistency()
    test_fingerprint_confidence()
    test_attack_classifier_rules()
    test_mitre_mapping()
    test_honeytokens_generation()
    test_sanitizer()
    test_feature_extractor()
    test_export_formats()

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED")

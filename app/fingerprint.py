"""
Attacker Fingerprinting Engine.
Generates unique fingerprint IDs based on IP, User-Agent, header patterns,
and optional browser-side signals. Even if IP changes, header + UA patterns
can still help identify repeat attackers.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy.orm import Session
from .models import AttackerFingerprint


def _normalize_ua(ua: str) -> str:
    """Normalize user agent for consistent hashing."""
    return (ua or "").strip().lower()


def _hash_header_keys(headers: Dict[str, str]) -> str:
    """
    Create a stable hash from the set of header keys.
    Attackers/scanners often have distinctive header key combinations.
    """
    # Sort keys, lowercase, ignore common varying ones
    skip_keys = {"host", "content-length", "content-type", "cookie", "accept-encoding"}
    keys = sorted(k.lower() for k in headers.keys() if k.lower() not in skip_keys)
    return hashlib.sha256("|".join(keys).encode()).hexdigest()[:16]


def generate_fingerprint_id(
    ip: str,
    user_agent: str,
    headers_dict: Dict[str, str]
) -> str:
    """
    Generate a deterministic fingerprint ID from request properties.
    Returns a 64-char hex SHA-256 hash.
    """
    ua_norm = _normalize_ua(user_agent)
    header_hash = _hash_header_keys(headers_dict)
    raw = f"{ip}|{ua_norm}|{header_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def calculate_confidence(
    has_ip: bool = True,
    has_ua: bool = True,
    has_header_hash: bool = True,
    has_browser_fp: bool = False,
    request_count: int = 1
) -> float:
    """
    Calculate fingerprint confidence score (0.0 - 1.0).
    More signals + more requests = higher confidence.
    """
    score = 0.0
    if has_ip:
        score += 0.25
    if has_ua:
        score += 0.2
    if has_header_hash:
        score += 0.15
    if has_browser_fp:
        score += 0.25
    # Repeated observations increase confidence
    if request_count > 5:
        score += 0.1
    if request_count > 20:
        score += 0.05
    return min(score, 1.0)


def calculate_threat_level(
    total_requests: int,
    max_threat_score: float,
    honeytoken_triggered: bool = False
) -> str:
    """Determine threat level from accumulated behavior."""
    if honeytoken_triggered:
        return "CRITICAL"
    if max_threat_score > 85 or total_requests > 100:
        return "HIGH"
    if max_threat_score > 60 or total_requests > 30:
        return "MEDIUM"
    return "LOW"


def upsert_fingerprint(
    db: Session,
    ip: str,
    user_agent: str,
    headers_dict: Dict[str, str],
    browser_fp: Optional[str] = None,
    threat_score: float = 0.0
) -> Tuple[str, AttackerFingerprint]:
    """
    Create or update an attacker fingerprint record.
    Returns (fingerprint_id, fingerprint_record).
    """
    fp_id = generate_fingerprint_id(ip, user_agent, headers_dict)
    header_hash = _hash_header_keys(headers_dict)

    existing = db.query(AttackerFingerprint).filter(
        AttackerFingerprint.id == fp_id
    ).first()

    if existing:
        # Update existing fingerprint
        existing.total_requests += 1
        existing.last_seen = datetime.now(timezone.utc)
        if browser_fp and not existing.browser_fingerprint:
            existing.browser_fingerprint = browser_fp

        existing.confidence_score = calculate_confidence(
            has_ip=True,
            has_ua=bool(user_agent),
            has_header_hash=True,
            has_browser_fp=bool(existing.browser_fingerprint),
            request_count=existing.total_requests
        )

        # Upgrade threat level if warranted
        new_level = calculate_threat_level(
            existing.total_requests,
            max(threat_score, 0)
        )
        level_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if level_order.get(new_level, 0) > level_order.get(existing.threat_level, 0):
            existing.threat_level = new_level

        db.flush()
        return fp_id, existing

    else:
        # Create new fingerprint
        confidence = calculate_confidence(
            has_ip=True,
            has_ua=bool(user_agent),
            has_header_hash=True,
            has_browser_fp=bool(browser_fp),
            request_count=1
        )

        new_fp = AttackerFingerprint(
            id=fp_id,
            ip_address=ip,
            user_agent=user_agent or "",
            header_hash=header_hash,
            browser_fingerprint=browser_fp,
            confidence_score=confidence,
            threat_level=calculate_threat_level(1, threat_score),
            total_requests=1
        )
        db.add(new_fp)
        db.flush()
        return fp_id, new_fp

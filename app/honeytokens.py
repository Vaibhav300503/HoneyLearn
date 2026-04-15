"""
Honeytoken Generator & Validator.
Creates fake credentials/tokens embedded in honeypot pages.
If an attacker reuses these tokens, they are instantly flagged HIGH RISK.
"""
import secrets
import base64
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from sqlalchemy.orm import Session as DBSession

from .models import Honeytoken, AttackerFingerprint


# ──────────────────────────────────────────────
# TOKEN GENERATORS
# ──────────────────────────────────────────────

def generate_fake_api_key() -> str:
    """Generate a realistic-looking API key (e.g., sk-live-xxxx)."""
    token = secrets.token_hex(24)
    return f"sk-live-{token}"


def generate_fake_jwt() -> str:
    """Generate a valid-looking JWT with fake admin claims."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": "admin",
            "admin": True,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 86400,
            "role": "superadmin"
        }).encode()
    ).rstrip(b"=").decode()

    # Fake signature (not a real HMAC — this is a trap token)
    sig = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).rstrip(b"=").decode()

    return f"{header}.{payload}.{sig}"


def generate_fake_aws_key() -> str:
    """Generate a realistic-looking AWS Access Key ID."""
    # AWS keys start with AKIA followed by 16 uppercase alphanumeric chars
    suffix = secrets.token_hex(8).upper()
    return f"AKIA{suffix}"


def generate_fake_aws_secret() -> str:
    """Generate a realistic-looking AWS Secret Access Key."""
    return secrets.token_urlsafe(30)


def generate_fake_session_cookie() -> str:
    """Generate a realistic-looking session cookie value."""
    return secrets.token_hex(32)


# ──────────────────────────────────────────────
# TOKEN MANAGEMENT
# ──────────────────────────────────────────────

def create_honeytoken(
    db: DBSession,
    token_type: str,
    session_id: Optional[str] = None,
    fingerprint_id: Optional[str] = None
) -> Honeytoken:
    """
    Create and store a new honeytoken of the specified type.
    """
    generators = {
        "api_key": generate_fake_api_key,
        "jwt": generate_fake_jwt,
        "aws_key": generate_fake_aws_key,
        "session_cookie": generate_fake_session_cookie,
    }

    gen_func = generators.get(token_type, generate_fake_api_key)
    token_value = gen_func()

    record = Honeytoken(
        token_type=token_type,
        token_value=token_value,
        session_id=session_id,
        fingerprint_id=fingerprint_id,
        triggered=False
    )
    db.add(record)
    db.flush()
    return record


def create_token_set(
    db: DBSession,
    session_id: Optional[str] = None,
    fingerprint_id: Optional[str] = None
) -> Dict[str, str]:
    """
    Create a complete set of honeytokens for embedding in a response.
    Returns dict of token_type → token_value.
    """
    tokens = {}
    for token_type in ["api_key", "jwt", "aws_key", "session_cookie"]:
        record = create_honeytoken(db, token_type, session_id, fingerprint_id)
        tokens[token_type] = record.token_value
    return tokens


def check_for_honeytoken(db: DBSession, request_text: str) -> Optional[Honeytoken]:
    """
    Check if any part of the request contains a known honeytoken.
    Scans the full request text (path + headers + payload).
    Returns the matched Honeytoken record, or None.
    """
    if not request_text:
        return None

    # Get all active (non-triggered) tokens
    tokens = db.query(Honeytoken).filter(
        Honeytoken.triggered == False
    ).all()

    for token in tokens:
        if token.token_value in request_text:
            return token

    # Also check already-triggered tokens (repeat offender)
    triggered_tokens = db.query(Honeytoken).filter(
        Honeytoken.triggered == True
    ).all()

    for token in triggered_tokens:
        if token.token_value in request_text:
            return token

    return None


def trigger_honeytoken(
    db: DBSession,
    token: Honeytoken,
    triggered_by_ip: str,
    triggered_by_fingerprint: Optional[str] = None
) -> None:
    """
    Mark a honeytoken as triggered and record who triggered it.
    """
    token.triggered = True
    token.triggered_at = datetime.now(timezone.utc)
    token.triggered_by_ip = triggered_by_ip
    token.triggered_by_fingerprint = triggered_by_fingerprint

    # If we know the fingerprint, escalate to CRITICAL
    if triggered_by_fingerprint:
        fp = db.query(AttackerFingerprint).filter(
            AttackerFingerprint.id == triggered_by_fingerprint
        ).first()
        if fp:
            fp.threat_level = "CRITICAL"

    db.flush()


def get_all_honeytokens(db: DBSession, limit: int = 100) -> List[Dict[str, Any]]:
    """Get all honeytokens with their status."""
    tokens = db.query(Honeytoken).order_by(Honeytoken.created_at.desc()).limit(limit).all()
    return [
        {
            "id": t.id,
            "token_type": t.token_type,
            "token_value": t.token_value[:20] + "..." if len(t.token_value) > 20 else t.token_value,
            "session_id": t.session_id,
            "fingerprint_id": t.fingerprint_id,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "triggered": t.triggered,
            "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
            "triggered_by_ip": t.triggered_by_ip,
        }
        for t in tokens
    ]

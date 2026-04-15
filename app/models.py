"""
Database models for Honeypot v2.
Includes all tables for fingerprinting, sessions, attack classification,
MITRE mapping, honeytokens, alerting, and blocking.
"""
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .database import Base


# ──────────────────────────────────────────────
# ORIGINAL V1 TABLES (Enhanced)
# ──────────────────────────────────────────────

class HoneypotLog(Base):
    """Core request log — every incoming request is recorded here."""
    __tablename__ = "honeypot_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    ip_address = Column(String(50), index=True)
    user_agent = Column(Text)
    method = Column(String(10))
    path = Column(String(500), index=True)
    headers = Column(Text)          # JSON string
    payload = Column(Text)          # Sanitized payload
    threat_score = Column(Float, default=0.0)
    anomaly_flag = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)

    # v2 additions
    fingerprint_id = Column(String(64), ForeignKey("attacker_fingerprints.id"), nullable=True, index=True)
    session_id = Column(String(36), ForeignKey("attacker_sessions.id"), nullable=True, index=True)
    attack_type = Column(String(50), nullable=True)
    attack_confidence = Column(Float, nullable=True)
    detected_patterns = Column(Text, nullable=True)   # JSON array of pattern strings
    response_code = Column(Integer, nullable=True)


class BlockedIP(Base):
    """Blocked IP addresses (v1 compatible)."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, index=True)
    reason = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())


# ──────────────────────────────────────────────
# V2: ATTACKER FINGERPRINTING
# ──────────────────────────────────────────────

class AttackerFingerprint(Base):
    """
    Unique attacker fingerprint built from IP, UA, headers, and optional
    browser-side signals. Persists across sessions.
    """
    __tablename__ = "attacker_fingerprints"

    id = Column(String(64), primary_key=True)  # SHA-256 hash
    ip_address = Column(String(50), index=True)
    user_agent = Column(Text)
    header_hash = Column(String(64))           # Hash of sorted header key set
    cookie_behavior = Column(String(20), default="unknown")  # accepts / rejects / none
    browser_fingerprint = Column(Text, nullable=True)         # JSON: canvas, tz, lang, screen
    confidence_score = Column(Float, default=0.5)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    total_requests = Column(Integer, default=1)
    threat_level = Column(String(10), default="LOW")  # LOW / MEDIUM / HIGH / CRITICAL

    sessions = relationship("AttackerSession", backref="fingerprint", lazy="dynamic")


# ──────────────────────────────────────────────
# V2: SESSION TRACKING
# ──────────────────────────────────────────────

class AttackerSession(Base):
    """
    Groups requests from one attacker fingerprint into a timed session.
    A new session starts when there's a >30 min gap in activity.
    """
    __tablename__ = "attacker_sessions"

    id = Column(String(36), primary_key=True)  # UUID
    fingerprint_id = Column(String(64), ForeignKey("attacker_fingerprints.id"), index=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    total_requests = Column(Integer, default=0)
    max_threat_score = Column(Float, default=0.0)
    attack_types = Column(Text, default="[]")         # JSON array of strings
    mitre_techniques = Column(Text, default="[]")     # JSON array of technique IDs
    is_active = Column(Boolean, default=True)

    events = relationship("SessionEvent", backref="session", lazy="dynamic",
                          order_by="SessionEvent.timestamp")


class SessionEvent(Base):
    """
    Individual event in a session timeline.
    Captures the ordered attacker journey through honeypot endpoints.
    """
    __tablename__ = "session_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), ForeignKey("attacker_sessions.id"), index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    method = Column(String(10))
    path = Column(String(500))
    payload_snippet = Column(Text, nullable=True)       # First 500 chars, sanitized
    response_code = Column(Integer, nullable=True)
    threat_score = Column(Float, default=0.0)
    attack_type = Column(String(50), nullable=True)
    time_delta_ms = Column(Integer, default=0)           # Ms since last event in session


# ──────────────────────────────────────────────
# V2: HONEYTOKENS (Trap Tokens)
# ──────────────────────────────────────────────

class Honeytoken(Base):
    """
    Fake credentials/tokens embedded in honeypot responses.
    If reused in a later request, the attacker is flagged HIGH RISK.
    """
    __tablename__ = "honeytokens"

    id = Column(Integer, primary_key=True, index=True)
    token_type = Column(String(30))          # api_key / jwt / aws_key / session_cookie
    token_value = Column(String(500), unique=True, index=True)
    session_id = Column(String(36), ForeignKey("attacker_sessions.id"), nullable=True)
    fingerprint_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    triggered = Column(Boolean, default=False)
    triggered_at = Column(DateTime(timezone=True), nullable=True)
    triggered_by_ip = Column(String(50), nullable=True)
    triggered_by_fingerprint = Column(String(64), nullable=True)


# ──────────────────────────────────────────────
# V2: MITRE ATT&CK MAPPING
# ──────────────────────────────────────────────

class MitreMapping(Base):
    """
    Maps detected attack behaviors to MITRE ATT&CK framework techniques.
    """
    __tablename__ = "mitre_mappings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), ForeignKey("attacker_sessions.id"), nullable=True, index=True)
    log_id = Column(Integer, ForeignKey("honeypot_logs.id"), nullable=True)
    tactic = Column(String(50))              # e.g., "Initial Access"
    technique_id = Column(String(20))        # e.g., "T1190"
    technique_name = Column(String(100))     # e.g., "Exploit Public-Facing Application"
    confidence = Column(Float, default=0.0)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())


# ──────────────────────────────────────────────
# V2: ALERT HISTORY
# ──────────────────────────────────────────────

class AlertLog(Base):
    """Records of all alerts sent via Telegram, Email, or Discord."""
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(20))          # telegram / email / discord
    trigger_reason = Column(String(200))
    fingerprint_id = Column(String(64), nullable=True)
    session_id = Column(String(36), nullable=True)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())
    success = Column(Boolean, default=False)
    details = Column(Text, nullable=True)    # JSON summary


# ──────────────────────────────────────────────
# V2: BLOCKING HISTORY
# ──────────────────────────────────────────────

class BlockEvent(Base):
    """Detailed blocking audit trail with method tracking."""
    __tablename__ = "block_events"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), index=True)
    block_reason = Column(Text)
    block_method = Column(String(20), default="local")  # local / cloudflare / nginx
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    auto_blocked = Column(Boolean, default=True)

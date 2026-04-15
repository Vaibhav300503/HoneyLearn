"""
Session Tracker — Groups requests from the same attacker fingerprint
into timed sessions and records an ordered timeline of events.
"""
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

from .models import AttackerSession, SessionEvent
from .config import settings
from .sanitizer import extract_safe_snippet


def get_or_create_session(
    db: Session,
    fingerprint_id: str
) -> str:
    """
    Find the active session for this fingerprint, or create a new one.
    A session expires after SESSION_TIMEOUT_MINUTES of inactivity.
    Returns the session_id.
    """
    timeout = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
    cutoff = datetime.now(timezone.utc) - timeout

    # Find most recent active session for this fingerprint
    active_session = db.query(AttackerSession).filter(
        AttackerSession.fingerprint_id == fingerprint_id,
        AttackerSession.is_active == True,
        AttackerSession.last_activity >= cutoff
    ).order_by(desc(AttackerSession.last_activity)).first()

    if active_session:
        return active_session.id

    # Deactivate any stale sessions for this fingerprint
    stale = db.query(AttackerSession).filter(
        AttackerSession.fingerprint_id == fingerprint_id,
        AttackerSession.is_active == True,
        AttackerSession.last_activity < cutoff
    ).all()
    for s in stale:
        s.is_active = False

    # Create new session
    session_id = str(uuid.uuid4())
    new_session = AttackerSession(
        id=session_id,
        fingerprint_id=fingerprint_id,
        total_requests=0,
        max_threat_score=0.0,
        attack_types="[]",
        mitre_techniques="[]",
        is_active=True
    )
    db.add(new_session)
    db.flush()
    return session_id


def record_event(
    db: Session,
    session_id: str,
    method: str,
    path: str,
    payload: str,
    response_code: Optional[int],
    threat_score: float,
    attack_type: Optional[str]
) -> SessionEvent:
    """
    Record a single event in the session timeline.
    Calculates time delta from the previous event.
    """
    now = datetime.now(timezone.utc)

    # Get the last event in this session for time delta
    last_event = db.query(SessionEvent).filter(
        SessionEvent.session_id == session_id
    ).order_by(desc(SessionEvent.timestamp)).first()

    time_delta_ms = 0
    if last_event and last_event.timestamp:
        delta = now - last_event.timestamp.replace(tzinfo=timezone.utc) if last_event.timestamp.tzinfo is None else now - last_event.timestamp
        time_delta_ms = int(delta.total_seconds() * 1000)

    event = SessionEvent(
        session_id=session_id,
        timestamp=now,
        method=method,
        path=path,
        payload_snippet=extract_safe_snippet(payload),
        response_code=response_code,
        threat_score=threat_score,
        attack_type=attack_type,
        time_delta_ms=time_delta_ms
    )
    db.add(event)

    # Update session aggregate data
    session = db.query(AttackerSession).filter(
        AttackerSession.id == session_id
    ).first()

    if session:
        session.total_requests += 1
        session.last_activity = now
        if threat_score > session.max_threat_score:
            session.max_threat_score = threat_score

        # Track unique attack types
        if attack_type and attack_type != "benign":
            current_types = json.loads(session.attack_types or "[]")
            if attack_type not in current_types:
                current_types.append(attack_type)
                session.attack_types = json.dumps(current_types)

    db.flush()
    return event


def get_session_timeline(db: Session, session_id: str) -> List[Dict[str, Any]]:
    """Get the ordered timeline of events for a session."""
    events = db.query(SessionEvent).filter(
        SessionEvent.session_id == session_id
    ).order_by(SessionEvent.timestamp).all()

    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "method": e.method,
            "path": e.path,
            "payload_snippet": e.payload_snippet,
            "response_code": e.response_code,
            "threat_score": e.threat_score,
            "attack_type": e.attack_type,
            "time_delta_ms": e.time_delta_ms
        }
        for e in events
    ]


def get_active_sessions(db: Session) -> List[Dict[str, Any]]:
    """Get all currently active sessions."""
    timeout = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
    cutoff = datetime.now(timezone.utc) - timeout

    sessions = db.query(AttackerSession).filter(
        AttackerSession.is_active == True,
        AttackerSession.last_activity >= cutoff
    ).order_by(desc(AttackerSession.last_activity)).all()

    return [
        {
            "id": s.id,
            "fingerprint_id": s.fingerprint_id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "last_activity": s.last_activity.isoformat() if s.last_activity else None,
            "total_requests": s.total_requests,
            "max_threat_score": s.max_threat_score,
            "attack_types": json.loads(s.attack_types or "[]"),
            "mitre_techniques": json.loads(s.mitre_techniques or "[]"),
            "is_active": s.is_active
        }
        for s in sessions
    ]


def get_all_sessions(db: Session, limit: int = 100) -> List[Dict[str, Any]]:
    """Get all sessions ordered by most recent."""
    sessions = db.query(AttackerSession).order_by(
        desc(AttackerSession.last_activity)
    ).limit(limit).all()

    return [
        {
            "id": s.id,
            "fingerprint_id": s.fingerprint_id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "last_activity": s.last_activity.isoformat() if s.last_activity else None,
            "total_requests": s.total_requests,
            "max_threat_score": s.max_threat_score,
            "attack_types": json.loads(s.attack_types or "[]"),
            "mitre_techniques": json.loads(s.mitre_techniques or "[]"),
            "is_active": s.is_active
        }
        for s in sessions
    ]

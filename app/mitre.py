"""
MITRE ATT&CK Mapping Engine.
Maps detected attack types and behaviors to MITRE ATT&CK techniques.
"""
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from .models import MitreMapping, AttackerSession


# ──────────────────────────────────────────────
# MITRE ATT&CK TECHNIQUE DATABASE
# ──────────────────────────────────────────────

MITRE_ATTACK_MAP: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "description": "Adversary attempts SQL injection to exploit web application vulnerabilities."
    },
    "xss": {
        "tactic": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "description": "Cross-site scripting attack to execute malicious code in victim browser."
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "description": "Adversary attempts to gain access by systematically trying passwords."
    },
    "credential_stuffing": {
        "tactic": "Credential Access",
        "technique_id": "T1110.004",
        "technique_name": "Credential Stuffing",
        "description": "Adversary uses stolen credential pairs from breaches to authenticate."
    },
    "directory_traversal": {
        "tactic": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "description": "Adversary attempts to enumerate files/directories on the system."
    },
    "rce_attempt": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "description": "Adversary attempts remote command execution through interpreter abuse."
    },
    "bot_scanner": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "description": "Adversary uses automated scanning tools to probe for vulnerabilities."
    },
    "honeytoken_triggered": {
        "tactic": "Collection",
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "description": "Adversary attempted to use a stolen/captured application token."
    },
}

# Additional behavioral MITRE mappings
BEHAVIORAL_MITRE_MAP = {
    "rapid_requests": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "description": "High-frequency automated scanning behavior detected."
    },
    "config_probe": {
        "tactic": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "description": "Adversary probing for configuration files and system information."
    },
    "web_shell_upload": {
        "tactic": "Persistence",
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "description": "Adversary attempting to upload a web shell for persistent access."
    },
}


def map_attack_to_mitre(attack_type: str, confidence: float = 0.0) -> Optional[Dict[str, Any]]:
    """
    Map a classified attack type to its MITRE ATT&CK technique.
    Returns a dict with tactic, technique_id, technique_name, confidence.
    """
    mapping = MITRE_ATTACK_MAP.get(attack_type)
    if not mapping:
        return None

    return {
        "tactic": mapping["tactic"],
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
        "description": mapping["description"],
        "confidence": confidence
    }


def record_mitre_mapping(
    db: Session,
    session_id: Optional[str],
    log_id: Optional[int],
    attack_type: str,
    confidence: float
) -> Optional[MitreMapping]:
    """
    Record a MITRE ATT&CK mapping in the database and update the session.
    """
    mapping = map_attack_to_mitre(attack_type, confidence)
    if not mapping:
        return None

    record = MitreMapping(
        session_id=session_id,
        log_id=log_id,
        tactic=mapping["tactic"],
        technique_id=mapping["technique_id"],
        technique_name=mapping["technique_name"],
        confidence=confidence,
        detected_at=datetime.now(timezone.utc)
    )
    db.add(record)

    # Update session's mitre_techniques list
    if session_id:
        session = db.query(AttackerSession).filter(
            AttackerSession.id == session_id
        ).first()
        if session:
            current = json.loads(session.mitre_techniques or "[]")
            if mapping["technique_id"] not in current:
                current.append(mapping["technique_id"])
                session.mitre_techniques = json.dumps(current)

    db.flush()
    return record


def get_session_mitre_summary(db: Session, session_id: str) -> List[Dict[str, Any]]:
    """Get all MITRE mappings for a specific session."""
    mappings = db.query(MitreMapping).filter(
        MitreMapping.session_id == session_id
    ).all()

    # Deduplicate by technique_id, keep highest confidence
    seen = {}
    for m in mappings:
        key = m.technique_id
        if key not in seen or m.confidence > seen[key]["confidence"]:
            seen[key] = {
                "tactic": m.tactic,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "confidence": m.confidence,
                "detected_at": m.detected_at.isoformat() if m.detected_at else None,
                "count": 1
            }
        else:
            seen[key]["count"] += 1

    return list(seen.values())


def get_global_mitre_summary(db: Session) -> List[Dict[str, Any]]:
    """Get aggregated MITRE ATT&CK statistics across all sessions."""
    results = db.query(
        MitreMapping.technique_id,
        MitreMapping.technique_name,
        MitreMapping.tactic,
        func.count(MitreMapping.id).label("count"),
        func.avg(MitreMapping.confidence).label("avg_confidence")
    ).group_by(
        MitreMapping.technique_id,
        MitreMapping.technique_name,
        MitreMapping.tactic
    ).order_by(func.count(MitreMapping.id).desc()).all()

    return [
        {
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "count": r.count,
            "avg_confidence": round(float(r.avg_confidence), 3) if r.avg_confidence else 0.0
        }
        for r in results
    ]

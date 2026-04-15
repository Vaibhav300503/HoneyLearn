"""
Threat Intelligence Export Module.
Exports collected intelligence in JSON, CSV, and STIX 2.1 formats.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session as DBSession
from sqlalchemy import desc

from .models import (
    AttackerFingerprint, AttackerSession, HoneypotLog,
    MitreMapping, Honeytoken
)
from .sanitizer import sanitize_for_display


def _gather_intel(db: DBSession, days: int = 7) -> List[Dict[str, Any]]:
    """
    Gather threat intelligence data from the last N days.
    Returns a list of attacker intel records.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    fingerprints = db.query(AttackerFingerprint).filter(
        AttackerFingerprint.last_seen >= cutoff
    ).all()

    intel = []
    for fp in fingerprints:
        sessions = db.query(AttackerSession).filter(
            AttackerSession.fingerprint_id == fp.id
        ).all()

        mitre_techniques = []
        attack_types_all = set()
        max_score = 0.0

        for session in sessions:
            attack_types_all.update(json.loads(session.attack_types or "[]"))
            if session.max_threat_score > max_score:
                max_score = session.max_threat_score

            mappings = db.query(MitreMapping).filter(
                MitreMapping.session_id == session.id
            ).all()
            for m in mappings:
                mitre_techniques.append({
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "confidence": m.confidence
                })

        # Get sample payloads (sanitized)
        sample_logs = db.query(HoneypotLog).filter(
            HoneypotLog.fingerprint_id == fp.id,
            HoneypotLog.anomaly_flag == True
        ).limit(5).all()

        payload_indicators = [
            sanitize_for_display(log.payload[:200]) if log.payload else ""
            for log in sample_logs
        ]

        intel.append({
            "fingerprint_id": fp.id,
            "ip_address": fp.ip_address,
            "user_agent": fp.user_agent,
            "threat_level": fp.threat_level,
            "threat_score": max_score,
            "confidence_score": fp.confidence_score,
            "attack_types": list(attack_types_all),
            "mitre_techniques": mitre_techniques,
            "total_requests": fp.total_requests,
            "first_seen": fp.first_seen.isoformat() if fp.first_seen else None,
            "last_seen": fp.last_seen.isoformat() if fp.last_seen else None,
            "session_count": len(sessions),
            "payload_indicators": payload_indicators
        })

    return intel


def export_json(db: DBSession, days: int = 7) -> str:
    """Export threat intelligence as JSON."""
    intel = _gather_intel(db, days)
    export_data = {
        "export_type": "honeypot_threat_intelligence",
        "version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": days,
        "total_indicators": len(intel),
        "indicators": intel
    }
    return json.dumps(export_data, indent=2)


def export_csv(db: DBSession, days: int = 7) -> str:
    """Export threat intelligence as CSV."""
    intel = _gather_intel(db, days)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "fingerprint_id", "ip_address", "user_agent", "threat_level",
        "threat_score", "confidence_score", "attack_types",
        "mitre_techniques", "total_requests", "first_seen",
        "last_seen", "session_count"
    ])

    for record in intel:
        writer.writerow([
            record["fingerprint_id"],
            record["ip_address"],
            record["user_agent"][:100] if record["user_agent"] else "",
            record["threat_level"],
            record["threat_score"],
            record["confidence_score"],
            "|".join(record["attack_types"]),
            "|".join(t["technique_id"] for t in record["mitre_techniques"]),
            record["total_requests"],
            record["first_seen"],
            record["last_seen"],
            record["session_count"]
        ])

    return output.getvalue()


def export_stix21(db: DBSession, days: int = 7) -> str:
    """
    Export threat intelligence in STIX 2.1 format (basic bundle).
    Creates threat-actor, indicator, attack-pattern, and relationship objects.
    """
    intel = _gather_intel(db, days)
    now = datetime.now(timezone.utc).isoformat() + "Z"

    stix_objects = []

    # Identity for the honeypot (author)
    honeypot_identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'honeypot-v2')}",
        "created": now,
        "modified": now,
        "name": "Honeypot v2 SOC Platform",
        "identity_class": "system"
    }
    stix_objects.append(honeypot_identity)

    for record in intel:
        # Threat Actor per fingerprint
        actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_URL, record['fingerprint_id'])}"
        actor = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": f"Attacker {record['ip_address']}",
            "description": f"Threat level: {record['threat_level']}. "
                          f"Attack types: {', '.join(record['attack_types'])}.",
            "threat_actor_types": ["unknown"],
            "first_seen": record["first_seen"],
            "last_seen": record["last_seen"],
        }
        stix_objects.append(actor)

        # Indicator for IP
        indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, record['ip_address'])}"
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Malicious IP: {record['ip_address']}",
            "description": f"IP observed attacking honeypot. Score: {record['threat_score']}",
            "pattern": f"[ipv4-addr:value = '{record['ip_address']}']",
            "pattern_type": "stix",
            "valid_from": record["first_seen"] or now,
            "indicator_types": ["malicious-activity"]
        }
        stix_objects.append(indicator)

        # Relationship: indicator → threat-actor
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": actor_id
        }
        stix_objects.append(rel)

        # Attack Pattern objects for MITRE techniques
        seen_techniques = set()
        for tech in record["mitre_techniques"]:
            if tech["technique_id"] in seen_techniques:
                continue
            seen_techniques.add(tech["technique_id"])

            ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, tech['technique_id'])}"
            ap = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": tech["technique_name"],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech["technique_id"],
                    "url": f"https://attack.mitre.org/techniques/{tech['technique_id']}/"
                }]
            }
            stix_objects.append(ap)

            # Relationship: threat-actor uses attack-pattern
            uses_rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": ap_id
            }
            stix_objects.append(uses_rel)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }

    return json.dumps(bundle, indent=2)

"""
Incident Report Generator.
Creates detailed Markdown incident reports for attacker sessions.
"""
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from .models import (
    AttackerFingerprint, AttackerSession, SessionEvent,
    MitreMapping, HoneypotLog
)
from .session_tracker import get_session_timeline
from .mitre import get_session_mitre_summary


def generate_incident_report(db: DBSession, session_id: str) -> str:
    """
    Generate a comprehensive Markdown incident report for a session.
    Includes fingerprint, timeline, attack classifications, MITRE mapping,
    and recommended response actions.
    """
    # Fetch session
    session = db.query(AttackerSession).filter(
        AttackerSession.id == session_id
    ).first()

    if not session:
        return f"# Incident Report\n\n**Error:** Session `{session_id}` not found."

    # Fetch fingerprint
    fingerprint = None
    if session.fingerprint_id:
        fingerprint = db.query(AttackerFingerprint).filter(
            AttackerFingerprint.id == session.fingerprint_id
        ).first()

    # Fetch timeline
    timeline = get_session_timeline(db, session_id)

    # Fetch MITRE mappings
    mitre_data = get_session_mitre_summary(db, session_id)

    # Build report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    attack_types = json.loads(session.attack_types or "[]")

    report = []
    report.append(f"# 🚨 Incident Report")
    report.append(f"")
    report.append(f"**Report Generated:** {now}")
    report.append(f"**Session ID:** `{session_id}`")
    report.append(f"**Status:** {'🔴 Active' if session.is_active else '⚪ Closed'}")
    report.append(f"")

    # ── Threat Summary ──
    report.append(f"## 📊 Threat Summary")
    report.append(f"")
    report.append(f"| Metric | Value |")
    report.append(f"|--------|-------|")
    report.append(f"| Max Threat Score | **{session.max_threat_score:.0f}**/100 |")
    report.append(f"| Total Requests | {session.total_requests} |")
    report.append(f"| Attack Types | {', '.join(attack_types) if attack_types else 'None detected'} |")
    report.append(f"| Session Duration | {_format_duration(session.started_at, session.last_activity)} |")
    report.append(f"| First Activity | {session.started_at.isoformat() if session.started_at else 'N/A'} |")
    report.append(f"| Last Activity | {session.last_activity.isoformat() if session.last_activity else 'N/A'} |")
    report.append(f"")

    # ── Attacker Fingerprint ──
    report.append(f"## 🔍 Attacker Fingerprint")
    report.append(f"")
    if fingerprint:
        report.append(f"| Field | Value |")
        report.append(f"|-------|-------|")
        report.append(f"| Fingerprint ID | `{fingerprint.id}` |")
        report.append(f"| IP Address | `{fingerprint.ip_address}` |")
        report.append(f"| User Agent | `{(fingerprint.user_agent or 'N/A')[:100]}` |")
        report.append(f"| Header Hash | `{fingerprint.header_hash}` |")
        report.append(f"| Confidence | {fingerprint.confidence_score:.2f} |")
        report.append(f"| Threat Level | **{fingerprint.threat_level}** |")
        report.append(f"| Total Requests (All Sessions) | {fingerprint.total_requests} |")
        report.append(f"| First Seen | {fingerprint.first_seen.isoformat() if fingerprint.first_seen else 'N/A'} |")
    else:
        report.append(f"*Fingerprint data unavailable.*")
    report.append(f"")

    # ── Session Replay Timeline ──
    report.append(f"## 🕐 Session Replay Timeline")
    report.append(f"")
    if timeline:
        # Visual path flow
        paths = [f"`{e['method']} {e['path']}`" for e in timeline]
        report.append(f"**Attack Path:** {' → '.join(paths)}")
        report.append(f"")

        report.append(f"| # | Time | Method | Path | Score | Attack Type | Δ Time |")
        report.append(f"|---|------|--------|------|-------|-------------|--------|")
        for i, event in enumerate(timeline, 1):
            ts = event.get("timestamp", "")
            if ts:
                ts = ts.split("T")[1][:8] if "T" in ts else ts
            delta = f"{event.get('time_delta_ms', 0)}ms" if event.get('time_delta_ms') else "-"
            score = event.get("threat_score", 0)
            score_icon = "🔴" if score > 80 else ("🟡" if score > 50 else "🟢")
            attack = event.get("attack_type") or "-"

            report.append(
                f"| {i} | {ts} | {event.get('method', '')} | "
                f"`{event.get('path', '')}` | {score_icon} {score:.0f} | {attack} | {delta} |"
            )

        report.append(f"")

        # Payload snippets
        payloads = [(e["path"], e.get("payload_snippet")) for e in timeline if e.get("payload_snippet")]
        if payloads:
            report.append(f"### Payload Snippets (Sanitized)")
            report.append(f"")
            for path, payload in payloads:
                report.append(f"**{path}:**")
                report.append(f"```")
                report.append(f"{payload[:300]}")
                report.append(f"```")
                report.append(f"")
    else:
        report.append(f"*No timeline events recorded.*")
    report.append(f"")

    # ── MITRE ATT&CK Mapping ──
    report.append(f"## 🗺️ MITRE ATT&CK Mapping")
    report.append(f"")
    if mitre_data:
        report.append(f"| Tactic | Technique ID | Technique Name | Confidence | Occurrences |")
        report.append(f"|--------|-------------|----------------|------------|-------------|")
        for m in mitre_data:
            report.append(
                f"| {m['tactic']} | `{m['technique_id']}` | "
                f"{m['technique_name']} | {m['confidence']:.2f} | {m.get('count', 1)} |"
            )
    else:
        report.append(f"*No MITRE ATT&CK techniques mapped for this session.*")
    report.append(f"")

    # ── Recommended Response Actions ──
    report.append(f"## 🛡️ Recommended Response Actions")
    report.append(f"")
    threat = session.max_threat_score

    if threat > 85:
        report.append(f"1. ✅ **Immediately block** IP `{fingerprint.ip_address if fingerprint else 'Unknown'}` at firewall level")
        report.append(f"2. ✅ **Report** IP to threat intelligence feeds (AbuseIPDB, etc.)")
        report.append(f"3. ✅ **Review** all logs from this fingerprint for lateral movement")
        report.append(f"4. ✅ **Verify** no real services were affected")
    elif threat > 60:
        report.append(f"1. ⚠️ **Monitor** IP `{fingerprint.ip_address if fingerprint else 'Unknown'}` closely")
        report.append(f"2. ⚠️ **Consider** rate limiting or JS challenge for this IP")
        report.append(f"3. ⚠️ **Review** request patterns for escalation indicators")
    else:
        report.append(f"1. ℹ️ **Log** and continue monitoring")
        report.append(f"2. ℹ️ **No immediate action** required")

    report.append(f"")
    report.append(f"---")
    report.append(f"*Report generated by Honeypot v2 SOC Platform*")

    return "\n".join(report)


def _format_duration(start, end) -> str:
    """Format duration between two datetimes."""
    if not start or not end:
        return "N/A"
    try:
        delta = end - start
        total_seconds = int(delta.total_seconds())
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m {total_seconds % 60}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    except Exception:
        return "N/A"

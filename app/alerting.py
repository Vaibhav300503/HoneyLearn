"""
Alerting System — Sends alerts via Telegram, Email, and Discord
when threats exceed thresholds or honeytokens are triggered.
"""
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session as DBSession

from .config import settings
from .models import AlertLog

# Optional httpx for Telegram/Discord
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


def _log_alert(
    db: DBSession,
    alert_type: str,
    trigger_reason: str,
    fingerprint_id: Optional[str],
    session_id: Optional[str],
    success: bool,
    details: str = ""
):
    """Record alert attempt in database."""
    record = AlertLog(
        alert_type=alert_type,
        trigger_reason=trigger_reason,
        fingerprint_id=fingerprint_id,
        session_id=session_id,
        success=success,
        details=details
    )
    db.add(record)
    db.flush()


def send_telegram_alert(message: str) -> bool:
    """Send alert message via Telegram Bot API."""
    if not settings.telegram_enabled or not HTTPX_AVAILABLE:
        return False

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, json=payload)
            result = resp.json()
            success = result.get("ok", False)
            if success:
                print("[ALERT] Telegram alert sent successfully.")
            else:
                print(f"[ALERT] Telegram alert failed: {result}")
            return success
    except Exception as e:
        print(f"[ALERT] Telegram error: {e}")
        return False


def send_email_alert(subject: str, body: str) -> bool:
    """Send alert email via SMTP."""
    if not settings.email_enabled:
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = settings.SMTP_USER
        msg["To"] = settings.ALERT_EMAIL_TO
        msg["Subject"] = f"[HONEYPOT ALERT] {subject}"
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.send_message(msg)

        print("[ALERT] Email alert sent successfully.")
        return True
    except Exception as e:
        print(f"[ALERT] Email error: {e}")
        return False


def send_discord_alert(message: str) -> bool:
    """Send alert via Discord webhook."""
    if not settings.discord_enabled or not HTTPX_AVAILABLE:
        return False

    payload = {
        "content": message,
        "username": "Honeypot Alert"
    }

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(settings.DISCORD_WEBHOOK_URL, json=payload)
            success = resp.status_code in (200, 204)
            if success:
                print("[ALERT] Discord alert sent successfully.")
            return success
    except Exception as e:
        print(f"[ALERT] Discord error: {e}")
        return False


def format_alert_message(
    trigger_reason: str,
    ip: str,
    fingerprint_id: str,
    threat_score: float,
    attack_type: str,
    path: str,
    session_id: Optional[str] = None
) -> str:
    """Format a rich alert message for all channels."""
    return (
        f"🚨 *HONEYPOT ALERT*\n\n"
        f"**Trigger:** {trigger_reason}\n"
        f"**IP:** `{ip}`\n"
        f"**Fingerprint:** `{fingerprint_id[:16]}...`\n"
        f"**Threat Score:** {threat_score:.0f}/100\n"
        f"**Attack Type:** {attack_type}\n"
        f"**Target Path:** `{path}`\n"
        f"**Session:** `{session_id or 'N/A'}`\n"
        f"**Time:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"🔗 Check dashboard for full details."
    )


def dispatch_alert(
    db: DBSession,
    trigger_reason: str,
    ip: str,
    fingerprint_id: str,
    threat_score: float,
    attack_type: str,
    path: str,
    session_id: Optional[str] = None
):
    """
    Dispatch alert to all configured channels.
    Called when threat_score exceeds threshold or honeytoken is triggered.
    """
    message = format_alert_message(
        trigger_reason, ip, fingerprint_id, threat_score, attack_type, path, session_id
    )

    # Try each channel
    if settings.telegram_enabled:
        success = send_telegram_alert(message)
        _log_alert(db, "telegram", trigger_reason, fingerprint_id, session_id, success, message)

    if settings.email_enabled:
        success = send_email_alert(trigger_reason, message)
        _log_alert(db, "email", trigger_reason, fingerprint_id, session_id, success, message)

    if settings.discord_enabled:
        success = send_discord_alert(message)
        _log_alert(db, "discord", trigger_reason, fingerprint_id, session_id, success, message)

    # If no external channels configured, just log locally
    if not any([settings.telegram_enabled, settings.email_enabled, settings.discord_enabled]):
        _log_alert(db, "local", trigger_reason, fingerprint_id, session_id, True, message)
        print(f"[ALERT LOCAL] {trigger_reason} - IP: {ip}, Score: {threat_score}")

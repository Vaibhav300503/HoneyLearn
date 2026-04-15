"""
Nginx Deny Rules Generator.
Generates an Nginx deny config file from blocked IPs.
Supports whitelist and auto-reload.
"""
import os
from typing import List, Set
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import BlockedIP
from .config import settings


def generate_deny_rules(db: Session, whitelist: Set[str] = None) -> str:
    """
    Generate Nginx deny rules content from blocked IPs in database.
    Returns the config file content as a string.
    """
    if whitelist is None:
        whitelist = set(settings.WHITELIST_IPS)

    blocked = db.query(BlockedIP).all()

    lines = [
        f"# Honeypot Auto-Generated Deny Rules",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        f"# Total blocked IPs: {len(blocked)}",
        "",
    ]

    # Add whitelist allow rules first
    for ip in sorted(whitelist):
        if ip and ip not in ("localhost", "::1"):
            lines.append(f"allow {ip};")

    lines.append("")

    # Add deny rules
    for entry in blocked:
        if entry.ip_address not in whitelist:
            reason = (entry.reason or "No reason").replace("\n", " ")[:80]
            lines.append(f"deny {entry.ip_address};  # {reason}")

    lines.append("")
    return "\n".join(lines)


def write_deny_file(db: Session) -> dict:
    """
    Write the deny rules to the configured Nginx deny file.
    Returns status dict.
    """
    deny_file = settings.NGINX_DENY_FILE
    content = generate_deny_rules(db)

    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(deny_file), exist_ok=True)

        with open(deny_file, "w") as f:
            f.write(content)

        print(f"[NGINX] Deny rules written to {deny_file}")
        return {"success": True, "file": deny_file, "rules_count": content.count("deny ")}
    except PermissionError:
        print(f"[NGINX] Permission denied writing to {deny_file}")
        return {"success": False, "error": f"Permission denied: {deny_file}"}
    except Exception as e:
        print(f"[NGINX] Error writing deny file: {e}")
        return {"success": False, "error": str(e)}


def add_deny_rule(ip: str) -> str:
    """
    Append a single deny rule to the Nginx config file.
    Returns the rule line.
    """
    rule = f"deny {ip};  # Added {datetime.now(timezone.utc).isoformat()}\n"
    try:
        with open(settings.NGINX_DENY_FILE, "a") as f:
            f.write(rule)
    except Exception as e:
        print(f"[NGINX] Error appending deny rule: {e}")
    return rule


def reload_nginx() -> dict:
    """
    Send reload signal to Nginx (only works if running with proper permissions).
    """
    try:
        result = os.system("nginx -s reload")
        return {"success": result == 0}
    except Exception as e:
        return {"success": False, "error": str(e)}

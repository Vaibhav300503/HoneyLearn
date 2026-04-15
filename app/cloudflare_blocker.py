"""
Cloudflare API Integration for automated IP blocking.
Uses Cloudflare Firewall Access Rules to block/challenge IPs.
Only active when CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID are configured.
"""
import json
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from .config import settings

# Optional httpx import — works without it if Cloudflare is not configured
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


CF_API_BASE = "https://api.cloudflare.com/client/v4"


def _headers() -> Dict[str, str]:
    """Build Cloudflare API authorization headers."""
    return {
        "Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }


def block_ip_cloudflare(ip: str, reason: str) -> Dict[str, Any]:
    """
    Create a Cloudflare firewall access rule to block an IP.
    Returns the API response or error details.
    """
    if not settings.cloudflare_enabled or not HTTPX_AVAILABLE:
        return {"success": False, "error": "Cloudflare not configured or httpx not installed"}

    url = f"{CF_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    payload = {
        "mode": "block",
        "configuration": {
            "target": "ip",
            "value": ip
        },
        "notes": f"[Honeypot] {reason} - {datetime.now(timezone.utc).isoformat()}"
    }

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, headers=_headers(), json=payload)
            data = resp.json()
            if data.get("success"):
                print(f"[CLOUDFLARE] Blocked IP {ip}")
                return {"success": True, "rule_id": data.get("result", {}).get("id")}
            else:
                errors = data.get("errors", [])
                print(f"[CLOUDFLARE] Failed to block {ip}: {errors}")
                return {"success": False, "errors": errors}
    except Exception as e:
        print(f"[CLOUDFLARE] Error blocking IP {ip}: {e}")
        return {"success": False, "error": str(e)}


def challenge_ip_cloudflare(ip: str) -> Dict[str, Any]:
    """
    Set a Cloudflare JS Challenge for a suspicious IP (captcha mode).
    """
    if not settings.cloudflare_enabled or not HTTPX_AVAILABLE:
        return {"success": False, "error": "Cloudflare not configured"}

    url = f"{CF_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    payload = {
        "mode": "js_challenge",
        "configuration": {
            "target": "ip",
            "value": ip
        },
        "notes": f"[Honeypot] Suspicious traffic challenge - {datetime.now(timezone.utc).isoformat()}"
    }

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, headers=_headers(), json=payload)
            data = resp.json()
            return {"success": data.get("success", False)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def unblock_ip_cloudflare(ip: str) -> Dict[str, Any]:
    """
    Remove a Cloudflare firewall rule for an IP.
    First finds the rule by IP, then deletes it.
    """
    if not settings.cloudflare_enabled or not HTTPX_AVAILABLE:
        return {"success": False, "error": "Cloudflare not configured"}

    # Find the rule
    url = f"{CF_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    params = {"configuration.value": ip, "configuration.target": "ip"}

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers=_headers(), params=params)
            data = resp.json()

            if not data.get("success") or not data.get("result"):
                return {"success": False, "error": "Rule not found"}

            # Delete each matching rule
            for rule in data["result"]:
                rule_id = rule["id"]
                del_url = f"{url}/{rule_id}"
                client.delete(del_url, headers=_headers())

            print(f"[CLOUDFLARE] Unblocked IP {ip}")
            return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

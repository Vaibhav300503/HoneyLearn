"""
Payload sanitization utilities.
Ensures all stored/displayed payloads are safe and cannot execute code.
"""
import re
import html


def sanitize_payload(raw: str, max_length: int = 2000) -> str:
    """
    Sanitize a raw payload for safe storage.
    Removes null bytes, truncates to max_length.
    """
    if not raw:
        return ""
    # Remove null bytes
    cleaned = raw.replace("\x00", "")
    # Truncate
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "...[TRUNCATED]"
    return cleaned


def sanitize_for_display(raw: str) -> str:
    """
    HTML-escape a payload for safe rendering in the dashboard.
    Prevents stored XSS from captured attacker payloads.
    """
    if not raw:
        return ""
    return html.escape(raw, quote=True)


def extract_safe_snippet(raw: str, max_len: int = 500) -> str:
    """
    Extract a safe, truncated snippet of a payload for timeline display.
    """
    if not raw:
        return ""
    cleaned = raw.replace("\x00", "")
    # Remove excessively long base64 blobs or binary noise
    cleaned = re.sub(r'[A-Za-z0-9+/=]{100,}', '[BASE64_BLOB]', cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned


def strip_dangerous_chars(value: str) -> str:
    """
    Strip characters that could be dangerous in log injection or CRLF attacks.
    """
    if not value:
        return ""
    return re.sub(r'[\r\n\x00\x1b]', '', value)

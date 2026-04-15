"""
Centralized configuration for Honeypot v2.
All settings are loaded from environment variables with sensible defaults.
"""
import os
from typing import List, Optional


class Settings:
    """Application settings loaded from environment variables."""

    # --- Database ---
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./honeypot.db")

    # --- Threat Thresholds ---
    THREAT_BLOCK_THRESHOLD: int = int(os.getenv("THREAT_BLOCK_THRESHOLD", "85"))
    ALERT_THRESHOLD: int = int(os.getenv("ALERT_THRESHOLD", "80"))
    SESSION_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))

    # --- Whitelist ---
    WHITELIST_IPS: List[str] = [
        ip.strip()
        for ip in os.getenv("WHITELIST_IPS", "127.0.0.1,localhost,::1").split(",")
        if ip.strip()
    ]

    # --- Cloudflare Integration (Optional) ---
    CLOUDFLARE_API_TOKEN: Optional[str] = os.getenv("CLOUDFLARE_API_TOKEN")
    CLOUDFLARE_ZONE_ID: Optional[str] = os.getenv("CLOUDFLARE_ZONE_ID")
    CLOUDFLARE_ACCOUNT_ID: Optional[str] = os.getenv("CLOUDFLARE_ACCOUNT_ID")

    # --- Telegram Alerts (Optional) ---
    TELEGRAM_BOT_TOKEN: Optional[str] = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID: Optional[str] = os.getenv("TELEGRAM_CHAT_ID")

    # --- Email Alerts (Optional) ---
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASS: Optional[str] = os.getenv("SMTP_PASS")
    ALERT_EMAIL_TO: Optional[str] = os.getenv("ALERT_EMAIL_TO")

    # --- Discord Alerts (Optional) ---
    DISCORD_WEBHOOK_URL: Optional[str] = os.getenv("DISCORD_WEBHOOK_URL")

    # --- Nginx Blocking (Optional) ---
    NGINX_DENY_FILE: str = os.getenv(
        "NGINX_DENY_FILE", "/etc/nginx/conf.d/honeypot_deny.conf"
    )

    @property
    def cloudflare_enabled(self) -> bool:
        return bool(self.CLOUDFLARE_API_TOKEN and self.CLOUDFLARE_ZONE_ID)

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.TELEGRAM_BOT_TOKEN and self.TELEGRAM_CHAT_ID)

    @property
    def email_enabled(self) -> bool:
        return bool(self.SMTP_HOST and self.SMTP_USER and self.ALERT_EMAIL_TO)

    @property
    def discord_enabled(self) -> bool:
        return bool(self.DISCORD_WEBHOOK_URL)


settings = Settings()

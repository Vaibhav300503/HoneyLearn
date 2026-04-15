"""
Enhanced Blocking Manager with multi-backend support.
Supports local (in-memory + DB), Cloudflare API, and Nginx deny rules.
"""
from typing import Set
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import BlockedIP, BlockEvent
from .config import settings


class BlockManager:
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.whitelist: Set[str] = set(settings.WHITELIST_IPS)

    def load_blocked_ips(self):
        """Load blocked IPs from database into memory."""
        db: Session = SessionLocal()
        try:
            blocked = db.query(BlockedIP).all()
            self.blocked_ips = {b.ip_address for b in blocked}
            print(f"[BLOCK] Loaded {len(self.blocked_ips)} blocked IPs from database.")
        finally:
            db.close()

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist

    def block_ip(self, ip: str, reason: str, auto: bool = True, method: str = "local"):
        """
        Block an IP address.
        Supports multiple blocking methods: local, cloudflare, nginx.
        """
        if self.is_whitelisted(ip):
            return False

        if ip not in self.blocked_ips:
            db: Session = SessionLocal()
            try:
                # Add to BlockedIP table (v1 compat)
                new_block = BlockedIP(ip_address=ip, reason=reason)
                db.add(new_block)

                # Add to BlockEvent audit trail (v2)
                event = BlockEvent(
                    ip_address=ip,
                    block_reason=reason,
                    block_method=method,
                    auto_blocked=auto
                )
                db.add(event)

                db.commit()
                self.blocked_ips.add(ip)
                print(f"[BLOCK] IP {ip} blocked via {method}. Reason: {reason}")

                # Try Cloudflare blocking if configured
                if settings.cloudflare_enabled:
                    try:
                        from .cloudflare_blocker import block_ip_cloudflare
                        cf_result = block_ip_cloudflare(ip, reason)
                        if cf_result.get("success"):
                            # Record cloudflare event too
                            cf_event = BlockEvent(
                                ip_address=ip,
                                block_reason=reason,
                                block_method="cloudflare",
                                auto_blocked=auto
                            )
                            db.add(cf_event)
                            db.commit()
                    except Exception as e:
                        print(f"[BLOCK] Cloudflare block failed for {ip}: {e}")

                return True
            except Exception as e:
                db.rollback()
                print(f"[BLOCK] Error blocking IP {ip}: {e}")
            finally:
                db.close()
        return False

    def unblock_ip(self, ip: str):
        """Unblock an IP from all blocking backends."""
        if ip in self.blocked_ips:
            db: Session = SessionLocal()
            try:
                db.query(BlockedIP).filter(BlockedIP.ip_address == ip).delete()

                # Update block events with unblock timestamp
                events = db.query(BlockEvent).filter(
                    BlockEvent.ip_address == ip,
                    BlockEvent.unblocked_at == None
                ).all()
                for event in events:
                    event.unblocked_at = datetime.now(timezone.utc)

                db.commit()
                self.blocked_ips.remove(ip)
                print(f"[BLOCK] IP {ip} unblocked.")

                # Try Cloudflare unblocking if configured
                if settings.cloudflare_enabled:
                    try:
                        from .cloudflare_blocker import unblock_ip_cloudflare
                        unblock_ip_cloudflare(ip)
                    except Exception as e:
                        print(f"[BLOCK] Cloudflare unblock failed for {ip}: {e}")

                return True
            except Exception as e:
                db.rollback()
                print(f"[BLOCK] Error unblocking IP {ip}: {e}")
            finally:
                db.close()
        return False

    def get_block_history(self, ip: str = None, limit: int = 100):
        """Get blocking audit trail."""
        db: Session = SessionLocal()
        try:
            query = db.query(BlockEvent)
            if ip:
                query = query.filter(BlockEvent.ip_address == ip)
            events = query.order_by(BlockEvent.blocked_at.desc()).limit(limit).all()
            return [
                {
                    "ip_address": e.ip_address,
                    "block_reason": e.block_reason,
                    "block_method": e.block_method,
                    "blocked_at": e.blocked_at.isoformat() if e.blocked_at else None,
                    "unblocked_at": e.unblocked_at.isoformat() if e.unblocked_at else None,
                    "auto_blocked": e.auto_blocked,
                }
                for e in events
            ]
        finally:
            db.close()


block_manager = BlockManager()

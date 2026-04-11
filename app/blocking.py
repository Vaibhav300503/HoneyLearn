from typing import Set
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import BlockedIP

class BlockManager:
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.whitelist: Set[str] = {"127.0.0.1", "localhost", "::1"}

    def load_blocked_ips(self):
        db: Session = SessionLocal()
        try:
            blocked = db.query(BlockedIP).all()
            self.blocked_ips = {b.ip_address for b in blocked}
            print(f"Loaded {len(self.blocked_ips)} blocked IPs from database.")
        finally:
            db.close()

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist

    def block_ip(self, ip: str, reason: str):
        if self.is_whitelisted(ip):
            return False

        if ip not in self.blocked_ips:
            db: Session = SessionLocal()
            try:
                # Add to DB
                new_block = BlockedIP(ip_address=ip, reason=reason)
                db.add(new_block)
                db.commit()
                # Update memory
                self.blocked_ips.add(ip)
                print(f"[ACTION] IP {ip} permanently blocked. Reason: {reason}")
                return True
            except Exception as e:
                db.rollback()
                print(f"Error blocking IP {ip}: {e}")
            finally:
                db.close()
        return False
        
    def unblock_ip(self, ip: str):
        if ip in self.blocked_ips:
            db: Session = SessionLocal()
            try:
                db.query(BlockedIP).filter(BlockedIP.ip_address == ip).delete()
                db.commit()
                self.blocked_ips.remove(ip)
                return True
            except Exception as e:
                db.rollback()
                print(f"Error unblocking IP {ip}: {e}")
            finally:
                db.close()
        return False

block_manager = BlockManager()

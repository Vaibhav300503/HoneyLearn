from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from .database import Base

class HoneypotLog(Base):
    __tablename__ = "honeypot_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(50), index=True)
    user_agent = Column(Text)
    method = Column(String(10))
    path = Column(String(255), index=True)
    headers = Column(Text)  # JSON string
    payload = Column(Text)
    threat_score = Column(Float, default=0.0)
    anomaly_flag = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, index=True)
    reason = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())

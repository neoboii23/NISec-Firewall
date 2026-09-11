"""Portable SQLAlchemy mappings over the ONE existing security database.

Migrations remain owned by ManagementStore/SecurityEventStore. Do not call
create_all on a live database: BlockedIP, TrustedIP and RequestLog map read-only
views. A MySQL migration must port the existing SQL queries and view DDL too.
"""
from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base=declarative_base()

class AdminUser(Base):
    __tablename__='dashboard_admins'
    username=Column(String(80),primary_key=True)
    password_hash=Column(Text,nullable=False)
    role=Column(String(16),nullable=False,default='ADMIN')

class FirewallRule(Base):
    __tablename__='firewall_rules'
    id=Column(String(100),primary_key=True)
    config=Column(Text,nullable=False)
    updated_at=Column(Float,nullable=False)

class SecurityEvent(Base):
    __tablename__='security_events'
    id=Column(Integer,primary_key=True)
    incident_id=Column(String(100),index=True)
    timestamp=Column(String(40),index=True)
    source_ip=Column(String(45),index=True)
    method=Column(String(16))
    path=Column(Text)
    attack_category=Column(String(60),index=True)
    category_code=Column(String(16))
    category_name=Column(String(80))
    severity=Column(String(16),index=True)
    threat_score=Column(Integer)
    matched_rules=Column(Text)
    decision=Column(String(32),index=True)
    response_status=Column(Integer)
    evidence=Column(Text)
    categories=Column(Text)
    alerts=relationship('SecurityAlert',viewonly=True)

class SecurityAlert(Base):
    __tablename__='security_alerts'
    id=Column(Integer,primary_key=True)
    event_id=Column(Integer,ForeignKey('security_events.id'),unique=True)
    incident_id=Column(String(100))
    timestamp=Column(String(40))
    source_ip=Column(String(45))
    category=Column(String(60))
    severity=Column(String(16))
    message=Column(Text)
    acknowledged=Column(Integer)

class PolicyFields:
    ip=Column(String(45),primary_key=True)
    kind=Column(String(16),primary_key=True)
    reason=Column(Text)
    created_at=Column(Float)
    expires_at=Column(Float)
    source=Column(String(16))
    added_by=Column(String(80))
    incident_id=Column(String(100))
    attack_category=Column(String(60))
    trust_mode=Column(String(32))

class BlockedIP(PolicyFields,Base):
    __tablename__='blocked_ips'

class TrustedIP(PolicyFields,Base):
    __tablename__='trusted_ips'

class RequestLog(Base):
    __tablename__='request_logs'
    id=Column(Integer,primary_key=True)
    incident_id=Column(String(100))
    timestamp=Column(String(40))
    source_ip=Column(String(45))
    method=Column(String(16))
    path=Column(Text)
    decision=Column(String(32))
    response_status=Column(Integer)

class RateLimitRecord(Base):
    __tablename__='rate_limit_records'
    id=Column(Integer,primary_key=True)
    event_id=Column(Integer,ForeignKey('security_events.id'))
    source_ip=Column(String(45))
    timestamp=Column(String(40))
    retry_after=Column(Integer)

class AdminAuditLog(Base):
    __tablename__='management_audit'
    id=Column(Integer,primary_key=True)
    timestamp=Column(Float)
    actor=Column(String(80))
    action=Column(String(100))
    target=Column(String(250))
    old_value=Column(Text)
    new_value=Column(Text)

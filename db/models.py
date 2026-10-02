"""
Database models for AI-IDPS
Run inside backend/app.py context to create tables:
    from db.models import db
    db.create_all()
"""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# Max length kept for a captured request body snippet. This column is
# documented as "truncated" by its callers, but nothing previously enforced
# that at the DB layer - a caller that forgot to truncate could write an
# unbounded blob per request, which is a real memory/disk bloat risk on a
# high-traffic sensor. This is a backstop, not the primary truncation point.
MAX_BODY_SNIPPET_LEN = 2000

VALID_ROLES         = ("admin", "analyst", "viewer")
VALID_SEVERITIES     = ("low", "medium", "high", "critical")
VALID_ACTIONS_TAKEN  = ("none", "blocked", "alerted")


class User(db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), nullable=False, default="viewer")  # admin, analyst, viewer
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')", name="ck_users_role_valid"
        ),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class TrafficLog(db.Model):
    __tablename__ = "traffic_logs"

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    src_ip     = db.Column(db.String(45), nullable=False, index=True)
    dst_ip     = db.Column(db.String(45))
    src_port   = db.Column(db.Integer)
    dst_port   = db.Column(db.Integer)
    protocol   = db.Column(db.String(10))
    packet_len = db.Column(db.Integer)
    flags      = db.Column(db.String(20))

    __table_args__ = (
        db.Index("ix_traffic_logs_src_ip_ts", "src_ip", "timestamp"),
    )


class Alert(db.Model):
    __tablename__ = "alerts"

    id              = db.Column(db.Integer, primary_key=True)
    timestamp       = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    src_ip          = db.Column(db.String(45), nullable=False, index=True)
    dst_ip          = db.Column(db.String(45))
    attack_type     = db.Column(db.String(50), nullable=False)   # SQLi, XSS, BruteForce, PortScan, DoS, Normal
    confidence      = db.Column(db.Float)
    severity        = db.Column(db.String(20))   # low, medium, high, critical
    raw_features    = db.Column(db.Text)         # JSON string of feature vector
    action_taken    = db.Column(db.String(50), default="none")  # none, blocked, alerted
    mitre_technique = db.Column(db.String(100), nullable=True)  # e.g. T1046, T1499

    __table_args__ = (
        db.Index("ix_alerts_src_ip_ts", "src_ip", "timestamp"),
        db.Index("ix_alerts_attack_type", "attack_type"),
        # The analytics endpoints (distribution/timeline/severity/heatmap)
        # all filter on a timestamp range *and* group/filter by attack_type
        # in the same query - a composite index lets SQLite satisfy both
        # parts of that query with one index scan instead of a full scan
        # filtered by attack_type alone.
        db.Index("ix_alerts_ts_attack_type", "timestamp", "attack_type"),
        db.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_alerts_confidence_range",
        ),
        db.CheckConstraint(
            "severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_alerts_severity_valid",
        ),
        db.CheckConstraint(
            "action_taken IS NULL OR action_taken IN ('none', 'blocked', 'alerted')",
            name="ck_alerts_action_taken_valid",
        ),
    )


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id               = db.Column(db.Integer, primary_key=True)
    ip_address       = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason           = db.Column(db.String(255))
    blocked_at       = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at       = db.Column(db.DateTime, nullable=True, index=True)  # None = permanent
    opnsense_rule_id = db.Column(db.String(100), nullable=True)
    # `active` is filtered on by nearly every blocked-IP query
    # (dashboard listing, unblock/re-block checks, IPS expiry sweeps) but
    # previously had no index, forcing a full table scan as the block list
    # grows.
    active           = db.Column(db.Boolean, default=True, nullable=False, index=True)


class WebAccessLog(db.Model):
    __tablename__ = "web_access_logs"

    id           = db.Column(db.Integer, primary_key=True)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    src_ip       = db.Column(db.String(45), nullable=False, index=True)
    method       = db.Column(db.String(10))
    path         = db.Column(db.String(500))
    status_code  = db.Column(db.Integer)
    user_agent   = db.Column(db.String(255))
    body_snippet = db.Column(db.Text)  # truncated request body for pattern checks

    __table_args__ = (
        db.Index("ix_web_logs_src_ip_ts", "src_ip", "timestamp"),
        db.CheckConstraint(
            "status_code IS NULL OR (status_code >= 100 AND status_code < 600)",
            name="ck_web_logs_status_code_valid",
        ),
    )

    @validates("body_snippet")
    def _cap_body_snippet(self, key, value):
        """Defensive truncation so a caller that forgets to trim a captured
        body before insert can't write unbounded text into the DB."""
        if value is not None and len(value) > MAX_BODY_SNIPPET_LEN:
            return value[:MAX_BODY_SNIPPET_LEN]
        return value


class AuditLog(db.Model):
    """Records every admin/analyst action for SOC compliance."""
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    username   = db.Column(db.String(80), nullable=False)
    role       = db.Column(db.String(20), nullable=False)
    action     = db.Column(db.String(100), nullable=False)  # e.g. "BLOCK_IP", "UNBLOCK_IP"
    target     = db.Column(db.String(255), nullable=True)   # IP address or resource affected
    detail     = db.Column(db.Text, nullable=True)          # JSON extra context
    ip_address = db.Column(db.String(45), nullable=True)    # analyst's own IP

    __table_args__ = (
        db.Index("ix_audit_logs_username_ts", "username", "timestamp"),
    )
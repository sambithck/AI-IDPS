"""
backend/api.py
REST API endpoints consumed by the SOC dashboard frontend.
All endpoints require a valid JWT (any role) unless noted.
"""
import csv
import io
import json
import logging
from datetime import datetime, timedelta
import psutil
from flask import Blueprint, jsonify, request, make_response
from flask_jwt_extended import (
    jwt_required,
    get_jwt,
    get_jwt_identity,
    verify_jwt_in_request
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from db.models import db, Alert, BlockedIP, WebAccessLog, AuditLog
from feature_engine.aggregator import aggregator
from backend.auth import roles_required

logger = logging.getLogger("ai_idps.api")
api_bp = Blueprint("api", __name__)

# ---------------------------------------------------------------------------
# Rate limiter (attached to app in create_app via limiter.init_app)
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "PortScan":          "T1046 - Network Service Discovery",
    "DoS":               "T1499 - Endpoint Denial of Service",
    "BruteForce":        "T1110 - Brute Force",
    "WebAttack":         "T1190 - Exploit Public-Facing Application",
    "SQL_INJECTION":     "T1190 - Exploit Public-Facing Application",
    "XSS":               "T1189 - Drive-by Compromise",
    "XSS_REFLECTED":     "T1189 - Drive-by Compromise",
    "XSS_STORED":        "T1189 - Drive-by Compromise",
    "COMMAND_INJECTION": "T1059 - Command and Scripting Interpreter",
    "LFI":               "T1005 - Data from Local System",
    "Normal":            None,
}

# Attack-type value used by the classifier/aggregator to tag benign traffic.
# Rows with this attack_type are real DB rows (kept for full traffic
# visibility / forensics) but must never be counted in "attack" statistics.
BENIGN_ATTACK_TYPE = "Normal"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _write_audit(action, target=None, detail=None):
    try:
        verify_jwt_in_request(optional=True)
        try:
            claims = get_jwt()
            username = get_jwt_identity() or "anonymous"
            role = claims.get("role", "anonymous")
        except Exception:
            username = "anonymous"
            role = "anonymous"
        entry = AuditLog(
            username=username,
            role=role,
            action=action,
            target=target,
            detail=json.dumps(detail) if detail else None,
            ip_address=request.remote_addr,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning("Audit log write failed: %s", e)


def _safe_round(value, ndigits=3):
    """round() blows up on None; every endpoint that formats a confidence
    score needs this instead of calling round()/format directly."""
    if value is None:
        return None
    try:
        return round(value, ndigits)
    except (TypeError, ValueError):
        return None


def _parse_int_arg(name, default, minimum=None, maximum=None):
    """Parse an int query param, falling back to `default` on bad input
    instead of letting int() raise and fall through to a generic 500."""
    raw = request.args.get(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


# ===========================================================================
# Page 1 - Live monitoring
# ===========================================================================
@api_bp.route("/api/system/stats", methods=["GET"])
@jwt_required()
@limiter.limit("60 per minute")
def system_stats():
    try:
        # interval=0.2 blocks this worker thread on every single poll; the
        # dashboard polls this endpoint continuously, so a non-blocking call
        # (which reports usage since the previous call) avoids stacking up
        # blocked request threads under load.
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        net = psutil.net_io_counters()
        return jsonify({
            "cpu_percent":  cpu,
            "ram_percent":  mem.percent,
            "ram_used_mb":  round(mem.used  / (1024 * 1024), 2),
            "ram_total_mb": round(mem.total / (1024 * 1024), 2),
            "bytes_sent":   net.bytes_sent,
            "bytes_recv":   net.bytes_recv,
        })
    except Exception as e:
        logger.error("system_stats error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/traffic/live", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def live_traffic():
    """Aggregate live feature snapshot for every actively-seen IP."""
    try:
        result = []
        for ip in aggregator.active_ips():
            feats = aggregator.get_features(ip)
            feats["ip"] = ip
            result.append(feats)
        return jsonify(result)
    except Exception as e:
        logger.error("live_traffic error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/stats/summary", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def stats_summary():
    """KPI summary for Page 1 header cards."""
    try:
        since = datetime.utcnow() - timedelta(hours=24)
        active_alerts = (
            Alert.query
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .count()
        )
        blocked_count = BlockedIP.query.filter_by(active=True).count()
        critical_count = Alert.query.filter(
            Alert.timestamp >= since,
            Alert.attack_type != BENIGN_ATTACK_TYPE,
            Alert.severity == "critical",
        ).count()
        # Top attacking IP in last 24h (benign traffic excluded so a chatty
        # but harmless IP can't crowd out the real top attacker)
        top_ip_row = (
            db.session.query(Alert.src_ip, db.func.count(Alert.id).label("cnt"))
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by(Alert.src_ip)
            .order_by(db.desc("cnt"))
            .first()
        )
        top_ip = top_ip_row[0] if top_ip_row else "N/A"
        top_ip_count = top_ip_row[1] if top_ip_row else 0
        return jsonify({
            "active_alerts_24h": active_alerts,
            "blocked_ips":       blocked_count,
            "critical_alerts":   critical_count,
            "top_attacker_ip":   top_ip,
            "top_attacker_hits": top_ip_count,
        })
    except Exception as e:
        logger.error("stats_summary error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


# ===========================================================================
# Page 2 - Attack analytics
# ===========================================================================
# ---------------------------------------------------------------------------
# Dashboard time-window helper
# ---------------------------------------------------------------------------
# All dashboard stat endpoints default to showing only the last 24 hours of
# data so older alerts don't linger on the SOC Overview / Analytics pages.
# Callers can override with ?hours=N or an explicit ?since=ISO8601.
DEFAULT_DASHBOARD_WINDOW_HOURS = 24


def _dashboard_since(default_hours=DEFAULT_DASHBOARD_WINDOW_HOURS):
    """Resolve the cutoff datetime for dashboard queries.
    ?since=<ISO8601> takes priority if provided and valid.
    Otherwise falls back to now - ?hours=N (default 24)."""
    since_str = request.args.get("since")
    if since_str:
        try:
            # datetime.fromisoformat() can't parse a trailing "Z" (UTC
            # designator) on Python < 3.11, which is exactly what
            # JS's `Date.toISOString()` sends from the dashboard.
            normalized = since_str.replace("Z", "+00:00") if since_str.endswith("Z") else since_str
            parsed = datetime.fromisoformat(normalized)
            # Alert.timestamp is stored naive (UTC) in SQLite; comparing a
            # tz-aware datetime against a naive column raises/breaks the
            # filter, so convert to UTC and drop tzinfo before returning.
            if parsed.tzinfo is not None:
                parsed = (parsed - parsed.utcoffset()).replace(tzinfo=None)
            return parsed
        except ValueError:
            pass
    try:
        hours = float(request.args.get("hours", default_hours))
    except (TypeError, ValueError):
        hours = default_hours
    return datetime.utcnow() - timedelta(hours=hours)


@api_bp.route("/api/alerts", methods=["GET"])
@jwt_required()
@limiter.limit("60 per minute")
def list_alerts():
    try:
        page        = _parse_int_arg("page", 1, minimum=1)
        per_page    = _parse_int_arg("per_page", 50, minimum=1, maximum=200)
        attack_type = request.args.get("attack_type")
        severity    = request.args.get("severity")
        since       = _dashboard_since()
        q = Alert.query.order_by(Alert.timestamp.desc()).filter(Alert.timestamp >= since)
        if attack_type:
            q = q.filter(Alert.attack_type == attack_type)
        if severity:
            q = q.filter(Alert.severity == severity)
        paginated = q.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            "page":       paginated.page,
            "per_page":   paginated.per_page,
            "total":      paginated.total,
            "pages":      paginated.pages,
            "alerts": [
                {
                    "id":              a.id,
                    "timestamp":       a.timestamp.isoformat(),
                    "src_ip":          a.src_ip,
                    "attack_type":     a.attack_type,
                    "confidence":      _safe_round(a.confidence, 3),
                    "severity":        a.severity,
                    "action_taken":    a.action_taken,
                    "mitre_technique": MITRE_MAP.get(a.attack_type),
                }
                for a in paginated.items
            ],
        })
    except Exception as e:
        logger.error("list_alerts error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/distribution", methods=["GET"])
@jwt_required()
def alert_distribution():
    try:
        since = _dashboard_since()
        rows = (
            db.session.query(Alert.attack_type, db.func.count(Alert.id))
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by(Alert.attack_type)
            .all()
        )
        return jsonify({at: cnt for at, cnt in rows})
    except Exception as e:
        logger.error("alert_distribution error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/severity", methods=["GET"])
@jwt_required()
def alert_severity():
    """Count of alerts grouped by severity."""
    try:
        since = _dashboard_since()
        rows = (
            db.session.query(Alert.severity, db.func.count(Alert.id))
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by(Alert.severity)
            .all()
        )
        return jsonify({sev: cnt for sev, cnt in rows})
    except Exception as e:
        logger.error("alert_severity error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/timeline", methods=["GET"])
@jwt_required()
def alert_timeline():
    """Alerts grouped by hour, for Page 2 trend chart."""
    try:
        since = _dashboard_since()
        rows = (
            db.session.query(
                db.func.strftime("%Y-%m-%d %H:00:00", Alert.timestamp).label("bucket"),
                Alert.attack_type,
                db.func.count(Alert.id),
            )
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by("bucket", Alert.attack_type)
            .order_by("bucket")
            .all()
        )
        timeline = {}
        for bucket, attack_type, count in rows:
            key = str(bucket)
            timeline.setdefault(key, {})[attack_type] = count
        return jsonify(timeline)
    except Exception as e:
        logger.error("alert_timeline error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/top-sources", methods=["GET"])
@jwt_required()
def top_sources():
    """Top attacking source IPs by alert count."""
    try:
        since = _dashboard_since()
        limit = _parse_int_arg("limit", 10, minimum=1, maximum=20)
        rows = (
            db.session.query(Alert.src_ip, db.func.count(Alert.id).label("cnt"))
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by(Alert.src_ip)
            .order_by(db.desc("cnt"))
            .limit(limit)
            .all()
        )
        return jsonify([{"ip": ip, "count": cnt} for ip, cnt in rows])
    except Exception as e:
        logger.error("top_sources error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/blocked-vs-allowed", methods=["GET"])
@jwt_required()
def blocked_vs_allowed():
    """Counts of alerts by action_taken (blocked vs alerted vs none)."""
    try:
        since = _dashboard_since()
        rows = (
            db.session.query(Alert.action_taken, db.func.count(Alert.id))
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by(Alert.action_taken)
            .all()
        )
        return jsonify({action: cnt for action, cnt in rows})
    except Exception as e:
        logger.error("blocked_vs_allowed error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/heatmap", methods=["GET"])
@jwt_required()
def alerts_heatmap():
    """Alerts by hour-of-day (0-23) and attack type for the heatmap."""
    try:
        since = _dashboard_since()
        rows = (
            db.session.query(
                db.func.strftime("%H", Alert.timestamp).label("hour"),
                Alert.attack_type,
                db.func.count(Alert.id).label("cnt"),
            )
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .group_by("hour", Alert.attack_type)
            .all()
        )
        result = {}
        for hour, attack_type, cnt in rows:
            h = int(hour)
            result.setdefault(attack_type, {})[h] = cnt
        return jsonify(result)
    except Exception as e:
        logger.error("alerts_heatmap error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/confidence-distribution", methods=["GET"])
@jwt_required()
def confidence_distribution():
    """Histogram of confidence scores in 10% buckets."""
    try:
        since = _dashboard_since()
        alerts = (
            Alert.query
            .filter(Alert.timestamp >= since, Alert.attack_type != BENIGN_ATTACK_TYPE)
            .with_entities(Alert.confidence)
            .all()
        )
        buckets = {f"{i*10}-{i*10+10}%": 0 for i in range(10)}
        for (conf,) in alerts:
            if conf is None:
                continue
            # Clamp so a stray out-of-range value (e.g. exactly 1.0, or a
            # bad upstream score like 1.02) can't produce a bucket key that
            # was never initialized above.
            idx = min(max(int(conf * 10), 0), 9)
            key = f"{idx*10}-{idx*10+10}%"
            buckets[key] += 1
        return jsonify(buckets)
    except Exception as e:
        logger.error("confidence_distribution error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/alerts/export/csv", methods=["GET"])
@jwt_required()
@limiter.limit("10 per minute")
def export_alerts_csv():
    """Download all alerts as CSV."""
    try:
        _write_audit("EXPORT_CSV", target="alerts")
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10000).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "timestamp", "src_ip", "dst_ip", "attack_type",
                          "confidence", "severity", "action_taken", "mitre_technique"])
        for a in alerts:
            conf = _safe_round(a.confidence, 4)
            writer.writerow([
                a.id, a.timestamp.isoformat(), a.src_ip, a.dst_ip,
                a.attack_type, conf if conf is not None else "",
                a.severity, a.action_taken,
                MITRE_MAP.get(a.attack_type, ""),
            ])
        resp = make_response(output.getvalue())
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = "attachment; filename=alerts_export.csv"
        return resp
    except Exception as e:
        logger.error("export_alerts_csv error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


# ===========================================================================
# Page 3 - Incident forensics
# ===========================================================================
@api_bp.route("/api/forensics/<ip>", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def ip_forensics(ip):
    """Full timeline of alerts + traffic + web requests for a given IP."""
    try:
        alerts = (
            Alert.query.filter_by(src_ip=ip)
            .order_by(Alert.timestamp.desc())
            .limit(200)
            .all()
        )
        web_logs = (
            WebAccessLog.query.filter_by(src_ip=ip)
            .order_by(WebAccessLog.timestamp.desc())
            .limit(200)
            .all()
        )
        # Compute risk score (0-100), ignoring benign classifications so a
        # chatty-but-harmless IP doesn't accumulate a risk score.
        severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 3}
        real_alerts = [a for a in alerts if a.attack_type != BENIGN_ATTACK_TYPE]
        raw_score = sum(severity_weights.get(a.severity, 0) for a in real_alerts)
        if any(a.action_taken == "blocked" for a in real_alerts):
            raw_score += 20
        risk_score = min(100, raw_score)
        # Unique MITRE techniques
        mitre_techniques = list({
            MITRE_MAP[a.attack_type]
            for a in alerts
            if a.attack_type in MITRE_MAP and MITRE_MAP[a.attack_type]
        })
        return jsonify({
            "ip":    ip,
            "risk_score":       risk_score,
            "mitre_techniques": mitre_techniques,
            "alert_count":      len(alerts),
            "web_request_count": len(web_logs),
            "alerts": [
                {
                    "timestamp":       a.timestamp.isoformat(),
                    "attack_type":     a.attack_type,
                    "confidence":      _safe_round(a.confidence, 3),
                    "severity":        a.severity,
                    "features":        json.loads(a.raw_features) if a.raw_features else {},
                    "action_taken":    a.action_taken,
                    "mitre_technique": MITRE_MAP.get(a.attack_type),
                }
                for a in alerts
            ],
            "web_requests": [
                {
                    "timestamp":   w.timestamp.isoformat(),
                    "method":      w.method,
                    "path":        w.path,
                    "status_code": w.status_code,
                    "user_agent":  w.user_agent,
                }
                for w in web_logs
            ],
        })
    except Exception as e:
        logger.error("ip_forensics error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/forensics/<ip>/incident-report", methods=["GET"])
@jwt_required()
@limiter.limit("10 per minute")
def incident_report_pdf(ip):
    """Generate and download a PDF incident report for an IP."""
    try:
        from fpdf import FPDF
        alerts = (
            Alert.query.filter_by(src_ip=ip)
            .order_by(Alert.timestamp.desc())
            .limit(100)
            .all()
        )
        _write_audit("EXPORT_INCIDENT_PDF", target=ip)
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "AI-IDPS - Incident Report", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", ln=True)
        pdf.cell(0, 7, f"Target IP: {ip}", ln=True)
        pdf.cell(0, 7, f"Total Alerts: {len(alerts)}", ln=True)
        pdf.ln(4)
        severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 3}
        real_alerts = [a for a in alerts if a.attack_type != BENIGN_ATTACK_TYPE]
        risk_score = min(100, sum(severity_weights.get(a.severity, 0) for a in real_alerts))
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"Risk Score: {risk_score}/100", ln=True)
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, "Alert Timeline", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_fill_color(30, 30, 50)
        for a in alerts[:50]:
            conf = _safe_round(a.confidence, 2)
            conf_str = f"{conf:.2f}" if conf is not None else "n/a"
            line = (f"{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  "
                    f"{a.attack_type:<14} {a.severity:<10} "
                    f"conf={conf_str}  action={a.action_taken}")
            pdf.cell(0, 6, line, ln=True)
        pdf_bytes = pdf.output()
        resp = make_response(bytes(pdf_bytes))
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = f"attachment; filename=incident_{ip}.pdf"
        return resp
    except Exception as e:
        logger.error("incident_report_pdf error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


# ===========================================================================
# Blocked IP management
# ===========================================================================
@api_bp.route("/api/blocked-ips", methods=["GET"])
@jwt_required()
def blocked_ips():
    try:
        rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
        return jsonify([
            {
                "ip_address": b.ip_address,
                "reason":     b.reason,
                "blocked_at": b.blocked_at.isoformat(),
                "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                "active":     b.active,
            }
            for b in rows
        ])
    except Exception as e:
        logger.error("blocked_ips error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/blocked-ips/<ip>/unblock", methods=["POST"])
@roles_required("admin", "analyst")
def unblock_ip(ip):
    try:
        from flask import current_app
        ips_engine = current_app.config["IPS_ENGINE"]
        ok = ips_engine.unblock_ip(ip)
        if not ok:
            return jsonify({"error": "IP not currently blocked"}), 404
        _write_audit("UNBLOCK_IP", target=ip)
        return jsonify({"message": f"{ip} unblocked"})
    except Exception as e:
        db.session.rollback()
        logger.error("unblock_ip error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@api_bp.route("/api/blocked-ips/<ip>/block", methods=["POST"])
@roles_required("admin", "analyst")
def manual_block_ip(ip):
    try:
        from flask import current_app
        ips_engine = current_app.config["IPS_ENGINE"]
        existing = BlockedIP.query.filter_by(ip_address=ip, active=True).first()
        if existing:
            return jsonify({"error": "already blocked"}), 409
        data = request.get_json() or {}
        reason = data.get("reason", "manual block")
        timeout = data.get("timeout_minutes")   # optional timeout
        rule_id = None
        expires_at = None
        if timeout:
            try:
                expires_at = datetime.utcnow() + timedelta(minutes=int(timeout))
            except (ValueError, TypeError):
                return jsonify({"error": "timeout_minutes must be an integer"}), 400
        if not ips_engine.dry_run:
            try:
                rule_id = ips_engine._add_to_opnsense_alias(ip)
            except Exception as e:
                return jsonify({"error": f"OPNsense error: {e}"}), 502
        blocked = BlockedIP(
            ip_address       = ip,
            reason           = reason,
            blocked_at       = datetime.utcnow(),
            expires_at       = expires_at,
            opnsense_rule_id = rule_id,
            active           = True,
        )
        db.session.add(blocked)
        db.session.commit()
        _write_audit("BLOCK_IP", target=ip, detail={"reason": reason, "timeout_minutes": timeout})
        return jsonify({"message": f"{ip} blocked", "expires_at": expires_at.isoformat() if expires_at else None})
    except Exception as e:
        db.session.rollback()
        logger.error("manual_block_ip error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


# ===========================================================================
# Audit log (admin only)
# ===========================================================================
@api_bp.route("/api/audit-log", methods=["GET"])
@roles_required("admin")
def audit_log():
    try:
        page = _parse_int_arg("page", 1, minimum=1)
        per_page = _parse_int_arg("per_page", 50, minimum=1, maximum=100)
        paginated = (
            AuditLog.query
            .order_by(AuditLog.timestamp.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )
        return jsonify({
            "page":     paginated.page,
            "total":    paginated.total,
            "entries": [
                {
                    "timestamp":  e.timestamp.isoformat(),
                    "username":   e.username,
                    "role":       e.role,
                    "action":     e.action,
                    "target":     e.target,
                    "ip_address": e.ip_address,
                }
                for e in paginated.items
            ],
        })
    except Exception as e:
        logger.error("audit_log error: %s", e)
        return jsonify({"error": "Internal server error"}), 500
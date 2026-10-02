"""
ips/engine.py
IPS Engine: when the IDS raises a high/critical severity alert,
this module automatically blocks the offending IP using the
OPNsense REST API (firewall alias + rule, or alias-table approach).
OPNsense setup assumed:
  - An alias of type "Host(s)" named e.g. "IDPS_BLOCKLIST" exists
  - A firewall rule blocks traffic from that alias (created once, manually)
  - This engine adds/removes IPs from that alias via the API
API docs: https://docs.opnsense.org/development/api.html
"""
import os
import logging
import threading
import time
import ipaddress
from datetime import datetime, timedelta

import requests

logger = logging.getLogger("ai_idps.ips")

OPNSENSE_HOST = os.environ.get("OPNSENSE_HOST", "https://192.168.1.1")
OPNSENSE_API_KEY = os.environ.get("OPNSENSE_API_KEY", "")
OPNSENSE_API_SECRET = os.environ.get("OPNSENSE_API_SECRET", "")
ALIAS_NAME = os.environ.get("OPNSENSE_ALIAS", "IDPS_BLOCKLIST")
VERIFY_TLS = False  # set True if OPNsense has a valid cert

# Default thresholds used if the app didn't supply Config.IPS_BLOCK_THRESHOLDS
DEFAULT_BLOCK_THRESHOLDS = {
    "SQL_INJECTION":     0.90,
    "XSS":               0.88,
    "XSS_REFLECTED":     0.88,
    "XSS_STORED":        0.85,
    "COMMAND_INJECTION": 0.90,
    "LFI":               0.85,
    "BruteForce":        0.80,
    "DoS":               0.75,
    "PortScan":          0.85,
    "WebAttack":         0.90,
}

# How often the background auto-unblock sweep checks for expired
# temporary blocks. Only starts if BOTH an `app` was supplied to
# IPSEngine (needed for Flask app-context) AND the BlockedIP model has
# a recognized expiry column - see _detect_expiry_field().
AUTO_UNBLOCK_CHECK_INTERVAL = 30


class IPSEngine:
    def __init__(self, db, BlockedIPModel, socketio, dry_run=True, block_thresholds=None, app=None):
        self.db = db
        self.BlockedIPModel = BlockedIPModel
        self.socketio = socketio
        # dry_run=True means we log/record blocks but DO NOT call OPNsense.
        # Set to False once OPNSENSE_* env vars are configured and tested.
        self.dry_run = dry_run
        self.block_thresholds = block_thresholds or DEFAULT_BLOCK_THRESHOLDS
        # Optional Flask app instance - only needed to enable the
        # background auto-unblock sweep (it must run inside an
        # app_context to use self.db.session). If not supplied,
        # temporary blocks simply behave as permanent blocks, same as
        # the original behavior.
        self.app = app

        # Serializes the check-then-insert/update sequences in
        # handle_alert/unblock_ip so concurrent callers (or the
        # auto-unblock sweep running alongside a live alert) can't race
        # into duplicate or conflicting BlockedIP rows.
        self._lock = threading.Lock()

        # Reused HTTP connection pool instead of a fresh TCP/TLS
        # handshake on every OPNsense API call.
        self._session = requests.Session()

        # Detect (without altering the schema) whether BlockedIPModel
        # has a conventional expiry column, so temporary blocks /
        # auto-unblock only activate where the schema actually supports
        # it.
        self._expiry_field = self._detect_expiry_field()

        self._auto_unblock_thread = None
        if self.app is not None and self._expiry_field:
            self._start_auto_unblock_thread()
        elif self._expiry_field and self.app is None:
            logger.info(
                "[IPS] BlockedIP.%s column detected but no `app` was passed to "
                "IPSEngine - temporary blocks will be stored but won't auto-expire "
                "until app= is supplied.",
                self._expiry_field,
            )

    # ------------------------------------------------------------------
    # Schema introspection (read-only - never alters the schema)
    # ------------------------------------------------------------------
    def _detect_expiry_field(self):
        """Look for a conventional expiry column on BlockedIPModel
        (expires_at / block_until / unblock_at). Returns the attribute
        name if one exists, else None - in which case temporary
        blocks/auto-unblock are simply disabled and behavior is
        identical to the original permanent-block-only code."""
        candidates = ("expires_at", "block_until", "unblock_at")
        try:
            columns = {c.name for c in self.BlockedIPModel.__table__.columns}
        except Exception:
            columns = set()
        for name in candidates:
            if name in columns:
                return name
        return None

    def _validate_ip(self, ip):
        """True for any syntactically valid IPv4 or IPv6 address. Keeps
        malformed/empty values from reaching the OPNsense API or being
        written into the block table."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _should_block(self, attack_type, confidence):
        """Deterministic, threshold-based decision: same attack type and
        confidence always produces the same outcome."""
        threshold = self.block_thresholds.get(attack_type, 0.85)
        return confidence is not None and confidence >= threshold

    # ------------------------------------------------------------------
    def handle_alert(self, alert, ip, block_duration_seconds=None):
        """Block the offending IP if it crosses the configured threshold
        for its attack type.

        block_duration_seconds is optional and defaults to None
        (permanent block), so any existing caller that only passes
        (alert, ip) behaves exactly as before. Pass a number of seconds
        for a temporary block; it only takes effect if the BlockedIP
        model has an expiry column (see _detect_expiry_field) - if not,
        the value is silently ignored and the block is permanent, same
        as the original behavior.
        """
        if not self._validate_ip(ip):
            logger.warning("[IPS] Refusing to block invalid IP value: %r", ip)
            return

        blocked = None
        reason = None

        with self._lock:
            # Avoid duplicate blocks
            existing = self.BlockedIPModel.query.filter_by(ip_address=ip, active=True).first()
            if existing:
                return

            if not self._should_block(alert.attack_type, alert.confidence):
                logger.info(
                    "[IPS] %s from %s below block threshold (conf=%.2f) - alert only",
                    alert.attack_type, ip, alert.confidence or 0.0,
                )
                return

            reason = f"{alert.attack_type} (confidence={alert.confidence:.2f})"
            rule_id = None
            if not self.dry_run:
                try:
                    rule_id = self._add_to_opnsense_alias(ip)
                except Exception as e:
                    logger.error("[IPS] OPNsense block failed for %s: %s", ip, e)
            else:
                logger.info("[IPS][DRY-RUN] Would block %s (%s)", ip, reason)

            blocked = self.BlockedIPModel(
                ip_address=ip,
                reason=reason,
                blocked_at=datetime.utcnow(),
                opnsense_rule_id=rule_id,
                active=True,
            )
            if self._expiry_field and block_duration_seconds:
                setattr(
                    blocked,
                    self._expiry_field,
                    datetime.utcnow() + timedelta(seconds=block_duration_seconds),
                )

            try:
                self.db.session.add(blocked)
                alert.action_taken = "blocked"
                self.db.session.commit()
            except Exception as e:
                try:
                    self.db.session.rollback()
                except Exception:
                    pass
                if rule_id is not None:
                    # The firewall block already succeeded but we failed
                    # to persist it - surface this loudly, since the IP
                    # is now blocked at the firewall with nothing in the
                    # DB to track or unblock it via this app.
                    logger.error(
                        "[IPS] CRITICAL: %s was blocked on OPNsense (rule_id=%s) but the DB "
                        "record failed to save (%s). Manual OPNsense cleanup may be required.",
                        ip, rule_id, e
                    )
                else:
                    logger.error("[IPS] Failed to record block for %s: %s", ip, e)
                return

        try:
            self.socketio.emit(
                "ip_blocked",
                {"ip": ip, "reason": reason, "timestamp": blocked.blocked_at.isoformat()},
                namespace="/live",
            )
        except Exception as e:
            logger.error("[IPS] Failed to emit ip_blocked event for %s: %s", ip, e)

    # ------------------------------------------------------------------
    def unblock_ip(self, ip):
        with self._lock:
            blocked = self.BlockedIPModel.query.filter_by(ip_address=ip, active=True).first()
            if not blocked:
                return False

            if not self.dry_run:
                try:
                    self._remove_from_opnsense_alias(ip)
                except Exception as e:
                    logger.error("[IPS] OPNsense unblock failed for %s: %s", ip, e)

            try:
                blocked.active = False
                self.db.session.commit()
            except Exception as e:
                try:
                    self.db.session.rollback()
                except Exception:
                    pass
                logger.error("[IPS] Failed to record unblock for %s: %s", ip, e)
                return False

        try:
            self.socketio.emit("ip_unblocked", {"ip": ip}, namespace="/live")
        except Exception as e:
            logger.error("[IPS] Failed to emit ip_unblocked event for %s: %s", ip, e)
        return True

    # ------------------------------------------------------------------
    # Auto-unblock (temporary blocks)
    # ------------------------------------------------------------------
    def _start_auto_unblock_thread(self):
        t = threading.Thread(target=self._auto_unblock_loop, daemon=True, name="IPSAutoUnblock")
        self._auto_unblock_thread = t
        t.start()

    def _auto_unblock_loop(self):
        while True:
            try:
                with self.app.app_context():
                    self._check_expired_blocks()
            except Exception as e:
                logger.error("[IPS] Auto-unblock sweep error: %s", e)
            time.sleep(AUTO_UNBLOCK_CHECK_INTERVAL)

    def _check_expired_blocks(self):
        if not self._expiry_field:
            return
        now = datetime.utcnow()
        active_blocks = self.BlockedIPModel.query.filter_by(active=True).all()
        for b in active_blocks:
            expires_at = getattr(b, self._expiry_field, None)
            if expires_at is not None and expires_at <= now:
                logger.info("[IPS] Temporary block expired for %s - auto-unblocking", b.ip_address)
                self.unblock_ip(b.ip_address)

    # ------------------------------------------------------------------
    # OPNsense API helpers
    # ------------------------------------------------------------------
    def _opnsense_auth(self):
        return (OPNSENSE_API_KEY, OPNSENSE_API_SECRET)

    def _add_to_opnsense_alias(self, ip):
        """
        Adds an IP to the alias content and applies the change.
        Uses the firewall_alias_util 'add' endpoint.
        """
        url = f"{OPNSENSE_HOST}/api/firewall/alias_util/add/{ALIAS_NAME}"
        resp = self._session.post(
            url,
            json={"address": ip},
            auth=self._opnsense_auth(),
            verify=VERIFY_TLS,
            timeout=10,
        )
        resp.raise_for_status()
        self._apply_changes()
        return resp.json().get("status", "ok")

    def _remove_from_opnsense_alias(self, ip):
        url = f"{OPNSENSE_HOST}/api/firewall/alias_util/delete/{ALIAS_NAME}"
        resp = self._session.post(
            url,
            json={"address": ip},
            auth=self._opnsense_auth(),
            verify=VERIFY_TLS,
            timeout=10,
        )
        resp.raise_for_status()
        self._apply_changes()

    def _apply_changes(self):
        """Reloads the OPNsense firewall filter so alias content changes
        actually take effect. Previously this response was never
        checked, so a failure here meant the alias was updated but the
        block/unblock was never actually enforced - and nobody knew."""
        url = f"{OPNSENSE_HOST}/api/firewall/filter/apply"
        resp = self._session.post(url, auth=self._opnsense_auth(), verify=VERIFY_TLS, timeout=10)
        resp.raise_for_status()
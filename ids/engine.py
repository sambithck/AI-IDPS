"""
ids/engine.py
"""
import json
import logging
import os
import threading
import time
from datetime import datetime
from feature_engine.aggregator import aggregator
from ml_model.predictor import get_predictor

logger = logging.getLogger("ai_idps.ids")

CHECK_INTERVAL       = 5
CONFIDENCE_THRESHOLD = 0.70

# IPs to never raise alerts for - typically the host machine's own LAN
# interface IP(s) plus loopback. Without this, the machine running the
# IDS talking to itself (browser <-> XAMPP, OS background chatter, etc.)
# can get misread as DoS-shaped packet rate by the ML model.
# Override via env var: IDS_IGNORED_IPS="192.168.1.31,10.0.0.5"
IGNORED_IPS = {
    ip.strip() for ip in os.environ.get("IDS_IGNORED_IPS", "127.0.0.1,::1").split(",") if ip.strip()
}

SEVERITY_MAP = {
    "Normal":            "info",
    "PortScan":          "medium",
    "DoS":               "critical",
    "BruteForce":        "high",
    "WebAttack":         "high",
    "SQL_INJECTION":     "high",
    "XSS":               "high",
    "XSS_REFLECTED":     "high",
    "XSS_STORED":        "critical",
    "COMMAND_INJECTION": "high",
    "LFI":               "high",
}

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
}

# Each rule-based signature carries its own base confidence. This is
# blended with the ML model's confidence for the same sweep instead of
# being a single hardcoded constant applied to every attack type.
RULE_BASE_CONFIDENCE = {
    "SQL_INJECTION":     0.93,
    "XSS":               0.90,
    "XSS_REFLECTED":     0.90,
    "XSS_STORED":        0.95,  # stored XSS is a stronger signal - it already persisted server-side
    "COMMAND_INJECTION": 0.92,
    "LFI":               0.88,
}

# Minimum keyword-hit count (from feature_engine's per-window counters)
# required before a rule fires. SQLi keywords ("select", "or 1=1", ...)
# can incidentally appear in ordinary traffic, so it keeps a stricter
# bar. XSS/CMD/LFI markers ("<script", "cmd=", "../", etc.) are
# unambiguous enough that a single occurrence is already a strong
# signal - DVWA's Reflected XSS and LFI tests are typically delivered
# in a single request, so requiring 2+ hits would silently miss them.
RULE_MIN_HITS = {
    "sql_keywords": 2,
    "xss_keywords": 1,
    "cmd_keywords": 1,
    "lfi_keywords": 1,
}

# Maps a feature-engine keyword counter to the specific attack type it
# signals. Order matters: checked top to bottom, first match wins.
# XSS is special-cased below using aggregator's xss_kind classification
# (reflected vs stored) instead of a flat "XSS" label.
RULE_TRIGGERS = [
    ("sql_keywords", "SQL_INJECTION"),
    ("xss_keywords", "XSS"),
    ("cmd_keywords", "COMMAND_INJECTION"),
    ("lfi_keywords", "LFI"),
]

# Alert-cooldown bookkeeping (self.last_alert) housekeeping: how long a
# cooldown entry is kept before being treated as stale, and how many
# sweeps pass between cleanup sweeps (amortized, mirrors the pattern in
# feature_engine/aggregator.py).
ALERT_COOLDOWN_SECONDS        = 30
ALERT_STALE_SECONDS           = 600  # drop cooldown entries idle 10+ min
ALERT_CLEANUP_EVERY_N_SWEEPS  = 60   # ~5 min at CHECK_INTERVAL=5s


class IDSEngine:
    def __init__(self, app, db, AlertModel, socketio, ips_engine=None):
        self.app        = app
        self.db         = db
        self.AlertModel = AlertModel
        self.socketio   = socketio
        self.ips_engine = ips_engine
        self.predictor  = get_predictor()
        self._running   = False
        self._thread    = None
        self.last_alert = {}
        # Guards read-check-write access to last_alert, since start()
        # being called twice (or stop() resetting it mid-sweep) would
        # otherwise race with the background sweep thread.
        self._alert_lock = threading.Lock()
        self._sweep_count = 0

    def start(self):
        # Idempotent: calling start() while already running used to spin
        # up a second _loop thread, and both threads would race on
        # last_alert - each seeing an empty cooldown slot and both firing
        # -> duplicate DB inserts + duplicate SocketIO emits for the same
        # detection. Guard against that here.
        if self._running:
            logger.warning("IDSEngine.start() called while already running; ignoring.")
            return self._thread
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        self._thread = t
        t.start()
        return t

    def stop(self):
        self._running = False
        with self._alert_lock:
            self.last_alert = {}

    def _loop(self):
        while self._running:
            try:
                with self.app.app_context():
                    self._sweep()
            except Exception as e:
                logger.error("Sweep error: %s", e)
            time.sleep(CHECK_INTERVAL)

    def _sweep(self):
        active = [ip for ip in aggregator.active_ips() if ip not in IGNORED_IPS]
        if active:
            logger.debug("Sweeping %d IPs", len(active))

        for ip in active:
            # Isolate failures per-IP: a bad predictor call or DB error
            # for one IP must not abort processing of the rest of the
            # active IPs in this sweep (previously it did, since the
            # exception would bubble all the way up to _loop's outer
            # try/except, silently skipping every remaining IP).
            try:
                self._process_ip(ip)
            except Exception as e:
                logger.error("Error processing IP %s during sweep: %s", ip, e)
                continue

        self._maybe_cleanup_alert_cooldowns()

    def _process_ip(self, ip):
        features = aggregator.get_features(ip)
        label, confidence, proba_vector = self.predictor.predict(features)

        # -----------------------------------------------------------
        # Rule-based Web Attack Detection
        # -----------------------------------------------------------
        # The ML model only knows the coarse classes it was trained on
        # (Normal / PortScan / DoS / BruteForce / WebAttack). These
        # keyword-count rules refine a "WebAttack"-shaped detection
        # into its specific subtype WITHOUT discarding the model's own
        # confidence signal - each subtype keeps its own identity and
        # a confidence that blends the rule's base score with however
        # confident the ML model already was about this sweep.
        rule_label = None
        for feature_key, attack_label in RULE_TRIGGERS:
            min_hits = RULE_MIN_HITS.get(feature_key, 2)
            if features.get(feature_key, 0) >= min_hits:
                rule_label = attack_label
                break

        # XSS gets refined further into REFLECTED vs STORED using the
        # aggregator's payload-recurrence heuristic: if this exact
        # payload was already seen before (any IP/path), it persisted
        # server-side -> STORED. First time seen -> REFLECTED.
        if rule_label == "XSS":
            xss_kind = features.get("xss_kind")
            rule_label = xss_kind if xss_kind in ("XSS_REFLECTED", "XSS_STORED") else "XSS"

        if rule_label is not None:
            label = rule_label
            ml_component   = proba_vector.get("WebAttack", confidence) if proba_vector else confidence
            rule_component = RULE_BASE_CONFIDENCE.get(rule_label, 0.85)
            # Weighted blend: rules are the stronger signal here since
            # they fired on explicit payload patterns, but the model's
            # own confidence still pulls the score up or down.
            confidence = round((0.6 * rule_component) + (0.4 * ml_component), 4)
        else:
            # Normalize precision here too, so the DB value for a
            # pure-ML detection isn't a raw unrounded float while the
            # rule-blended path stores a 4-decimal value - previously
            # the two paths disagreed on precision.
            confidence = round(confidence, 4)

        if label == "Normal" or confidence < CONFIDENCE_THRESHOLD:
            return

        self._raise_alert(ip, label, confidence, features, proba_vector)

    def _raise_alert(self, ip, label, confidence, features, proba_vector=None):
        now = time.time()
        key = (ip, label)

        with self._alert_lock:
            last_ts = self.last_alert.get(key)
            if last_ts is not None and now - last_ts < ALERT_COOLDOWN_SECONDS:
                return
            # Reserve the cooldown slot optimistically. If persisting the
            # alert below fails, we release this slot again so a DB
            # hiccup can't silently suppress the next real detection.
            self.last_alert[key] = now

        severity        = SEVERITY_MAP.get(label, "medium")
        mitre_technique = MITRE_MAP.get(label)

        try:
            alert = self.AlertModel(
                timestamp       = datetime.utcnow(),
                src_ip          = ip,
                dst_ip          = None,
                attack_type     = label,
                confidence      = confidence,
                severity        = severity,
                raw_features    = json.dumps(features),
                action_taken    = "none",
                mitre_technique = mitre_technique,
            )
            self.db.session.add(alert)
            self.db.session.commit()
        except Exception as e:
            # Roll back so the SQLAlchemy session isn't left poisoned -
            # an uncommitted/failed transaction here previously caused
            # every subsequent alert commit to fail too, silently
            # killing alerting until the process restarted.
            try:
                self.db.session.rollback()
            except Exception:
                pass
            with self._alert_lock:
                if self.last_alert.get(key) == now:
                    del self.last_alert[key]
            logger.error("Failed to persist alert (%s from %s): %s", label, ip, e)
            return

        payload = {
            "id":              alert.id,
            "timestamp":       alert.timestamp.isoformat(),
            "src_ip":          ip,
            "attack_type":     label,
            "confidence":      round(confidence, 3),
            "severity":        severity,
            "features":        features,
            "mitre_technique": mitre_technique,
            "proba_vector":    proba_vector,
        }
        try:
            self.socketio.emit("new_alert", payload, namespace="/live")
        except Exception as e:
            logger.error("Failed to emit new_alert over SocketIO for alert %s: %s", alert.id, e)

        logger.info("ALERT: %s from %s conf=%.2f severity=%s mitre=%s",
                    label, ip, confidence, severity, mitre_technique)

        if self.ips_engine and severity in ("high", "critical"):
            try:
                self.ips_engine.handle_alert(alert, ip)
            except Exception as e:
                logger.error("ips_engine.handle_alert failed for alert %s: %s", alert.id, e)

    def _maybe_cleanup_alert_cooldowns(self):
        """Amortized sweep that drops (ip, label) cooldown entries that
        have gone stale, so self.last_alert doesn't grow unbounded over
        a long-running process (e.g. every distinct IP seen during a
        port scan getting its own permanent entry)."""
        self._sweep_count += 1
        if self._sweep_count < ALERT_CLEANUP_EVERY_N_SWEEPS:
            return
        self._sweep_count = 0
        now = time.time()
        with self._alert_lock:
            stale_keys = [
                k for k, ts in self.last_alert.items()
                if now - ts > ALERT_STALE_SECONDS
            ]
            for k in stale_keys:
                del self.last_alert[k]
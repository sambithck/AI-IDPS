"""
feature_engine/aggregator.py
Consumes raw packets (from capture.sniffer.packet_queue) and web access
log entries and builds rolling, per-source-IP feature vectors over a
sliding time window.  These feature vectors feed the XGBoost model.
"""
import time
import logging
import threading
import hashlib
import re
import html
import urllib.parse
from collections import defaultdict, deque
logger = logging.getLogger("ai_idps.aggregator")
WINDOW_SECONDS = 10  # sliding window for rate calculations
# Window for the XSS reflected-vs-stored heuristic: if the *same* XSS
# payload is seen again later (from any IP/path) after first being
# recorded, it's treated as STORED (it persisted server-side and got
# served back out). If it's the first time we see that exact payload,
# it's treated as REFLECTED (a one-shot injection in the current
# request that hasn't shown up anywhere else yet).
XSS_STORED_WINDOW_SECONDS = 300
# How long an IP can sit idle (no packets/web/logins) before its
# tracking entries are dropped, to stop unbounded memory growth from
# one-off / spoofed source IPs (e.g. during a port scan).
STALE_IP_IDLE_SECONDS = WINDOW_SECONDS * 12
# How many writes between amortized stale-IP sweeps.
CLEANUP_EVERY_N_WRITES = 500
class FeatureAggregator:
    def __init__(self):
        # per-ip deque of (timestamp, packet_len, dst_port, flags, protocol)
        self._packets = defaultdict(deque)
        # per-ip deque of (timestamp, status_code, path, suspicious_score)
        self._web     = defaultdict(deque)
        # per-ip failed login counter within window
        self._failed_logins = defaultdict(deque)
        # global (cross-IP) tracker of XSS-looking payload hashes -> first
        # seen timestamp + source IP. Used to classify a new XSS hit as
        # REFLECTED (first time seen) vs STORED (payload seen again later,
        # implying it persisted server-side from an earlier request).
        self._xss_payload_seen = {}
        self._xss_lock = threading.Lock()
        self._lock = threading.Lock()
        # counter driving the amortized stale-IP cleanup sweep; only
        # touched while holding self._lock.
        self._write_count = 0
    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def add_packet(self, pkt):
        ip = pkt["src_ip"]
        # Flags can come back as non-string from the sniffer layer in
        # some edge cases (e.g. raw int bitmask); normalize to str so
        # the "S" in flags style checks in get_features() never raise.
        raw_flags = pkt.get("flags", "")
        flags = "" if raw_flags is None else str(raw_flags)
        with self._lock:
            dq = self._packets[ip]
            dq.append((
                pkt["timestamp"],
                pkt["packet_len"],
                pkt.get("dst_port"),
                flags,
                pkt.get("protocol", "")
            ))
            self._evict(dq)
            self._maybe_cleanup()
        #print("[PACKET]", pkt)
        #print("[ADD]", ip, "count =", len(dq))
    def add_web_request(
    self,
    ip,
    status_code,
    path,
    suspicious_score,
    method="",
    user_agent="",
    query=""
):
        xss_kind = self._classify_xss(path, query)
        with self._lock:
            dq = self._web[ip]
            dq.append((
    time.time(),
    status_code,
    path,
    suspicious_score,
    method,
    user_agent,
    query,
    xss_kind,
))
            self._evict(dq)
            self._maybe_cleanup()
         #   print("[AGGREGATOR] Added:", ip, path)
    XSS_PATTERN = re.compile(
        r"<script|javascript:|onerror=|onload=|onmouseover=|<svg|<img[^>]+src",
        re.IGNORECASE,
    )
    @staticmethod
    def _decode_payload(text):
        """Best-effort normalization of a URL path/query fragment so
        percent-encoded and HTML-entity-encoded payloads (%3Cscript%3E,
        &#60;script&#62;, double-encoded %2527, etc.) can't slip past
        the plain-text keyword/regex matches below. Safe no-op on
        already-plain text."""
        if not text:
            return ""
        decoded = text
        # unquote repeatedly to unwind double/triple percent-encoding;
        # stop as soon as a pass makes no further change.
        for _ in range(3):
            new_decoded = urllib.parse.unquote_plus(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        decoded = html.unescape(decoded)
        return decoded
    def _classify_xss(self, path, query):
        """Look at a single request's path+query and, if it contains an
        XSS-looking payload, classify it as REFLECTED (first time this
        exact payload has been seen anywhere) or STORED (this exact
        payload was already seen before, implying it persisted
        server-side and is now being served back out)."""
        text = self._decode_payload((path or "") + " " + (query or ""))
        match = self.XSS_PATTERN.search(text)
        if not match:
            return None
        # Hash only the actual payload substring (not the surrounding
        # path), so the same injected script is recognized as the same
        # payload even when it shows up under a different path or from a
        # different IP later on - which is exactly the "stored" signal.
        payload_text = text[match.start():match.start() + 200].lower()
        payload_hash = hashlib.sha256(payload_text.encode("utf-8", "ignore")).hexdigest()
        now = time.time()
        with self._xss_lock:
            # prune stale entries
            stale = [h for h, ts in self._xss_payload_seen.items() if now - ts > XSS_STORED_WINDOW_SECONDS]
            for h in stale:
                del self._xss_payload_seen[h]
            if payload_hash in self._xss_payload_seen:
                return "XSS_STORED"
            self._xss_payload_seen[payload_hash] = now
            return "XSS_REFLECTED"
    def add_failed_login(self, ip):
        """Call this from auth middleware on 401 responses."""
        with self._lock:
            dq = self._failed_logins[ip]
            dq.append(time.time())
            self._evict_ts(dq)
            self._maybe_cleanup()
    @staticmethod
    def _evict(dq, now=None):
        now = now or time.time()
        while dq and now - dq[0][0] > WINDOW_SECONDS:
            dq.popleft()
    @staticmethod
    def _evict_ts(dq, now=None):
        now = now or time.time()
        while dq and now - dq[0] > WINDOW_SECONDS:
            dq.popleft()
    def _maybe_cleanup(self):
        """Amortized sweep that drops tracking entries for IPs that have
        gone quiet, so long-running processes don't accumulate one dict
        entry per IP ever seen (e.g. every source IP touched during a
        port scan). MUST be called while holding self._lock."""
        self._write_count += 1
        if self._write_count < CLEANUP_EVERY_N_WRITES:
            return
        self._write_count = 0
        now = time.time()
        for store in (self._packets, self._web):
            stale_ips = [
                ip for ip, dq in store.items()
                if not dq or now - dq[-1][0] > STALE_IP_IDLE_SECONDS
            ]
            for ip in stale_ips:
                del store[ip]
        stale_login_ips = [
            ip for ip, dq in self._failed_logins.items()
            if not dq or now - dq[-1] > STALE_IP_IDLE_SECONDS
        ]
        for ip in stale_login_ips:
            del self._failed_logins[ip]
    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------
    def get_features(self, ip):
        """Return a flat feature dict for a given source IP."""
        now = time.time()
        with self._lock:
            pkts  = list(self._packets.get(ip, []))
            web   = list(self._web.get(ip, []))
            fl_ts = list(self._failed_logins.get(ip, []))
        pkts  = [p for p in pkts  if now - p[0] <= WINDOW_SECONDS]
        web   = [w for w in web   if now - w[0] <= WINDOW_SECONDS]
        fl_ts = [t for t in fl_ts if now - t    <= WINDOW_SECONDS]
        # Use the actual elapsed time covered by the data we have,
        # rather than always dividing by the full WINDOW_SECONDS. A
        # burst that only started 1-2s ago would otherwise get diluted
        # into an artificially low rate (e.g. a 2-second SYN flood
        # reporting at 1/5th its real rate), delaying detection.
        # Floored at 0.5s so a single fresh packet doesn't spike the
        # rate toward infinity.
        pkt_elapsed = min(WINDOW_SECONDS, now - pkts[0][0]) if pkts else WINDOW_SECONDS
        pkt_elapsed = max(pkt_elapsed, 0.5)
        web_elapsed = min(WINDOW_SECONDS, now - web[0][0]) if web else WINDOW_SECONDS
        web_elapsed = max(web_elapsed, 0.5)
        fl_elapsed = min(WINDOW_SECONDS, now - fl_ts[0]) if fl_ts else WINDOW_SECONDS
        fl_elapsed = max(fl_elapsed, 0.5)
        packet_count = len(pkts)
        byte_total   = sum(p[1] for p in pkts)
        unique_ports = len(set(p[2] for p in pkts if p[2] is not None))
        syn_count  = sum(1 for p in pkts if "S" in (p[3] or "") and "A" not in (p[3] or ""))
        icmp_count = sum(1 for p in pkts if p[4] == "ICMP")
        udp_count  = sum(1 for p in pkts if p[4] == "UDP")
        fin_count  = sum(1 for p in pkts if "F" in (p[3] or ""))
        null_count = sum(1 for p in pkts if p[3] == "" or p[3] == "0")
        xmas_count = sum(1 for p in pkts if all(f in (p[3] or "") for f in ["F", "P", "U"]))
        request_count    = len(web)
        error_count      = sum(1 for w in web if w[1] >= 400)
        avg_suspicious   = (sum(w[3] for w in web) / request_count) if request_count else 0.0
        failed_login_cnt = len(fl_ts)
        sql_keywords = 0
        xss_keywords = 0
        cmd_keywords = 0
        lfi_keywords = 0
        request_length = 0
        user_agent_entropy = 0
        sql_patterns = [
            "union",
            "select",
            "or 1=1",
            "--",
            "sleep(",
            "benchmark("
        ]
        xss_patterns = [
            "<script",
            "javascript:",
            "onerror="
        ]
        cmd_patterns = [
            "cmd=",
            "powershell",
            "whoami",
            "cat ",
            "dir "
        ]
        lfi_patterns = [
            "../",
            "..\\",
            "/etc/passwd",
            "boot.ini"
        ]
        # Decode each web entry's path/query exactly once up front (both
        # for admin-path detection and the keyword scoring loop below),
        # so percent-encoded / HTML-entity-encoded payloads (e.g.
        # "/%61dmin", "%27%20or%201=1") are matched the same as their
        # plain-text form instead of silently bypassing detection.
        decoded_web = []
        for w in web:
            d_path  = self._decode_payload(w[2] or "").lower()
            d_query = self._decode_payload(w[6] or "").lower()
            decoded_web.append((w, d_path, d_query))
        admin_path_hits = sum(
            1 for (_w, d_path, _d_query) in decoded_web
            if any(seg in d_path for seg in ["/admin", "/login", "/wp-admin", "/phpmyadmin"])
        )
        xss_kind_latest = None
        for w, path, query in decoded_web:
            ua = (w[5] or "").lower()
            text = path + " " + query
            request_length += len(text)
            sql_keywords += sum(k in text for k in sql_patterns)
            xss_keywords += sum(k in text for k in xss_patterns)
            cmd_keywords += sum(k in text for k in cmd_patterns)
            lfi_keywords += sum(k in text for k in lfi_patterns)
            user_agent_entropy += len(set(ua))
            kind = w[7] if len(w) > 7 else None
            if kind:
                xss_kind_latest = kind
     #   print(
    #"[FEATURES]",
   # ip,
   # "SQL =", sql_keywords,
   # "XSS =", xss_keywords,
   # "CMD =", cmd_keywords,
    #"LFI =", lfi_keywords
#)
        return {
            "packet_rate": packet_count / pkt_elapsed,
            "byte_rate": byte_total / pkt_elapsed,
            "unique_ports": unique_ports,
            "syn_rate": syn_count / pkt_elapsed,
            "icmp_rate": icmp_count / pkt_elapsed,
            "udp_rate": udp_count / pkt_elapsed,
            "fin_rate": fin_count / pkt_elapsed,
            "null_rate": null_count / pkt_elapsed,
            "xmas_rate": xmas_count / pkt_elapsed,
            "request_rate": request_count / web_elapsed,
            "error_rate": (error_count / request_count) if request_count else 0.0,
            "failed_login_rate": failed_login_cnt / fl_elapsed,
            "admin_path_hits": admin_path_hits,
            "suspicious_pattern_score": avg_suspicious,
            "sql_keywords": sql_keywords,
            "xss_keywords": xss_keywords,
            "cmd_keywords": cmd_keywords,
            "lfi_keywords": lfi_keywords,
            "xss_kind": xss_kind_latest,  # "XSS_REFLECTED" / "XSS_STORED" / None
            "request_length": request_length,
            "user_agent_entropy": user_agent_entropy,
        }
    def active_ips(self):
      now = time.time()
      with self._lock:
        active = set()
        for ip, dq in self._packets.items():
            if dq and now - dq[-1][0] <= WINDOW_SECONDS:
                active.add(ip)
        for ip, dq in self._web.items():
            if dq and now - dq[-1][0] <= WINDOW_SECONDS:
                active.add(ip)
        return active
aggregator = FeatureAggregator()
def packet_consumer_loop(packet_queue):
    """Background thread: pulls packets off the sniffer queue."""
    while True:
        pkt = packet_queue.get()
        try:
            aggregator.add_packet(pkt)
        except Exception as e:
            logger.warning("Error processing packet: %s", e)
def start_packet_consumer(packet_queue):
    t = threading.Thread(target=packet_consumer_loop, args=(packet_queue,), daemon=True)
    t.start()
    return t
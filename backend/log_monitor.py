"""
backend/log_monitor.py
Tails the Apache access.log and feeds parsed web requests into the
feature aggregator for rule-based + ML detection.
"""
import os
import time
import threading
import logging
import re
import html
from urllib.parse import unquote, unquote_plus
from feature_engine.aggregator import aggregator

logger = logging.getLogger(__name__)

LOG_PATH_DEFAULT = r"C:\xampp\apache\logs\access.log"

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
)

SQL_INJECTION_PATTERNS = [
    "union",
    "select",
    "sleep(",
    "benchmark(",
    "or 1=1",
    "--",
]
XSS_PATTERNS = [
    "<script",
    "onerror=",
    "javascript:",
]
TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
]
ADMIN_PATHS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
]

# Safety cap on a single log line's length before we run regex/decode
# work on it. Apache's own default LimitRequestLine is 8190 bytes, so
# genuine request paths never approach this - it only guards against a
# pathologically long or malformed line burning CPU/memory.
MAX_LINE_LENGTH = 8192

# Adaptive idle-polling bounds: back off gradually while the log is
# quiet (reduces CPU wakeups), reset to the minimum the instant new
# lines start flowing again (keeps detection effectively real-time).
IDLE_SLEEP_MIN = 0.05
IDLE_SLEEP_MAX = 1.0
IDLE_SLEEP_GROWTH = 1.5


class ApacheLogMonitor:
    def __init__(self, log_path=LOG_PATH_DEFAULT):
        self.log_path = log_path
        self._running = False
        self._thread = None
        logger.info("Loaded Apache log monitor")

    def start(self):
        # Idempotent: calling start() twice used to spin up a second
        # _monitor thread tailing the same file. Both threads would
        # independently seek to EOF and then both pick up every
        # subsequent line, so every real request got processed (and
        # alerted on) twice.
        if self._running:
            logger.warning("ApacheLogMonitor.start() called while already running; ignoring.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor,
            daemon=True,
            name="ApacheLogMonitor"
        )
        self._thread.start()
        logger.info("Watching: %s", self.log_path)

    def stop(self):
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    @staticmethod
    def _decode_payload(text):
        """Iteratively percent-decode (unwinds double/triple URL-encoding
        such as %253Cscript%253E used to smuggle a payload past a single
        decode pass) and unescape HTML entities. unquote_plus (not
        unquote) is used because query strings conventionally encode
        spaces as '+', and that's routinely used to break up multi-word
        signatures like "or 1=1" (sent as "or+1=1") past a check that
        only decodes %20."""
        if not text:
            return ""
        decoded = text
        for _ in range(3):
            new_decoded = unquote_plus(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        decoded = html.unescape(decoded)
        return decoded

    def _monitor(self):
        file_handle = None
        last_ino = None
        idle_sleep = IDLE_SLEEP_MIN
        try:
            while self._running:
                try:
                    if not os.path.exists(self.log_path):
                        if file_handle is not None:
                            file_handle.close()
                            file_handle = None
                            last_ino = None
                        time.sleep(2)
                        continue

                    if file_handle is None:
                        file_handle = open(self.log_path, "r", encoding="utf-8", errors="replace")
                        file_handle.seek(0, 2)  # tail from end on (re)open
                        try:
                            st = os.fstat(file_handle.fileno())
                            last_ino = getattr(st, "st_ino", None) or None
                        except OSError:
                            last_ino = None

                    line = file_handle.readline()

                    if not line:
                        # EOF is the natural point to check whether Apache
                        # rotated/truncated the log out from under us -
                        # rotation typically happens between write bursts,
                        # not mid-line.
                        try:
                            st = os.stat(self.log_path)
                            current_ino = getattr(st, "st_ino", None) or None
                            rotated = (
                                (last_ino is not None and current_ino is not None and current_ino != last_ino)
                                or st.st_size < file_handle.tell()
                            )
                            if rotated:
                                logger.info(
                                    "Apache log rotation/truncation detected for %s - reopening",
                                    self.log_path
                                )
                                try:
                                    file_handle.close()
                                except Exception:
                                    pass
                                file_handle = open(self.log_path, "r", encoding="utf-8", errors="replace")
                                file_handle.seek(0)  # new/truncated file - read from the start
                                try:
                                    fst = os.fstat(file_handle.fileno())
                                    last_ino = getattr(fst, "st_ino", None) or None
                                except OSError:
                                    last_ino = None
                                idle_sleep = IDLE_SLEEP_MIN
                                continue
                        except OSError:
                            pass
                        time.sleep(idle_sleep)
                        idle_sleep = min(idle_sleep * IDLE_SLEEP_GROWTH, IDLE_SLEEP_MAX)
                        continue

                    idle_sleep = IDLE_SLEEP_MIN

                    line = line.rstrip("\n").rstrip("\r")
                    if not line:
                        continue
                    if len(line) > MAX_LINE_LENGTH:
                        line = line[:MAX_LINE_LENGTH]

                    parsed = self._parse_line(line)
                    if parsed:
                        self._process_request(parsed)
                    else:
                        logger.debug("Unparsed Apache log line (skipped): %.200s", line)
                except Exception as exc:
                    logger.error("Error in monitor loop: %s", exc)
                    if file_handle is not None:
                        try:
                            file_handle.close()
                        except Exception:
                            pass
                        file_handle = None
                        last_ino = None
                    time.sleep(2)
        finally:
            if file_handle is not None:
                try:
                    file_handle.close()
                except Exception:
                    pass

    def _parse_line(self, line):
        match = COMBINED_LOG_PATTERN.match(line)
        if not match:
            return None
        try:
            size_raw = match.group("size")
            size = int(size_raw) if size_raw != "-" else 0
            return {
                "ip": match.group("ip"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "path": match.group("path"),
                "raw": line,
                "status": int(match.group("status")),
                "size": size,
                "useragent": match.group("useragent") or "",
            }
        except Exception as exc:
            logger.debug("Failed to parse matched log line fields: %s (line=%.200s)", exc, line)
            return None

    def _calculate_score(self, path, status):
        # CRITICAL: browsers/Apache log paths URL-encoded
        # (e.g. "<script>" becomes "%3Cscript%3E"). Without decoding here,
        # every pattern check below silently never matches real attack
        # traffic - this was why DVWA attacks weren't being detected at
        # all even though the log lines were being read correctly.
        # _decode_payload also unwinds double/triple encoding and HTML
        # entities, and treats "+" as a space (common query encoding),
        # all of which a single unquote() pass used to miss.
        path_decoded = self._decode_payload(path)
        score = 0
        path_lower = path_decoded.lower()
        for pattern in SQL_INJECTION_PATTERNS:
            if pattern in path_lower:
                score += 20
                break
        for pattern in XSS_PATTERNS:
            if pattern in path_lower:
                score += 20
                break
        for pattern in TRAVERSAL_PATTERNS:
            if pattern in path_lower:
                score += 20
                break
        for admin_path in ADMIN_PATHS:
            if path_lower.startswith(admin_path):
                score += 5
                break
        if status == 401:
            score += 10
        elif status == 403:
            score += 20
        elif status == 500:
            score += 25
        return min(score, 100)

    def _process_request(self, parsed):
        ip = parsed["ip"]
        status = parsed["status"]
        path = parsed["path"]
        method = parsed["method"]
        suspicious_score = self._calculate_score(path, status)
        if suspicious_score >= 50:
            logger.warning(
                "[WEB ATTACK] %s %s %s score=%d",
                ip, method, path, suspicious_score
            )
        try:
            # Pass the fully decoded path/query into the aggregator so its
            # own sql/xss/cmd/lfi pattern matching (which also looks for
            # plain-text patterns like "<script" or "union") can actually
            # see the real payload instead of its percent-/entity-encoded
            # form.
            decoded_path = self._decode_payload(path)
            aggregator.add_web_request(
                ip=ip,
                status_code=status,
                path=decoded_path,
                suspicious_score=suspicious_score,
                method=method,
                user_agent=parsed.get("useragent", ""),
                query="",  # Apache's logged request target already includes
                           # the query string as part of `path` - passing it
                           # again here would double-count keyword matches.
            )
        except Exception as exc:
            logger.error("Failed to add web request to aggregator: %s", exc)
        if status == 401:
            try:
                aggregator.add_failed_login(ip)
            except Exception as exc:
                logger.error("Failed to add failed login to aggregator: %s", exc)
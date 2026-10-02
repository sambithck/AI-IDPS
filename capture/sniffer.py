"""
capture/sniffer.py

Captures live network traffic using Scapy (requires Npcap on Windows).
Pushes parsed packet info into a thread-safe queue that the feature
engineering layer consumes.

Run as Administrator on Windows so Npcap can open raw sockets.
"""

import logging
import queue
import threading
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply

logger = logging.getLogger("ai_idps.capture")

# Shared queue consumed by feature_engine/aggregator.py
packet_queue = queue.Queue(maxsize=50000)

# Rate-limits how often we log "queue full, dropping packets" so that a
# genuine flood attack (exactly when drops are most likely) doesn't
# turn into a logging-induced CPU spike of its own.
_drop_log_lock = threading.Lock()
_dropped_since_log = 0
_last_drop_log_time = 0.0


def _parse_packet(pkt):
    is_v6 = False
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        is_v6 = True
    else:
        return None

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Loopback filtering: host-to-self traffic (127.0.0.0/8 for IPv4,
    # ::1 for IPv6) is internal service chatter, not attacker<->target
    # traffic, so it's excluded from network-level flood/scan features.
    if src_ip.startswith("127.") or dst_ip.startswith("127."):
        return None
    if src_ip == "::1" or dst_ip == "::1":
        return None

    proto = "OTHER"
    src_port = dst_port = None
    flags = ""

    try:
        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        elif is_v6 and (ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt):
            proto = "ICMP"
    except Exception as exc:
        # A malformed/truncated packet can raise while Scapy tries to
        # dissect a sub-layer field (corrupted TCP header, etc). Don't
        # lose the packet entirely (it may still be flood-relevant by
        # length alone) and don't let this escape into the sniff()
        # callback - just fall back to an OTHER-protocol packet.
        logger.debug("Failed to parse transport layer for packet: %s", exc)
        proto = "OTHER"
        src_port = dst_port = None
        flags = ""

    # Prefer the IP header's own declared length over Scapy's len(pkt),
    # which also folds in L2 framing (Ethernet header, short-frame FCS
    # padding) and varies by interface type - that inconsistency was
    # skewing byte_rate/byte_total features depending on which NIC/
    # loopback adapter captured the packet.
    try:
        if not is_v6 and getattr(ip_layer, "len", None):
            packet_len = int(ip_layer.len)
        elif is_v6 and getattr(ip_layer, "plen", None) is not None:
            # IPv6's fixed 40-byte header isn't included in plen.
            packet_len = int(ip_layer.plen) + 40
        else:
            packet_len = len(pkt)
    except Exception:
        packet_len = len(pkt)

    # pkt.time is the timestamp Npcap/libpcap attached at actual capture
    # time. time.time() here would instead reflect whenever Python got
    # around to running this callback - which lags further behind
    # exactly under the high packet-rate conditions (floods) where
    # accurate relative timing matters most for the sliding-window rate
    # features.
    try:
        ts = float(pkt.time)
    except Exception:
        ts = time.time()

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "packet_len": packet_len,
        "flags": flags,
    }


def _note_drop():
    """Track and rate-limit logging of queue-full drop events."""
    global _dropped_since_log, _last_drop_log_time
    with _drop_log_lock:
        _dropped_since_log += 1
        now = time.time()
        if now - _last_drop_log_time >= 1.0:
            logger.warning(
                "Packet queue saturated - dropped %d packet(s) in the last interval",
                _dropped_since_log
            )
            _dropped_since_log = 0
            _last_drop_log_time = now


def _on_packet(pkt):
    try:
        data = _parse_packet(pkt)
    except Exception as exc:
        # Never let a parsing failure on one packet propagate back into
        # Scapy's sniff() loop - depending on Scapy version an
        # exception raised inside prn can silently kill the entire
        # capture thread.
        logger.debug("Dropping unparseable packet: %s", exc)
        return

    if data is None:
        return

    try:
        packet_queue.put_nowait(data)
        return
    except queue.Full:
        pass

    # Queue saturated - most likely a real flood attack is in progress,
    # which is exactly when capture must keep working. Drop the oldest
    # queued packet to make room rather than blocking the capture
    # thread or discarding the newest (most relevant) data.
    try:
        packet_queue.get_nowait()
    except queue.Empty:
        pass
    try:
        packet_queue.put_nowait(data)
    except queue.Full:
        # Another producer/consumer raced us for the freed slot; just
        # drop this packet rather than raising back into sniff().
        pass

    _note_drop()


def start_sniffer(iface=None):

    def _run():
        backoff = 1.0
        max_backoff = 30.0

        while True:
            start_ts = time.time()

            try:
                logger.info(
                    "Starting Npcap/Scapy sniffer on iface=%s",
                    iface or "default"
                )

                sniff(
                    iface=iface,
                    prn=_on_packet,
                    store=False,
                    filter="ip or ip6",
                )

                logger.warning(
                    "Sniffer stopped unexpectedly (iface=%s); restarting",
                    iface or "default"
                )

            except Exception as exc:
                logger.exception(
                    "Sniffer crashed (iface=%s): %s",
                    iface or "default",
                    exc,
                )

            if time.time() - start_ts > 60:
                backoff = 1.0

            logger.info("Restarting sniffer in %.1fs", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t

    def _run():
        backoff = 1.0
        max_backoff = 30.0
        while True:
            start_ts = time.time()
            try:
                logger.info("Starting Npcap/Scapy sniffer on iface=%s", iface or "default")
                sniff(
                    iface=iface,
                    prn=_on_packet,
                    store=False,
                    filter="ip or ip6"
                )
                logger.warning(
                    "Sniffer stopped unexpectedly (iface=%s); restarting",
                    iface or "default"
                )
            except Exception as exc:
                logger.error("Sniffer crashed (iface=%s): %s", iface or "default", exc)

            # A sniffer that ran stably for a while before failing gets
            # its backoff reset, so a rare one-off hiccup doesn't leave
            # us stuck at the slow end of the backoff curve. A sniffer
            # that keeps crashing immediately (e.g. bad iface name)
            # keeps growing its backoff up to the cap.
            if time.time() - start_ts > 60:
                backoff = 1.0

            logger.info("Restarting sniffer in %.1fs", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_sniffer()
    while True:
        time.sleep(1)
       # print(f"[Capture] queue size: {packet_queue.qsize()}")
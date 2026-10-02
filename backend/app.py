"""
backend/app.py
"""
# ---------------------------------------------------------------------------
# eventlet MUST monkey-patch the standard library before anything else
# imports socket/threading/select/ssl/time - including `logging`, `sys`
# path setup, Flask, and every project module below. This app runs
# Flask-SocketIO with async_mode="eventlet" *and* spins up several plain
# threading.Thread-based background workers (packet sniffer, IDS engine,
# Apache log monitor). Without an early monkey_patch(), eventlet's
# cooperative event loop and those real OS threads fight over blocking
# I/O - the previous code never called monkey_patch() at all, which is a
# classic cause of the dashboard hanging or the capture pipeline silently
# stalling under load. If eventlet isn't installed, fall back to
# SocketIO's "threading" async mode instead of crashing at import time.
# Windows test mode
_SOCKETIO_ASYNC_MODE = "threading"

import os
import sys
import signal
import threading
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if _SOCKETIO_ASYNC_MODE == "threading":
    logging.getLogger("ai_idps").warning(
        "eventlet is not installed; falling back to SocketIO "
        "async_mode='threading'. Install eventlet for production use."
    )


def _log_thread_exception(args):
    """Uncaught exceptions in background threads (sniffer, IDS engine,
    Apache log monitor, ...) previously vanished silently - the thread
    just died and nothing was logged. This makes every thread crash
    visible instead of showing up only as "the feature stopped working"."""
    logging.getLogger("ai_idps.thread").error(
        "Unhandled exception in thread %r: %s",
        args.thread.name if args.thread else "unknown",
        args.exc_value,
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


threading.excepthook = _log_thread_exception

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, redirect, url_for
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_cors import CORS

from backend.config import Config
from db.models import db, Alert, BlockedIP
from backend.auth import auth_bp, create_default_admin
from backend.api import api_bp, limiter
from backend.test_site import test_site_bp
from capture.sniffer import start_sniffer, packet_queue
from feature_engine.aggregator import start_packet_consumer
from ids.engine import IDSEngine
from backend.log_monitor import ApacheLogMonitor
from ips.engine import IPSEngine

logger = logging.getLogger("ai_idps")


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "static"),
    )
    app.config.from_object(Config)

    db.init_app(app)
    JWTManager(app)

    cors_origins = app.config.get("CORS_ORIGINS", "*")
    CORS(app, origins=cors_origins, supports_credentials=True)

    limiter.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(test_site_bp)

    # Previously hardcoded to "*" here regardless of CORS_ORIGINS, so the
    # REST API enforced an origin allowlist while the WebSocket channel
    # (which streams the same live traffic/alert data) accepted any
    # origin - an inconsistent policy that undermined the REST
    # restriction. Reuse the same configured origins for both.
    socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins=cors_origins,
    logger=True,
    engineio_logger=True,
)

    @app.route("/")
    def index():
        return redirect(url_for("login_page"))

    @app.route("/login")
    def login_page():
        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard_page1():
        return render_template("page1_live.html")

    @app.route("/dashboard/analytics")
    def dashboard_page2():
        return render_template("page2_analytics.html")

    @app.route("/dashboard/forensics")
    def dashboard_page3():
        return render_template("page3_forensics.html")

    @socketio.on("connect", namespace="/live")
    def handle_connect():
        logging.getLogger("ai_idps.ws").info("WebSocket client connected")

    @socketio.on("disconnect", namespace="/live")
    def handle_disconnect():
        logging.getLogger("ai_idps.ws").info("WebSocket client disconnected")

    return app, socketio


def bootstrap_engines(app, socketio):
    boot_logger = logging.getLogger("ai_idps.bootstrap")
    with app.app_context():
        # --- 9. Create database tables -----------------------------------
        # Fatal if this fails: nothing else in the app can function
        # without a database, so fail loudly and immediately rather than
        # limping into a broken half-started state.
        try:
            db.create_all()
            boot_logger.info("Database tables ready.")
        except Exception as e:
            boot_logger.critical("Database initialization failed: %s", e)
            raise

        # --- 10. Create default admin --------------------------------------
        # create_default_admin() already handles its own DB errors
        # internally (see backend/auth.py) and never raises for the
        # expected "admin already exists" / race-condition case. This is
        # just a last-resort guard against a genuinely unexpected failure
        # so it can't take the whole app down before it ever serves a
        # login page.
        try:
            create_default_admin()
        except Exception as e:
            boot_logger.error("create_default_admin() failed unexpectedly: %s", e)

        # --- 11. Initialize IPS ---------------------------------------------
        # Fatal: IDS engine below depends on a working ips_engine reference.
        try:
            ips_engine = IPSEngine(
                db, BlockedIP, socketio,
                dry_run=app.config.get("IPS_DRY_RUN", True),
                block_thresholds=app.config.get("IPS_BLOCK_THRESHOLDS"),
            )
            app.config["IPS_ENGINE"] = ips_engine
            boot_logger.info("IPS engine initialized (dry_run=%s).", ips_engine.dry_run)
        except Exception as e:
            boot_logger.critical("IPS engine initialization failed: %s", e)
            raise

        # --- 12. Initialize IDS ---------------------------------------------
        try:
            ids_engine = IDSEngine(app, db, Alert, socketio, ips_engine=ips_engine)
            # Previously this was a local variable only - nothing outside
            # this function could ever reference it again, which made a
            # graceful shutdown of the IDS engine impossible. Store it the
            # same way ips_engine already was.
            app.config["IDS_ENGINE"] = ids_engine
            boot_logger.info("IDS engine initialized.")
        except Exception as e:
            boot_logger.critical("IDS engine initialization failed: %s", e)
            raise

        # --- 13. Start packet sniffer ---------------------------------------
        # Non-fatal: on a box without capture privileges (or Npcap missing
        # on Windows), the dashboard, REST API, and Apache-log-based
        # detection should still come up rather than the whole process
        # dying because raw packet capture couldn't start.
        try:
            start_sniffer(iface=app.config.get("CAPTURE_IFACE"))
            boot_logger.info(
                "Packet sniffer started (iface=%s).",
                app.config.get("CAPTURE_IFACE") or "default",
            )
        except Exception as e:
            boot_logger.error(
                "Packet sniffer failed to start (%s). Continuing without live "
                "packet capture - the dashboard, API, and Apache-log-based "
                "detection will still work. On Windows this usually means "
                "Npcap is not installed or the process lacks admin rights; "
                "on Linux it usually means missing CAP_NET_RAW.",
                e,
            )

        # --- 14. Start aggregator consumer -----------------------------------
        try:
            print("DEBUG-1"); start_packet_consumer(packet_queue); print("DEBUG-2")
            boot_logger.info("Packet aggregator consumer started.")
        except Exception as e:
            boot_logger.error("Packet aggregator failed to start: %s", e)

        # --- 15. Start IDS thread --------------------------------------------
        # Fatal: this is the core detection loop; if it can't start there's
        # no point continuing.
        try:
            print("DEBUG-3"); ids_engine.start(); print("DEBUG-4")
            boot_logger.info("IDS engine thread started.")
        except Exception as e:
            boot_logger.critical("IDS engine failed to start: %s", e)
            raise

        # --- 16. Start Apache log monitor -------------------------------------
        # Non-fatal: a missing/unreadable Apache log shouldn't take down
        # packet-based detection, which is already running at this point.
        try:
            log_monitor = ApacheLogMonitor(app.config["APACHE_ACCESS_LOG"])
            print("DEBUG-5"); log_monitor.start(); print("DEBUG-6")
            app.config["LOG_MONITOR"] = log_monitor
            boot_logger.info("Apache log monitor started (%s).", app.config["APACHE_ACCESS_LOG"])
        except Exception as e:
            boot_logger.error(
                "Apache log monitor failed to start (%s). Continuing without "
                "web-log-based detection.", e,
            )

        boot_logger.info(
            "IDPS engines started. IPS dry-run=%s",
            ips_engine.dry_run,
        )


def _try_stop(name, obj, method_names=("stop", "shutdown", "close")):
    """Best-effort stop of a single component. Missing stop methods and
    exceptions during shutdown are both logged and swallowed here so one
    component failing to stop cleanly can never prevent the rest of
    shutdown from proceeding."""
    stop_logger = logging.getLogger("ai_idps.shutdown")
    if obj is None:
        return
    for method_name in method_names:
        fn = getattr(obj, method_name, None)
        if callable(fn):
            try:
                fn()
                stop_logger.info("%s stopped.", name)
            except Exception as e:
                stop_logger.error("Error stopping %s: %s", name, e)
            return
    stop_logger.debug("%s exposes no stop/shutdown/close method; skipping.", name)


def _graceful_shutdown(app):
    """Best-effort, idempotent shutdown of every background subsystem plus
    the database connection. Safe to call more than once (e.g. once from a
    signal handler and once from main()'s finally block)."""
    stop_logger = logging.getLogger("ai_idps.shutdown")
    if getattr(app, "_idps_shutdown_done", False):
        return
    app._idps_shutdown_done = True
    stop_logger.info("Shutting down AI-IDPS...")

    # Stop capture first so nothing new enters the pipeline behind the
    # components we're about to stop downstream of it.
    try:
        import capture.sniffer as sniffer_module
        _try_stop("Packet sniffer", sniffer_module, method_names=("stop_sniffer", "stop", "shutdown"))
    except Exception as e:
        stop_logger.error("Error accessing capture.sniffer during shutdown: %s", e)

    try:
        import feature_engine.aggregator as aggregator_module
        _try_stop(
            "Packet aggregator", aggregator_module,
            method_names=("stop_packet_consumer", "stop", "shutdown"),
        )
    except Exception as e:
        stop_logger.error("Error accessing feature_engine.aggregator during shutdown: %s", e)

    _try_stop("IDS engine", app.config.get("IDS_ENGINE"))
    _try_stop("IPS engine", app.config.get("IPS_ENGINE"))
    _try_stop("Apache log monitor", app.config.get("LOG_MONITOR"))

    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        stop_logger.info("Database connections closed.")
    except Exception as e:
        stop_logger.error("Error closing database: %s", e)

    stop_logger.info("Shutdown complete.")


def _install_signal_handlers(app):
    """Register SIGINT/SIGTERM handlers where the platform supports them.
    Signal handlers can only be installed from the main thread, and
    SIGTERM doesn't exist as a deliverable signal on Windows - both cases
    are guarded so this never raises during startup."""
    sig_logger = logging.getLogger("ai_idps.shutdown")

    def _handler(signum, frame):
        sig_logger.info("Received signal %s, shutting down...", signum)
        _graceful_shutdown(app)
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError, AttributeError):
        sig_logger.debug("Could not install SIGINT handler (not in main thread?).")

    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError, AttributeError):
            sig_logger.debug("Could not install SIGTERM handler.")


def main():
    print("STEP 1")

    app, socketio = create_app()

    print("STEP 2")

    bootstrap_engines(app, socketio)

    print("STEP 3")

    _install_signal_handlers(app)

    print("STEP 4")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )

    print("STEP 5")


if __name__ == "__main__":
    main()

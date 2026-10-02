import os
import sys
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_SECRET = "change-this-secret-key"
_DEFAULT_JWT    = "change-this-jwt-secret"


def _current_env():
    return os.environ.get("FLASK_ENV", os.environ.get("ENV", "development")).lower()


def _warn_insecure():
    secret  = os.environ.get("SECRET_KEY", _DEFAULT_SECRET)
    jwt_sec = os.environ.get("JWT_SECRET_KEY", _DEFAULT_JWT)
    issues  = []
    if secret == _DEFAULT_SECRET:
        issues.append("SECRET_KEY is using the insecure default value")
    if jwt_sec == _DEFAULT_JWT:
        issues.append("JWT_SECRET_KEY is using the insecure default value")
    if issues:
        print("\n" + "=" * 60, file=sys.stderr)
        print("  WARNING - SECURITY - AI-IDPS", file=sys.stderr)
        for i in issues:
            print(f"  - {i}", file=sys.stderr)
        print("  Set SECRET_KEY and JWT_SECRET_KEY in your .env file", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)


def _validate_production_secrets():
    """Refuse to boot in production with a default secret. Previously this
    was only a printed warning, which is easy to miss in log noise and does
    nothing to stop an accidental production deploy with a well-known,
    public default key."""
    if _current_env() != "production":
        return
    secret  = os.environ.get("SECRET_KEY", _DEFAULT_SECRET)
    jwt_sec = os.environ.get("JWT_SECRET_KEY", _DEFAULT_JWT)
    if secret == _DEFAULT_SECRET or jwt_sec == _DEFAULT_JWT:
        raise RuntimeError(
            "Refusing to start: FLASK_ENV=production but SECRET_KEY and/or "
            "JWT_SECRET_KEY are still the insecure default values. Set both "
            "in your environment/.env file before running in production."
        )


def _default_apache_log_path():
    """The previous hardcoded XAMPP path only exists on a Windows dev box;
    on any Linux deployment (the typical production target for this
    project) that path simply doesn't exist, silently breaking Apache log
    ingestion. Pick a sane platform default and still allow override."""
    if os.name == "nt":
        return r"C:\xampp\apache\logs\access.log"
    return "/var/log/apache2/access.log"


def _parse_jwt_expiry_hours():
    try:
        return float(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 8))
    except (TypeError, ValueError):
        return 8.0


_warn_insecure()
_validate_production_secrets()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", _DEFAULT_SECRET)

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "idps.db"
        )
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # The IDS/IPS engine, the packet-capture thread, and Flask request
    # workers all touch the DB concurrently. SQLite's default driver
    # refuses cross-thread use of a single connection (raises
    # "SQLite objects created in a thread can only be used in that same
    # thread"), which previously showed up as intermittent 500s under load.
    # check_same_thread=False hands thread-safety to SQLAlchemy's pooling
    # (safe here since SQLAlchemy sessions are already scoped per-request/
    # per-thread). Only apply it for sqlite URIs - it's meaningless (and
    # an invalid connect_arg) for any other backend.
    if SQLALCHEMY_DATABASE_URI.startswith("sqlite"):
        SQLALCHEMY_ENGINE_OPTIONS = {
            "connect_args": {"check_same_thread": False},
        }
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": True,
        }

    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", _DEFAULT_JWT)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=_parse_jwt_expiry_hours())

    # Network interface for Npcap/Scapy (None = default)
    CAPTURE_IFACE = os.environ.get("CAPTURE_IFACE", None)

    # Set to False once OPNsense env vars are configured
    IPS_DRY_RUN = os.environ.get("IPS_DRY_RUN", "true").lower() == "true"

    # Per-attack-type confidence threshold for automatic IPS blocking.
    # Falls back to 0.85 for any attack type not listed here.
    IPS_BLOCK_THRESHOLDS = {
        "SQL_INJECTION":     0.90,
        "XSS":               0.88,
        "XSS_REFLECTED":     0.88,
        "XSS_STORED":        0.70,  # critical severity - stored XSS persists server-side, block more readily
        "COMMAND_INJECTION": 0.90,
        "LFI":               0.85,
        "BruteForce":        0.80,
        "DoS":               0.75,
        "PortScan":          0.85,
        "WebAttack":         0.90,
    }

    # Cross-platform default; override with APACHE_LOG_PATH in .env.
    APACHE_ACCESS_LOG = os.environ.get("APACHE_LOG_PATH", _default_apache_log_path())

    # Flask-CORS - split on commas so multiple dashboard origins (e.g. a
    # dev server plus a production domain) can be configured without code
    # changes. A single origin still works fine as a one-item list.
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.environ.get("CORS_ORIGINS", "http://localhost:5000").split(",")
        if origin.strip()
    ]

    # Flask-Limiter
    RATELIMIT_DEFAULT = "200 per minute"
    RATELIMIT_STORAGE_URL = os.environ.get("RATELIMIT_STORAGE_URL", "memory://")

    # Flask debug/production mode - previously undefined, so app.py had no
    # config-driven way to disable the Werkzeug debugger in production.
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
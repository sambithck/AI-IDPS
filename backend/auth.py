"""
backend/auth.py

JWT-based authentication and role-based access control.
Roles: admin, analyst, viewer
"""

import logging
import threading
import time
from functools import wraps

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt,
)
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from db.models import db, User

logger = logging.getLogger("ai_idps.auth")

auth_bp = Blueprint("auth", __name__)

MIN_PASSWORD_LENGTH = 8

# ---------------------------------------------------------------------------
# Login brute-force mitigation
# ---------------------------------------------------------------------------
# The dashboard's own Flask-Limiter instance lives in backend/api.py and is
# scoped to api_bp; importing it here would create a circular import
# (backend/api.py already imports roles_required from this module), and
# this blueprint has no way to register a second Limiter with the app
# without touching backend/app.py. So: a small, self-contained per-IP
# sliding-window limiter, good enough to stop naive credential-stuffing
# against /api/auth/login without pulling in another module's state.
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_ATTEMPTS = 10
_MAX_TRACKED_IPS = 10000

_login_attempts = {}
_login_attempts_lock = threading.Lock()

# Precomputed once so a flood of login attempts for nonexistent usernames
# doesn't force the server to run the (intentionally slow) password hasher
# on every request just to build a dummy hash to compare against.
_DUMMY_PASSWORD_HASH = generate_password_hash("this-value-is-never-a-real-password")


def _check_login_rate_limit(ip):
    """Return False if `ip` has exceeded the login attempt budget."""
    now = time.time()
    with _login_attempts_lock:
        if len(_login_attempts) > _MAX_TRACKED_IPS:
            # Opportunistic cleanup so tracking many distinct source IPs
            # (scanning/spraying traffic) can't grow this dict forever.
            stale = [
                k for k, v in _login_attempts.items()
                if not v or now - v[-1] > _LOGIN_WINDOW_SECONDS
            ]
            for k in stale:
                del _login_attempts[k]

        attempts = _login_attempts.setdefault(ip, [])
        attempts[:] = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
        if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
            return False
        attempts.append(now)
        return True


@auth_bp.route("/api/auth/register", methods=["POST"])
@jwt_required()
def register():
    """Only an admin can create new users."""
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admin role required"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "viewer")

    if not username or not isinstance(username, str) or not username.strip():
        return jsonify({"error": "username and password required"}), 400
    if not password or not isinstance(password, str):
        return jsonify({"error": "username and password required"}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({"error": f"password must be at least {MIN_PASSWORD_LENGTH} characters"}), 400

    username = username.strip()

    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "invalid role"}), 400

    try:
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "user already exists"}), 409

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    except SQLAlchemyError as e:
        # Covers both genuine DB errors and the race where two concurrent
        # register() calls for the same username both pass the
        # filter_by().first() check before either commits - the second
        # commit hits the users.username UNIQUE constraint and raises
        # instead of silently corrupting session state for the next request.
        db.session.rollback()
        logger.error("register() failed for username=%s: %s", username, e)
        return jsonify({"error": "user already exists"}), 409

    return jsonify({"message": "user created", "username": username, "role": role}), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    client_ip = request.remote_addr or "unknown"
    if not _check_login_rate_limit(client_ip):
        return jsonify({"error": "too many login attempts, try again later"}), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not isinstance(username, str) or not password or not isinstance(password, str):
        return jsonify({"error": "invalid credentials"}), 401

    try:
        user = User.query.filter_by(username=username).first()
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("login() DB lookup failed: %s", e)
        return jsonify({"error": "internal server error"}), 500

    if user is None:
        # Run the password hasher against a dummy hash anyway so a
        # nonexistent-username response takes roughly the same time as a
        # wrong-password response - otherwise the two cases are
        # distinguishable by timing and an attacker can enumerate valid
        # usernames without ever guessing a password.
        from werkzeug.security import check_password_hash
        check_password_hash(_DUMMY_PASSWORD_HASH, password)
        return jsonify({"error": "invalid credentials"}), 401

    if not user.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(
        identity=user.username,
        additional_claims={"role": user.role, "user_id": user.id},
    )

    return jsonify({"access_token": token, "role": user.role, "username": user.username})


def roles_required(*allowed_roles):
    """Decorator: restrict an endpoint to specific roles."""

    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") not in allowed_roles:
                return jsonify({"error": "insufficient permissions"}), 403
            return fn(*args, **kwargs)

        return decorated

    return wrapper


def create_default_admin():
    """Create a default admin user if none exists (first run)."""
    try:
        if User.query.filter_by(role="admin").first():
            return

        admin = User(username="admin", role="admin")
        admin.set_password("ChangeMe123!")
        db.session.add(admin)
        db.session.commit()
        logger.warning(
            "Created default admin user -> username: admin / password: ChangeMe123! "
            "CHANGE THIS PASSWORD IMMEDIATELY."
        )
    except SQLAlchemyError as e:
        # Guards the check-then-create race: if two app workers/processes
        # both start up at once, both can pass the "no admin exists" check
        # before either commits. Without this, the loser's commit raises
        # an unhandled IntegrityError on the users.username UNIQUE
        # constraint and crashes app startup instead of just no-oping,
        # since the winner already created the admin we wanted.
        db.session.rollback()
        logger.info("create_default_admin(): admin already exists or DB error: %s", e)
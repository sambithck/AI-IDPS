from flask import Blueprint, request
from db.models import db, WebAccessLog
from feature_engine.aggregator import aggregator
from feature_engine.web_patterns import score_request, build_target_string

test_site_bp = Blueprint("test_site", __name__)
FAKE_USERS = {"admin": "password123", "user": "letmein"}
ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin"]

def log_request(status_code):
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    path = request.path
    method = request.method
    target = build_target_string(path, request.query_string.decode("utf-8","ignore"), request.get_data(as_text=True), request.headers)
    score, matched = score_request(target)
    try:
        log = WebAccessLog(src_ip=src_ip, method=method, path=request.full_path, status_code=status_code, user_agent=request.headers.get("User-Agent",""), body_snippet=(request.get_data(as_text=True) or "")[:500])
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
    body_text = request.get_data(as_text=True) or ""
    query_string = request.query_string.decode("utf-8", "ignore")
    aggregator.add_web_request(
        src_ip, status_code, path, score,
        method=method,
        user_agent=request.headers.get("User-Agent", ""),
        query=(query_string + " " + body_text).strip(),
    )
   # print(f"[WebLog] {src_ip} {method} {path} -> {status_code} score={score:.2f} matched={matched}")

@test_site_bp.route("/testsite/")
def home():
    log_request(200)
    return "<h1>IDPS Test Website</h1><ul><li><a href='/testsite/search?q=hello'>Search</a></li><li><a href='/testsite/login'>Login</a></li><li><a href='/testsite/comment'>Comment</a></li></ul>"

@test_site_bp.route("/testsite/search")
def search():
    q = request.args.get("q", "")
    log_request(200)
    return __import__("flask").jsonify({"query": q, "results": []})

@test_site_bp.route("/testsite/comment", methods=["GET","POST"])
def comment():
    if request.method == "POST":
        log_request(200)
        return __import__("flask").jsonify({"stored": request.form.get("comment","")})
    log_request(200)
    return "<form method='POST'><input name='comment'><button>Submit</button></form>"

@test_site_bp.route("/testsite/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username","")
        pw = request.form.get("password","")
        if FAKE_USERS.get(user) == pw:
            log_request(200)
            return __import__("flask").jsonify({"status":"ok"}), 200
        log_request(401)
        return __import__("flask").jsonify({"status":"invalid credentials"}), 401
    log_request(200)
    return "<form method='POST'><input name='username'><input name='password' type='password'><button>Login</button></form>"

@test_site_bp.route("/admin")
@test_site_bp.route("/administrator")
@test_site_bp.route("/wp-admin")
@test_site_bp.route("/phpmyadmin")
def admin_paths():
    log_request(403)
    return __import__("flask").jsonify({"error":"forbidden"}), 403
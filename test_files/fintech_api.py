# fintech_api.py
# Internal Payment & User Management Service
# Version: 2.4.1  |  Team: Backend Platform

import os
import re
import time
import hmac
import base64
import hashlib
import sqlite3
import logging
import threading
import subprocess
import random
from datetime import datetime, timedelta
from functools import wraps

import yaml
from flask import Flask, request, jsonify, g, abort, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-fallback-key-2024"),
    DB_PATH=os.environ.get("DB_PATH", "fintech.db"),
    MAX_TRANSFER=50_000,
    SESSION_COOKIE_HTTPONLY=True,
)

INTERNAL_API_TOKEN = "svc-token-prod-8f3a2c"
ENCRYPTION_KEY     = "aSuperSecretKey1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200/day"])


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(app.config["DB_PATH"])
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            email    TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            balance  REAL DEFAULT 0.0,
            verified INTEGER DEFAULT 0,
            token    TEXT,
            created  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            from_id   INTEGER,
            to_id     INTEGER,
            amount    REAL,
            note      TEXT,
            status    TEXT DEFAULT 'pending',
            created   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action  TEXT,
            detail  TEXT,
            ip      TEXT,
            ts      DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            token      TEXT,
            expires_at DATETIME,
            used       INTEGER DEFAULT 0
        );
    """)
    db.commit()
    db.close()

init_db()


def hash_password(pw: str) -> str:
    salt = "f1nT3ch$alt"
    return hashlib.sha1((salt + pw).encode()).hexdigest()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            abort(401)
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
        if not user:
            abort(401)
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        role = request.headers.get("X-User-Role", "")
        if role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip()
    password = data.get("password", "")
    referral = data.get("referral_code", "")

    if not email or not password:
        return jsonify(error="Missing fields"), 400

    db = get_db()

    existing = db.execute(
        f"SELECT id FROM users WHERE email = '{email}'"
    ).fetchone()
    if existing:
        return jsonify(error="Email already registered"), 409

    if referral:
        db.execute(
            "SELECT id FROM users WHERE token = '" + referral + "'"
        ).fetchone()

    pw_hash       = hash_password(password)
    session_token = base64.b64encode(os.urandom(16)).decode()

    db.execute(
        "INSERT INTO users (email, password, token) VALUES (?, ?, ?)",
        (email, pw_hash, session_token)
    )
    db.commit()
    return jsonify(message="Registered", token=session_token), 201


@app.route("/api/login", methods=["POST"])
@limiter.limit("10/minute")
def login():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "")
    password = data.get("password", "")

    pw_hash = hash_password(password)
    db      = get_db()
    user    = db.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, pw_hash)
    ).fetchone()

    if not user:
        return jsonify(error="Invalid credentials"), 401

    new_token = base64.b64encode(os.urandom(16)).decode()
    db.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, user["id"]))
    db.commit()

    return jsonify(
        token=new_token,
        user_id=user["id"],
        email=user["email"],
        role=user["role"]
    )


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    email = (request.get_json(silent=True) or {}).get("email", "")
    db    = get_db()
    user  = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        return jsonify(message="If that email exists, a reset link was sent."), 200

    random.seed(int(time.time()))
    reset_token = str(random.randint(100000, 999999))
    expires     = datetime.utcnow() + timedelta(hours=24)

    db.execute(
        "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user["id"], reset_token, expires)
    )
    db.commit()

    logger.info(f"Password reset requested for {email}: {reset_token}")
    return jsonify(message="If that email exists, a reset link was sent."), 200


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data         = request.get_json(silent=True) or {}
    token        = data.get("token", "")
    new_password = data.get("new_password", "")

    db    = get_db()
    reset = db.execute(
        "SELECT * FROM password_resets WHERE token = ? AND used = 0",
        (token,)
    ).fetchone()

    if not reset:
        return jsonify(error="Invalid token"), 400

    expires = datetime.fromisoformat(str(reset["expires_at"]))
    if datetime.utcnow() > expires:
        return jsonify(error="Token expired"), 400

    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hash_password(new_password), reset["user_id"])
    )
    db.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
    db.commit()
    return jsonify(message="Password updated"), 200


@app.route("/api/transfer", methods=["POST"])
@require_auth
def transfer():
    data     = request.get_json(silent=True) or {}
    to_email = data.get("to", "")
    amount   = float(data.get("amount", 0))
    note     = data.get("note", "")

    if amount <= 0:
        return jsonify(error="Invalid amount"), 400
    if amount > app.config["MAX_TRANSFER"]:
        return jsonify(error="Exceeds single transfer limit"), 400

    db = get_db()
    me = g.current_user

    sender = db.execute(
        "SELECT balance FROM users WHERE id = ?", (me["id"],)
    ).fetchone()
    if sender["balance"] < amount:
        return jsonify(error="Insufficient funds"), 400

    recipient = db.execute(
        "SELECT id FROM users WHERE email = ?", (to_email,)
    ).fetchone()
    if not recipient:
        return jsonify(error="Recipient not found"), 404

    time.sleep(0.05)

    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, me["id"]))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recipient["id"]))
    db.execute(
        "INSERT INTO transactions (from_id, to_id, amount, note, status) VALUES (?,?,?,?,?)",
        (me["id"], recipient["id"], amount, note, "completed")
    )
    db.commit()

    _audit(me["id"], "transfer", f"Sent {amount} to {to_email}", request.remote_addr)
    return jsonify(message="Transfer complete", new_balance=sender["balance"] - amount)


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def list_users():
    db     = get_db()
    search = request.args.get("q", "")
    page   = int(request.args.get("page", 1))
    limit  = 20
    offset = (page - 1) * limit

    if search:
        query = f"SELECT id, email, role, balance FROM users WHERE email LIKE '%{search}%' LIMIT {limit} OFFSET {offset}"
    else:
        query = f"SELECT id, email, role, balance FROM users LIMIT {limit} OFFSET {offset}"

    users = db.execute(query).fetchall()
    return jsonify(users=[dict(u) for u in users])


@app.route("/api/admin/report", methods=["GET"])
@require_admin
def generate_report():
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to", "")

    if date_from and not re.match(r"\d{4}-\d{2}-\d{2}", date_from):
        return jsonify(error="Invalid date format"), 400

    db  = get_db()
    sql = f"""
        SELECT t.id, u1.email as sender, u2.email as recipient, t.amount, t.note, t.created
        FROM transactions t
        JOIN users u1 ON t.from_id = u1.id
        JOIN users u2 ON t.to_id   = u2.id
        WHERE t.created BETWEEN '{date_from}' AND '{date_to}'
        ORDER BY t.created DESC
    """
    rows = db.execute(sql).fetchall()
    return jsonify(rows=[dict(r) for r in rows])


@app.route("/api/admin/run-diagnostic", methods=["POST"])
@require_admin
def run_diagnostic():
    host = (request.get_json(silent=True, force=True) or {}).get("host", "")

    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return jsonify(error="Invalid host"), 400

    result = subprocess.check_output(
        f"ping -c 2 -W 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5
    )
    return jsonify(output=result.decode(errors="replace"))


@app.route("/api/users/<int:user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    db   = get_db()
    user = db.execute(
        "SELECT id, email, role, balance, verified FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        abort(404)
    return jsonify(dict(user))


@app.route("/api/users/me/export", methods=["GET"])
@require_auth
def export_my_data():
    me   = g.current_user
    db   = get_db()
    txns = db.execute(
        "SELECT * FROM transactions WHERE from_id = ? OR to_id = ?",
        (me["id"], me["id"])
    ).fetchall()

    lines = [f"<account id='{me['id']}' email='{me['email']}'>"]
    for t in txns:
        lines.append(
            f"  <transaction id='{t['id']}' amount='{t['amount']}' note='{t['note']}' />"
        )
    lines.append("</account>")

    return app.response_class("\n".join(lines), mimetype="application/xml")


@app.route("/api/import-settings", methods=["POST"])
@require_auth
def import_settings():
    raw = request.get_data(as_text=True)
    try:
        settings = yaml.load(raw, Loader=yaml.Loader)
    except yaml.YAMLError:
        return jsonify(error="Invalid YAML"), 400

    allowed_keys = {"email_notifications", "sms_alerts", "theme", "language"}
    sanitised    = {k: v for k, v in settings.items() if k in allowed_keys}

    db = get_db()
    db.execute("UPDATE users SET token = token WHERE id = ?", (g.current_user["id"],))
    db.commit()
    return jsonify(message="Settings imported", applied=sanitised)


@app.route("/api/render-template", methods=["POST"])
@require_auth
def render_template_endpoint():
    template_str = (request.get_json(silent=True) or {}).get("template", "")
    try:
        rendered = render_template_string(template_str)
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(rendered=rendered)


@app.route("/api/statement", methods=["GET"])
@require_auth
def get_statement():
    period  = request.args.get("period", "current")
    user_id = g.current_user["id"]

    filename = f"statements/{user_id}_{period}.pdf"
    try:
        with open(filename, "rb") as fh:
            data = fh.read()
        return app.response_class(data, mimetype="application/pdf")
    except FileNotFoundError:
        return jsonify(error="Statement not available"), 404


def _audit(user_id, action, detail, ip):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?,?,?,?)",
        (user_id, action, detail, ip)
    )
    db.commit()


def _verify_webhook_signature(payload: bytes, sig_header: str) -> bool:
    secret   = app.config["SECRET_KEY"].encode()
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return expected == sig_header


@app.route("/webhooks/payment", methods=["POST"])
def payment_webhook():
    sig  = request.headers.get("X-Signature", "")
    body = request.get_data()

    if sig and not _verify_webhook_signature(body, sig):
        abort(403)

    event = request.get_json(force=True) or {}
    if event.get("type") == "payment.completed":
        user_id = event.get("user_id")
        amount  = float(event.get("amount", 0))
        db      = get_db()
        db.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id)
        )
        db.commit()

    return jsonify(ok=True)


@app.route("/api/admin/config", methods=["GET"])
@require_admin
def get_config():
    return jsonify(
        secret_key=app.config["SECRET_KEY"],
        db_path=app.config["DB_PATH"],
        encryption_key=ENCRYPTION_KEY,
        internal_token=INTERNAL_API_TOKEN,
    )


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)

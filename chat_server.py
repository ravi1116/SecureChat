#!/usr/bin/env python3
"""
Secure Chat Server - E2E room secrets
------------------------------------
Auth uses one-time hardware keys from chat.db.
Encryption is client-side: each room uses a shared secret + room salt.
"""

import os, sqlite3, hashlib, secrets, base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = os.urandom(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

DB_PATH = "chat.db"
SESSION_TTL = timedelta(hours=1)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# -- DB --

def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def _maybe_add_column(con, table, col, ddl):
    cols = [r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]
    if col not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

def init_db():
    con = get_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key       TEXT    NOT NULL UNIQUE,
            key_hash  TEXT    NOT NULL,
            used      INTEGER NOT NULL DEFAULT 0,
            issued    INTEGER NOT NULL DEFAULT 0,
            created   TEXT    NOT NULL,
            used_at   TEXT,
            issued_at TEXT,
            issued_to TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            created     TEXT NOT NULL,
            expires     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rooms (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            aes_key_b64 TEXT NOT NULL,
            created     TEXT NOT NULL,
            salt_b64    TEXT
        );
        CREATE TABLE IF NOT EXISTS usage (
            username    TEXT PRIMARY KEY,
            char_used   INTEGER NOT NULL DEFAULT 0,
            updated     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS premium_users (
            username    TEXT PRIMARY KEY,
            plan        TEXT NOT NULL DEFAULT 'premium',
            is_active   INTEGER NOT NULL DEFAULT 1,
            created     TEXT NOT NULL,
            updated     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_attempts (
            ip            TEXT PRIMARY KEY,
            fail_count    INTEGER NOT NULL DEFAULT 0,
            blocked_until TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            room        TEXT NOT NULL,
            sender      TEXT NOT NULL,
            ciphertext  TEXT NOT NULL,
            nonce       TEXT NOT NULL,
            created     TEXT NOT NULL
        );
    """)
    # Lightweight migrations
    _maybe_add_column(con, "keys", "issued",    "INTEGER NOT NULL DEFAULT 0")
    _maybe_add_column(con, "keys", "issued_at", "TEXT")
    _maybe_add_column(con, "keys", "issued_to", "TEXT")
    _maybe_add_column(con, "rooms", "salt_b64", "TEXT")

    # Create default rooms
    for room_name in ["general", "private"]:
        existing = con.execute(
            "SELECT id FROM rooms WHERE name=?", (room_name,)
        ).fetchone()
        if not existing:
            room_key  = base64.b64encode(os.urandom(32)).decode()
            room_salt = base64.b64encode(os.urandom(16)).decode()
            con.execute(
                "INSERT INTO rooms (name, aes_key_b64, created, salt_b64) VALUES (?,?,?,?)",
                (room_name, room_key, datetime.now().isoformat(), room_salt)
            )
    # Ensure every room has a salt
    con.execute(
        "UPDATE rooms SET salt_b64=? WHERE salt_b64 IS NULL OR salt_b64=''",
        (base64.b64encode(os.urandom(16)).decode(),)
    )
    con.commit()
    con.close()

# -- Session helpers --

def verify_token(token: str):
    if not token:
        return None
    con = get_db()
    row = con.execute(
        "SELECT * FROM sessions WHERE token=?", (token,)
    ).fetchone()
    con.close()
    if not row:
        return None
    if datetime.fromisoformat(row["expires"]) < datetime.now():
        return None
    return dict(row)

def is_premium(username: str) -> bool:
    con = get_db()
    row = con.execute(
        "SELECT is_active FROM premium_users WHERE username=?", (username,)
    ).fetchone()
    con.close()
    return bool(row and row["is_active"])

def issue_unused_key(username: str):
    con = get_db()
    row = con.execute(
        "SELECT id, key FROM keys WHERE used=0 AND issued=0 ORDER BY id LIMIT 1"
    ).fetchone()
    if not row:
        con.close()
        return None
    now = datetime.now().isoformat()
    con.execute(
        "UPDATE keys SET issued=1, issued_at=?, issued_to=? WHERE id=?",
        (now, username, row["id"])
    )
    con.commit()
    key = row["key"]
    con.close()
    return key

# -- Auth --

@app.route("/auth/login", methods=["POST"])
def auth_login():
    data     = request.get_json() or {}
    key      = data.get("key", "").strip()
    username = data.get("username", "").strip()

    if not key or not username:
        return jsonify({"ok": False, "error": "Key and username required"}), 400
    if len(username) > 24:
        return jsonify({"ok": False, "error": "Username too long"}), 400
    if not username.lower().endswith("@gmail.com"):
        return jsonify({"ok": False, "error": "Gmail required"}), 400

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    con = get_db()
    row = con.execute(
        "SELECT id, used FROM keys WHERE key_hash=?", (key_hash,)
    ).fetchone()

    if not row:
        con.close()
        return jsonify({"ok": False, "error": "Invalid key"}), 401
    if row["used"]:
        con.close()
        return jsonify({"ok": False, "error": "Key already used"}), 401

    token   = secrets.token_hex(32)
    now     = datetime.now()
    expires = now + SESSION_TTL

    con.execute(
        "UPDATE keys SET used=1, used_at=? WHERE id=?",
        (now.isoformat(), row["id"])
    )
    con.execute(
        "INSERT INTO sessions (token, username, created, expires) VALUES (?,?,?,?)",
        (token, username, now.isoformat(), expires.isoformat())
    )
    con.commit()
    con.close()

    return jsonify({
        "ok":       True,
        "token":    token,
        "username": username,
        "expires":  expires.isoformat()
    })

@app.route("/auth/request_key", methods=["POST"])
def auth_request_key():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Username required"}), 400
    if len(username) > 24:
        return jsonify({"ok": False, "error": "Username too long"}), 400
    if not username.lower().endswith("@gmail.com"):
        return jsonify({"ok": False, "error": "Gmail required"}), 400
    key = issue_unused_key(username)
    if not key:
        return jsonify({"ok": False, "error": "No unused keys available"}), 409
    return jsonify({"ok": True, "key": key})

@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    data  = request.get_json() or {}
    token = data.get("token", "")
    con   = get_db()
    con.execute("DELETE FROM sessions WHERE token=?", (token,))
    con.commit()
    con.close()
    return jsonify({"ok": True})

@app.route("/auth/status")
def auth_status():
    token = request.headers.get("X-Session-Token", "")
    sess  = verify_token(token)
    return jsonify({"authenticated": bool(sess)})

# -- Admin --

def require_admin():
    return bool(session.get("is_admin"))

def client_ip():
    xf = request.headers.get("X-Forwarded-For", "")
    if xf:
        return xf.split(",")[0].strip()
    return request.remote_addr or "unknown"

@app.route("/admin")
def admin_page():
    if not require_admin():
        return render_template("admin_login.html")
    return render_template("admin.html")

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    pw = (data.get("password") or "").strip()
    if not ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Admin password not set"}), 500

    ip = client_ip()
    now = datetime.now()
    con = get_db()
    row = con.execute(
        "SELECT fail_count, blocked_until FROM admin_attempts WHERE ip=?", (ip,)
    ).fetchone()
    if row and row["blocked_until"]:
        try:
            if datetime.fromisoformat(row["blocked_until"]) > now:
                con.close()
                return jsonify({"ok": False, "error": "Too many attempts. IP blocked."}), 429
        except Exception:
            pass

    if pw != ADMIN_PASSWORD:
        fail_count = (row["fail_count"] if row else 0) + 1
        blocked_until = None
        if fail_count >= 5:
            blocked_until = (now + timedelta(minutes=15)).isoformat()
            fail_count = 0
        con.execute(
            "INSERT INTO admin_attempts (ip, fail_count, blocked_until) VALUES (?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET fail_count=?, blocked_until=?",
            (ip, fail_count, blocked_until, fail_count, blocked_until)
        )
        con.commit()
        con.close()
        return jsonify({"ok": False, "error": "Invalid password"}), 401

    # Success: clear attempts
    con.execute("DELETE FROM admin_attempts WHERE ip=?", (ip,))
    con.commit()
    con.close()
    session["is_admin"] = True
    return jsonify({"ok": True})

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/admin/data")
def admin_data():
    if not require_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    con = get_db()
    usage = con.execute("SELECT username, char_used FROM usage ORDER BY char_used DESC").fetchall()
    premium = con.execute("SELECT username, is_active, plan, updated FROM premium_users").fetchall()
    con.close()
    return jsonify({
        "usage": [dict(r) for r in usage],
        "premium": [dict(r) for r in premium]
    })

@app.route("/admin/premium", methods=["POST"])
def admin_set_premium():
    if not require_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    active = 1 if data.get("is_active") else 0
    if not username:
        return jsonify({"ok": False, "error": "Username required"}), 400
    now = datetime.now().isoformat()
    con = get_db()
    con.execute(
        "INSERT INTO premium_users (username, plan, is_active, created, updated) "
        "VALUES (?,?,?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET is_active=?, updated=?",
        (username, "premium", active, now, now, active, now)
    )
    con.commit()
    con.close()
    return jsonify({"ok": True})

# -- Rooms --

@app.route("/rooms")
def list_rooms():
    token = request.headers.get("X-Session-Token", "")
    sess  = verify_token(token)
    if not sess:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    con  = get_db()
    rows = con.execute("SELECT name FROM rooms ORDER BY name").fetchall()
    con.close()
    return jsonify({"rooms": [r["name"] for r in rows]})

@app.route("/rooms/<name>/salt")
def get_room_salt(name):
    token = request.headers.get("X-Session-Token", "")
    sess  = verify_token(token)
    if not sess:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    con = get_db()
    row = con.execute(
        "SELECT salt_b64 FROM rooms WHERE name=?", (name,)
    ).fetchone()
    con.close()
    if not row or not row["salt_b64"]:
        return jsonify({"ok": False, "error": "Room not found"}), 404
    return jsonify({"ok": True, "salt": row["salt_b64"]})

@app.route("/rooms", methods=["POST"])
def create_room():
    token = request.headers.get("X-Session-Token", "")
    if not verify_token(token):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    name = data.get("name", "").strip().lower().replace(" ", "-")
    if not name or len(name) > 32:
        return jsonify({"ok": False, "error": "Invalid room name"}), 400
    try:
        room_key  = base64.b64encode(os.urandom(32)).decode()
        room_salt = base64.b64encode(os.urandom(16)).decode()
        con = get_db()
        con.execute(
            "INSERT INTO rooms (name, aes_key_b64, created, salt_b64) VALUES (?,?,?,?)",
            (name, room_key, datetime.now().isoformat(), room_salt)
        )
        con.commit()
        con.close()
        socketio.emit("room_created", {"name": name}, broadcast=True)
        return jsonify({"ok": True, "name": name})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "Room already exists"}), 409

# -- Messages --

@app.route("/messages/<room>")
def get_messages(room):
    token = request.headers.get("X-Session-Token", "")
    if not verify_token(token):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    con  = get_db()
    rows = con.execute(
        "SELECT sender, ciphertext, nonce, created FROM messages WHERE room=? ORDER BY id DESC LIMIT 50",
        (room,)
    ).fetchall()
    con.close()
    return jsonify({"messages": [dict(r) for r in reversed(rows)]})

# -- SocketIO --

@socketio.on("join")
def on_join(data):
    token = data.get("token", "")
    sess  = verify_token(token)
    if not sess:
        emit("error", {"message": "Unauthorized"})
        return
    room = data.get("room", "general")
    join_room(room)
    emit("system", {"message": f"{sess['username']} joined", "room": room}, to=room)

@socketio.on("leave")
def on_leave(data):
    token = data.get("token", "")
    sess  = verify_token(token)
    room  = data.get("room", "general")
    leave_room(room)
    if sess:
        emit("system", {"message": f"{sess['username']} left", "room": room}, to=room)

@socketio.on("message")
def on_message(data):
    token = data.get("token", "")
    sess  = verify_token(token)
    if not sess:
        emit("error", {"message": "Unauthorized"})
        return

    room       = data.get("room", "general")
    ciphertext = data.get("ciphertext", "")
    nonce      = data.get("nonce", "")
    char_len   = int(data.get("char_len", 0) or 0)
    if not ciphertext or not nonce:
        return

    # Enforce 2400 total characters per user (best-effort, client-reported length)
    if not is_premium(sess["username"]):
        con = get_db()
        row = con.execute(
            "SELECT char_used FROM usage WHERE username=?", (sess["username"],)
        ).fetchone()
        used = row["char_used"] if row else 0
        if used + char_len > 2400:
            con.close()
            emit("error", {"message": "Character limit reached (2400)."})
            return

    now = datetime.now().isoformat()
    con = get_db()
    con.execute(
        "INSERT INTO messages (room, sender, ciphertext, nonce, created) VALUES (?,?,?,?,?)",
        (room, sess["username"], ciphertext, nonce, now)
    )
    if not is_premium(sess["username"]):
        con.execute(
            "INSERT INTO usage (username, char_used, updated) VALUES (?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET char_used=char_used+?, updated=?",
            (sess["username"], used + char_len, now, char_len, now)
        )
    con.commit()
    con.close()

    emit("message", {
        "sender":     sess["username"],
        "ciphertext": ciphertext,
        "nonce":      nonce,
        "created":    now,
        "room":       room
    }, to=room)

# -- Main --

@app.route("/")
def index():
    return render_template("chat.html")

@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    print(f"Secure Chat Server -> http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", debug=False, port=port)

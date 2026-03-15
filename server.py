#!/usr/bin/env python3
"""
FinanceIQ Server — Full-stack financial management with auth & 2FA
Pure Python stdlib: no Flask, no pip installs needed.
"""

import http.server
import json
import sqlite3
import hashlib
import hmac
import secrets
import base64
import struct
import time
import os
import re
import urllib.parse
from http.cookies import SimpleCookie
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "financeiq.db"))
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_HOURS = 24
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin123!")  # Change in production

# ═══════════════════════════════════════════════════════════════
#  TOTP (RFC 6238) — pure Python, no pyotp needed
# ═══════════════════════════════════════════════════════════════
def generate_totp_secret():
    """Generate a random base32-encoded secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii')

def get_totp_token(secret, time_step=30, digits=6):
    """Generate current TOTP token."""
    key = base64.b32decode(secret, casefold=True)
    counter = int(time.time()) // time_step
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def verify_totp(secret, token, window=1):
    """Verify TOTP with a time window (allows ±window steps)."""
    for offset in range(-window, window + 1):
        key = base64.b32decode(secret, casefold=True)
        counter = int(time.time()) // 30 + offset
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        off = h[-1] & 0x0F
        code = struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF
        expected = str(code % 1000000).zfill(6)
        if hmac.compare_digest(expected, token):
            return True
    return False

def get_totp_uri(secret, username, issuer="FinanceIQ"):
    """Generate otpauth:// URI for QR code / authenticator app."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

# ═══════════════════════════════════════════════════════════════
#  PASSWORD HASHING
# ═══════════════════════════════════════════════════════════════
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + ":" + hashed.hex()

def verify_password(password, stored):
    salt = stored.split(":")[0]
    return hmac.compare_digest(hash_password(password, salt), stored)

# ═══════════════════════════════════════════════════════════════
#  SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════
def create_session_token():
    return secrets.token_urlsafe(48)

def sign_token(data):
    payload = json.dumps(data).encode()
    sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode() + "." + sig

def verify_signed_token(token):
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload = base64.urlsafe_b64decode(parts[0])
        expected_sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, parts[1]):
            return None
        data = json.loads(payload)
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        totp_confirmed INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 0,
        is_approved INTEGER DEFAULT 0,
        display_name TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT,
        ai_key_enc TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT DEFAULT 'Other',
        method TEXT DEFAULT 'Unknown',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS budgets (
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        PRIMARY KEY (user_id, category),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        icon TEXT DEFAULT '🎯',
        target REAL NOT NULL,
        saved REAL DEFAULT 0,
        color TEXT DEFAULT '#10B981',
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    # Create admin user if not exists
    admin = conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
    if not admin:
        totp_secret = generate_totp_secret()
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret, totp_confirmed, is_admin, is_active, is_approved, display_name) VALUES (?,?,?,1,1,1,1,?)",
            (ADMIN_USER, hash_password(ADMIN_PASS), totp_secret, "Administrator")
        )
        print(f"\n{'='*60}")
        print(f"  ADMIN ACCOUNT CREATED")
        print(f"  Username: {ADMIN_USER}")
        print(f"  Password: {ADMIN_PASS}")
        print(f"  TOTP Secret: {totp_secret}")
        print(f"  Add to authenticator app using this secret")
        print(f"  URI: {get_totp_uri(totp_secret, ADMIN_USER)}")
        print(f"{'='*60}\n")
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════
#  REQUEST HANDLER
# ═══════════════════════════════════════════════════════════════
class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Quieter logs
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def get_session_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            data = verify_signed_token(token)
            if data:
                conn = get_db()
                user = conn.execute("SELECT * FROM users WHERE id=? AND is_active=1", (data["uid"],)).fetchone()
                conn.close()
                if user:
                    return dict(user)
        return None

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/" or path == "/app" or path == "/login" or path == "/register" or path == "/admin":
            self.serve_app()
        elif path.startswith("/api/"):
            self.handle_api_get(path)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_post(path)
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_put(path)
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.handle_api_delete(path)
        else:
            self.send_json({"error": "Not found"}, 404)

    # ─── API ROUTES (GET) ────────────────────────────────────
    def handle_api_get(self, path):
        if path == "/api/me":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            return self.send_json({"id": user["id"], "username": user["username"],
                "display_name": user["display_name"], "is_admin": user["is_admin"],
                "has_ai_key": bool(user["ai_key_enc"])})

        elif path == "/api/transactions":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC", (user["id"],)).fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/budgets":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM budgets WHERE user_id=?", (user["id"],)).fetchall()
            conn.close()
            return self.send_json({r["category"]: r["amount"] for r in rows})

        elif path == "/api/goals":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM goals WHERE user_id=?", (user["id"],)).fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/admin/users":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            conn = get_db()
            rows = conn.execute("SELECT id, username, display_name, is_admin, is_active, is_approved, totp_confirmed, created_at, last_login FROM users ORDER BY created_at DESC").fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/ai-key":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            return self.send_json({"has_key": bool(user["ai_key_enc"]), "key": user["ai_key_enc"] or ""})

        else:
            self.send_json({"error": "Not found"}, 404)

    # ─── API ROUTES (POST) ───────────────────────────────────
    def handle_api_post(self, path):
        body = self.read_body()

        if path == "/api/register":
            username = body.get("username", "").strip().lower()
            password = body.get("password", "")
            display_name = body.get("display_name", username)
            if not username or not password:
                return self.send_json({"error": "Username and password required"}, 400)
            if len(username) < 3 or not re.match(r'^[a-z0-9_]+$', username):
                return self.send_json({"error": "Username must be 3+ chars, lowercase alphanumeric/underscore"}, 400)
            if len(password) < 6:
                return self.send_json({"error": "Password must be 6+ characters"}, 400)
            conn = get_db()
            exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if exists:
                conn.close()
                return self.send_json({"error": "Username already taken"}, 409)
            totp_secret = generate_totp_secret()
            conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret, display_name, is_active, is_approved) VALUES (?,?,?,?,0,0)",
                (username, hash_password(password), totp_secret, display_name)
            )
            conn.commit()
            conn.close()
            totp_uri = get_totp_uri(totp_secret, username)
            return self.send_json({
                "ok": True,
                "message": "Account created. Waiting for admin approval.",
                "totp_secret": totp_secret,
                "totp_uri": totp_uri
            })

        elif path == "/api/login":
            username = body.get("username", "").strip().lower()
            password = body.get("password", "")
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            if not user or not verify_password(password, user["password_hash"]):
                return self.send_json({"error": "Invalid username or password"}, 401)
            if not user["is_approved"]:
                return self.send_json({"error": "Account pending admin approval"}, 403)
            if not user["is_active"]:
                return self.send_json({"error": "Account is deactivated"}, 403)
            # Return pending 2FA - don't create session yet
            return self.send_json({
                "requires_2fa": True,
                "user_id": user["id"],
                "totp_confirmed": bool(user["totp_confirmed"])
            })

        elif path == "/api/verify-2fa":
            user_id = body.get("user_id")
            totp_code = body.get("code", "").strip()
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not user:
                conn.close()
                return self.send_json({"error": "User not found"}, 404)
            if not verify_totp(user["totp_secret"], totp_code):
                conn.close()
                return self.send_json({"error": "Invalid 2FA code"}, 401)
            # Mark TOTP as confirmed on first successful verification
            if not user["totp_confirmed"]:
                conn.execute("UPDATE users SET totp_confirmed=1 WHERE id=?", (user_id,))
            conn.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            # Create session token
            token = sign_token({
                "uid": user["id"],
                "user": user["username"],
                "adm": bool(user["is_admin"]),
                "exp": time.time() + SESSION_HOURS * 3600
            })
            return self.send_json({
                "ok": True,
                "token": token,
                "user": {"id": user["id"], "username": user["username"],
                         "display_name": user["display_name"], "is_admin": bool(user["is_admin"])}
            })

        elif path == "/api/transactions":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            txns = body.get("transactions", [])
            if not txns:
                return self.send_json({"error": "No transactions"}, 400)
            conn = get_db()
            for tx in txns:
                conn.execute(
                    "INSERT INTO transactions (user_id, date, description, amount, category, method) VALUES (?,?,?,?,?,?)",
                    (user["id"], tx.get("date",""), tx.get("description",""), tx.get("amount",0),
                     tx.get("category","Other"), tx.get("method","Unknown"))
                )
            conn.commit()
            conn.close()
            return self.send_json({"ok": True, "count": len(txns)})

        elif path == "/api/budgets":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            budgets = body.get("budgets", {})
            conn = get_db()
            for cat, amt in budgets.items():
                conn.execute("INSERT OR REPLACE INTO budgets (user_id, category, amount) VALUES (?,?,?)",
                             (user["id"], cat, amt))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})

        elif path == "/api/goals":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            g = body
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO goals (user_id, name, icon, target, saved, color) VALUES (?,?,?,?,?,?)",
                (user["id"], g.get("name",""), g.get("icon","🎯"), g.get("target",0), g.get("saved",0), g.get("color","#10B981"))
            )
            conn.commit()
            gid = cur.lastrowid
            conn.close()
            return self.send_json({"ok": True, "id": gid})

        elif path == "/api/ai-key":
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            key = body.get("key", "")
            conn = get_db()
            conn.execute("UPDATE users SET ai_key_enc=? WHERE id=?", (key, user["id"]))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})

        elif path == "/api/admin/approve":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            uid = body.get("user_id")
            conn = get_db()
            conn.execute("UPDATE users SET is_approved=1, is_active=1 WHERE id=?", (uid,))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})

        elif path == "/api/admin/deactivate":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            uid = body.get("user_id")
            conn = get_db()
            conn.execute("UPDATE users SET is_active=0 WHERE id=? AND is_admin=0", (uid,))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})

        elif path == "/api/admin/activate":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            uid = body.get("user_id")
            conn = get_db()
            conn.execute("UPDATE users SET is_active=1 WHERE id=?", (uid,))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})

        elif path == "/api/admin/reset-password":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            uid = body.get("user_id")
            new_pass = body.get("new_password", "")
            if len(new_pass) < 6:
                return self.send_json({"error": "Password must be 6+ chars"}, 400)
            conn = get_db()
            # Also generate new TOTP secret on password reset
            new_totp = generate_totp_secret()
            conn.execute("UPDATE users SET password_hash=?, totp_secret=?, totp_confirmed=0 WHERE id=?",
                         (hash_password(new_pass), new_totp, uid))
            target = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
            conn.commit()
            conn.close()
            uname = target["username"] if target else "unknown"
            return self.send_json({"ok": True, "totp_secret": new_totp,
                                   "totp_uri": get_totp_uri(new_totp, uname)})

        elif path == "/api/admin/reset-2fa":
            user = self.get_session_user()
            if not user or not user["is_admin"]:
                return self.send_json({"error": "Forbidden"}, 403)
            uid = body.get("user_id")
            new_totp = generate_totp_secret()
            conn = get_db()
            conn.execute("UPDATE users SET totp_secret=?, totp_confirmed=0 WHERE id=?", (new_totp, uid))
            target = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
            conn.commit()
            conn.close()
            uname = target["username"] if target else "unknown"
            return self.send_json({"ok": True, "totp_secret": new_totp,
                                   "totp_uri": get_totp_uri(new_totp, uname)})

        else:
            self.send_json({"error": "Not found"}, 404)

    # ─── API ROUTES (PUT) ────────────────────────────────────
    def handle_api_put(self, path):
        m = re.match(r'/api/goals/(\d+)', path)
        if m:
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            gid = int(m.group(1))
            body = self.read_body()
            conn = get_db()
            conn.execute("UPDATE goals SET saved=? WHERE id=? AND user_id=?",
                         (body.get("saved", 0), gid, user["id"]))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})
        self.send_json({"error": "Not found"}, 404)

    # ─── API ROUTES (DELETE) ─────────────────────────────────
    def handle_api_delete(self, path):
        m = re.match(r'/api/goals/(\d+)', path)
        if m:
            user = self.get_session_user()
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            gid = int(m.group(1))
            conn = get_db()
            conn.execute("DELETE FROM goals WHERE id=? AND user_id=?", (gid, user["id"]))
            conn.commit()
            conn.close()
            return self.send_json({"ok": True})
        self.send_json({"error": "Not found"}, 404)

    # ─── SERVE FRONTEND ──────────────────────────────────────
    def serve_app(self):
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                self.send_html(f.read())
        else:
            self.send_html("<h1>app.html not found</h1>", 500)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer((HOST, PORT), Handler)
    print(f"\n  FinanceIQ Server running at http://localhost:{PORT}")
    print(f"  Open in any browser on any device on your network")
    print(f"  Admin: {ADMIN_USER} / {ADMIN_PASS}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()

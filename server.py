#!/usr/bin/env python3
"""
financiQ Server — Full-stack financial management
Pure Python stdlib: no Flask, no pip installs needed.
"""

import http.server
import json
import sqlite3
import hashlib
import hmac
import secrets
import base64
import time
import os
import re
import urllib.parse
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))
_default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "financiq.db")
DB_PATH = os.environ.get("DB_PATH", _default_db)
try:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
except PermissionError:
    DB_PATH = _default_db
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_HOURS = 24
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin123!")

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
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 0,
        is_approved INTEGER DEFAULT 0,
        display_name TEXT DEFAULT '',
        lang TEXT DEFAULT 'en',
        tour_completed INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT DEFAULT 'Other',
        method TEXT DEFAULT 'Unknown',
        type TEXT DEFAULT 'expense',
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
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)
    # Migrate existing DBs
    for col, default in [("lang", "'en'"), ("tour_completed", "0")]:
        try: conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
        except: pass
    try: conn.execute("ALTER TABLE transactions ADD COLUMN type TEXT DEFAULT 'expense'")
    except: pass
    # Default settings
    for key, val in [("global_ai_key", ""), ("currency", "₪")]:
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?,?)", (key, val))
    # Admin user
    admin = conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, is_active, is_approved, display_name, tour_completed) VALUES (?,?,1,1,1,?,1)",
            (ADMIN_USER, hash_password(ADMIN_PASS), "Administrator"))
        print(f"\n{'='*60}")
        print(f"  ADMIN ACCOUNT CREATED")
        print(f"  Username: {ADMIN_USER}")
        print(f"  Password: {ADMIN_PASS}")
        print(f"{'='*60}\n")
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════
#  REQUEST HANDLER
# ═══════════════════════════════════════════════════════════════
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

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
        if length == 0: return {}
        try: return json.loads(self.rfile.read(length))
        except: return {}

    def get_session_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            data = verify_signed_token(auth[7:])
            if data:
                conn = get_db()
                user = conn.execute("SELECT * FROM users WHERE id=? AND is_active=1", (data["uid"],)).fetchone()
                conn.close()
                if user: return dict(user)
        return None

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/app", "/login", "/register", "/admin"):
            self.serve_app()
        elif path.startswith("/api/"): self.handle_api_get(path)
        else: self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.handle_api_post(path)
        else: self.send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.handle_api_put(path)
        else: self.send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.handle_api_delete(path)
        else: self.send_json({"error": "Not found"}, 404)

    # ─── GET ─────────────────────────────────────────────────
    def handle_api_get(self, path):
        if path == "/api/me":
            user = self.get_session_user()
            if not user: return self.send_json({"error": "Unauthorized"}, 401)
            return self.send_json({
                "id": user["id"], "username": user["username"],
                "display_name": user["display_name"], "is_admin": user["is_admin"],
                "lang": user.get("lang","en"), "tour_completed": user.get("tour_completed",0)})

        elif path == "/api/transactions":
            user = self.get_session_user()
            if not user: return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC", (user["id"],)).fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/budgets":
            user = self.get_session_user()
            if not user: return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM budgets WHERE user_id=?", (user["id"],)).fetchall()
            conn.close()
            return self.send_json({r["category"]: r["amount"] for r in rows})

        elif path == "/api/goals":
            user = self.get_session_user()
            if not user: return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute("SELECT * FROM goals WHERE user_id=?", (user["id"],)).fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/settings":
            conn = get_db()
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            conn.close()
            # Don't expose API key to non-admin
            result = {r["key"]: r["value"] for r in rows}
            user = self.get_session_user()
            if not user or not user.get("is_admin"):
                if "global_ai_key" in result:
                    result["global_ai_key"] = "***" if result["global_ai_key"] else ""
            return self.send_json(result)

        elif path == "/api/admin/users":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error": "Forbidden"}, 403)
            conn = get_db()
            rows = conn.execute("SELECT id, username, display_name, is_admin, is_active, is_approved, created_at, last_login, lang FROM users ORDER BY created_at DESC").fetchall()
            conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/admin/settings":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error": "Forbidden"}, 403)
            conn = get_db()
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            conn.close()
            return self.send_json({r["key"]: r["value"] for r in rows})

        elif path == "/api/stats":
            user = self.get_session_user()
            if not user: return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            now = datetime.now()
            ms = now.strftime("%Y-%m-01")
            me = (now.replace(day=28) + timedelta(days=4)).replace(day=1).strftime("%Y-%m-%d")
            exp = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?", (user["id"], ms, me)).fetchone()
            inc = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='income' AND date>=? AND date<?", (user["id"], ms, me)).fetchone()
            tc = conn.execute("SELECT COUNT(*) as c FROM transactions WHERE user_id=?", (user["id"],)).fetchone()
            cats = conn.execute("SELECT category, SUM(amount) as total FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? GROUP BY category ORDER BY total DESC", (user["id"], ms, me)).fetchall()
            goals = conn.execute("SELECT * FROM goals WHERE user_id=?", (user["id"],)).fetchall()
            conn.close()
            return self.send_json({
                "month_expenses": exp["t"], "month_income": inc["t"],
                "total_transactions": tc["c"], "month": now.strftime("%Y-%m"),
                "categories": [{"category":c["category"],"total":c["total"]} for c in cats],
                "goals": [dict(g) for g in goals]})
        else:
            self.send_json({"error": "Not found"}, 404)

    # ─── POST ────────────────────────────────────────────────
    def handle_api_post(self, path):
        body = self.read_body()

        if path == "/api/register":
            username = body.get("username","").strip().lower()
            password = body.get("password","")
            display_name = body.get("display_name", username)
            lang = body.get("lang","en")
            if not username or not password:
                return self.send_json({"error":"Username and password required"}, 400)
            if len(username)<3 or not re.match(r'^[a-z0-9_]+$', username):
                return self.send_json({"error":"Username: 3+ chars, lowercase alphanumeric/underscore"}, 400)
            if len(password)<6:
                return self.send_json({"error":"Password must be 6+ characters"}, 400)
            conn = get_db()
            if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                conn.close(); return self.send_json({"error":"Username already taken"}, 409)
            conn.execute("INSERT INTO users (username,password_hash,display_name,lang,is_active,is_approved) VALUES (?,?,?,?,0,0)",
                         (username, hash_password(password), display_name, lang))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"message":"Account created. Waiting for admin approval."})

        elif path == "/api/login":
            username = body.get("username","").strip().lower()
            password = body.get("password","")
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                conn.close(); return self.send_json({"error":"Invalid username or password"}, 401)
            if not user["is_approved"]:
                conn.close(); return self.send_json({"error":"Account pending admin approval"}, 403)
            if not user["is_active"]:
                conn.close(); return self.send_json({"error":"Account is deactivated"}, 403)
            conn.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
            conn.commit(); conn.close()
            token = sign_token({"uid":user["id"],"user":user["username"],"adm":bool(user["is_admin"]),"exp":time.time()+SESSION_HOURS*3600})
            return self.send_json({"ok":True,"token":token,
                "user":{"id":user["id"],"username":user["username"],"display_name":user["display_name"],
                         "is_admin":bool(user["is_admin"]),"lang":user.get("lang","en"),
                         "tour_completed":user.get("tour_completed",0)}})

        elif path == "/api/tour-complete":
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db()
            conn.execute("UPDATE users SET tour_completed=1 WHERE id=?", (user["id"],))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/update-profile":
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db()
            conn.execute("UPDATE users SET lang=?, display_name=? WHERE id=?",
                         (body.get("lang",user.get("lang","en")), body.get("display_name",user.get("display_name","")), user["id"]))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/transactions":
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            txns = body.get("transactions", [])
            if not txns: return self.send_json({"error":"No transactions"}, 400)
            conn = get_db()
            for tx in txns:
                conn.execute("INSERT INTO transactions (user_id,date,description,amount,category,method,type) VALUES (?,?,?,?,?,?,?)",
                    (user["id"], tx.get("date",""), tx.get("description",""), tx.get("amount",0),
                     tx.get("category","Other"), tx.get("method","Unknown"), tx.get("type","expense")))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"count":len(txns)})

        elif path == "/api/budgets":
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db()
            for cat, amt in body.get("budgets",{}).items():
                conn.execute("INSERT OR REPLACE INTO budgets (user_id,category,amount) VALUES (?,?,?)", (user["id"],cat,amt))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/goals":
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db()
            cur = conn.execute("INSERT INTO goals (user_id,name,icon,target,saved,color) VALUES (?,?,?,?,?,?)",
                (user["id"], body.get("name",""), body.get("icon","🎯"), body.get("target",0), body.get("saved",0), body.get("color","#10B981")))
            conn.commit(); gid=cur.lastrowid; conn.close()
            return self.send_json({"ok":True,"id":gid})

        elif path == "/api/admin/approve":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error":"Forbidden"}, 403)
            conn = get_db(); conn.execute("UPDATE users SET is_approved=1, is_active=1 WHERE id=?", (body.get("user_id"),))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/deactivate":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error":"Forbidden"}, 403)
            conn = get_db(); conn.execute("UPDATE users SET is_active=0 WHERE id=? AND is_admin=0", (body.get("user_id"),))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/activate":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error":"Forbidden"}, 403)
            conn = get_db(); conn.execute("UPDATE users SET is_active=1 WHERE id=?", (body.get("user_id"),))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/reset-password":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error":"Forbidden"}, 403)
            np = body.get("new_password","")
            if len(np)<6: return self.send_json({"error":"Password must be 6+ chars"}, 400)
            conn = get_db(); conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(np), body.get("user_id")))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/settings":
            user = self.get_session_user()
            if not user or not user["is_admin"]: return self.send_json({"error":"Forbidden"}, 403)
            conn = get_db()
            for k, v in body.items():
                conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (k, str(v)))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        else:
            self.send_json({"error": "Not found"}, 404)

    # ─── PUT ─────────────────────────────────────────────────
    def handle_api_put(self, path):
        m = re.match(r'/api/goals/(\d+)', path)
        if m:
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            body = self.read_body(); conn = get_db()
            conn.execute("UPDATE goals SET saved=? WHERE id=? AND user_id=?", (body.get("saved",0), int(m.group(1)), user["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        m2 = re.match(r'/api/transactions/(\d+)', path)
        if m2:
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            body = self.read_body(); conn = get_db()
            conn.execute("UPDATE transactions SET date=?,description=?,amount=?,category=?,method=?,type=? WHERE id=? AND user_id=?",
                (body.get("date",""),body.get("description",""),body.get("amount",0),body.get("category","Other"),
                 body.get("method","Unknown"),body.get("type","expense"),int(m2.group(1)),user["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        self.send_json({"error":"Not found"}, 404)

    # ─── DELETE ──────────────────────────────────────────────
    def handle_api_delete(self, path):
        m = re.match(r'/api/goals/(\d+)', path)
        if m:
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db(); conn.execute("DELETE FROM goals WHERE id=? AND user_id=?", (int(m.group(1)), user["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        m2 = re.match(r'/api/transactions/(\d+)', path)
        if m2:
            user = self.get_session_user()
            if not user: return self.send_json({"error":"Unauthorized"}, 401)
            conn = get_db(); conn.execute("DELETE FROM transactions WHERE id=? AND user_id=?", (int(m2.group(1)), user["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        self.send_json({"error":"Not found"}, 404)

    # ─── SERVE FRONTEND ──────────────────────────────────────
    def serve_app(self):
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f: self.send_html(f.read())
        else: self.send_html("<h1>app.html not found</h1>", 500)

if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer((HOST, PORT), Handler)
    print(f"\n  financiQ Server running at http://localhost:{PORT}")
    print(f"  Admin: {ADMIN_USER} / {ADMIN_PASS}\n")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nShutting down..."); server.shutdown()

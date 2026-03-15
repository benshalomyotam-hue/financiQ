#!/usr/bin/env python3
"""financiQ Server v2 — Full-stack financial management. Pure Python stdlib."""

import http.server, json, sqlite3, hashlib, hmac, secrets, base64, time, os, re
import urllib.parse, urllib.request
from datetime import datetime, timedelta
from collections import defaultdict

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))
_default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "financiq.db")
DB_PATH = os.environ.get("DB_PATH", _default_db)
try: os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
except PermissionError: DB_PATH = _default_db; os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_HOURS = 24
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin123!")
LOGIN_ATTEMPTS = {}  # {ip: [(timestamp, count)]}
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 300  # 5 minutes

def hash_password(pw, salt=None):
    if not salt: salt = secrets.token_hex(16)
    return salt + ":" + hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()

def verify_password(pw, stored):
    salt = stored.split(":")[0]
    return hmac.compare_digest(hash_password(pw, salt), stored)

def sign_token(data):
    payload = json.dumps(data).encode()
    return base64.urlsafe_b64encode(payload).decode() + "." + hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()

def verify_signed_token(token):
    try:
        parts = token.split(".")
        if len(parts) != 2: return None
        payload = base64.urlsafe_b64decode(parts[0])
        if not hmac.compare_digest(hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest(), parts[1]): return None
        data = json.loads(payload)
        return data if data.get("exp", 0) >= time.time() else None
    except: return None

def check_rate_limit(ip):
    now = time.time()
    if ip in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = [(t, c) for t, c in LOGIN_ATTEMPTS[ip] if now - t < ATTEMPT_WINDOW]
        total = sum(c for _, c in LOGIN_ATTEMPTS[ip])
        if total >= MAX_ATTEMPTS: return False
    return True

def record_attempt(ip):
    now = time.time()
    if ip not in LOGIN_ATTEMPTS: LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip].append((now, 1))

TURSO_URL = os.environ.get("TURSO_URL", "")  # e.g. https://mydb-myorg.turso.io
TURSO_TOKEN = os.environ.get("TURSO_TOKEN", "")
USE_TURSO = bool(TURSO_URL and TURSO_TOKEN)

# ═══════════════ Database Adapter (Turso HTTP or local SQLite) ═══════════════
class TursoRow(dict):
    """Dict-like row that also supports index access like sqlite3.Row"""
    def __init__(self, columns, values):
        super().__init__(zip(columns, values))
        self._values = values
        self._columns = columns
    def __getitem__(self, key):
        if isinstance(key, int): return self._values[key]
        return super().__getitem__(key)
    def keys(self): return self._columns

class TursoCursor:
    def __init__(self, columns, rows, rows_affected=0):
        self.columns = columns
        self.rows = rows
        self.lastrowid = 0
        self.rowcount = rows_affected
    def fetchone(self):
        return self.rows[0] if self.rows else None
    def fetchall(self):
        return self.rows

class TursoConn:
    """Wraps Turso HTTP API to behave like sqlite3 connection"""
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.token = token
        self._pending = []  # batch statements for commit

    def _http_exec(self, statements):
        """Execute statements via Turso HTTP API"""
        body = json.dumps({"statements": statements}).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err = e.read().decode() if e.fp else str(e)
            print(f"Turso error: {err[:300]}")
            return [{"results":{"columns":[],"rows":[]},"error":None}]
        except Exception as e:
            print(f"Turso connection error: {e}")
            return [{"results":{"columns":[],"rows":[]},"error":str(e)}]

    def execute(self, sql, params=None):
        stmt = {"q": sql}
        if params:
            # Convert named or positional params
            if isinstance(params, (list, tuple)):
                stmt["params"] = [self._convert_param(p) for p in params]
            elif isinstance(params, dict):
                stmt["params"] = {k: self._convert_param(v) for k, v in params.items()}
        results = self._http_exec([stmt])
        if results and len(results) > 0:
            r = results[0]
            if "error" in r and r["error"]:
                return TursoCursor([], [], 0)
            res = r.get("results", {})
            cols = res.get("columns", [])
            raw_rows = res.get("rows", [])
            rows = [TursoRow(cols, row) for row in raw_rows]
            cursor = TursoCursor(cols, rows, res.get("rows_affected", 0))
            # Try to get lastrowid
            if "last_insert_rowid" in res:
                cursor.lastrowid = res["last_insert_rowid"]
            return cursor
        return TursoCursor([], [], 0)

    def _convert_param(self, p):
        if p is None: return None
        if isinstance(p, bool): return int(p)
        return p

    def executescript(self, script):
        """Execute multiple SQL statements"""
        stmts = [s.strip() for s in script.split(";") if s.strip()]
        if stmts:
            self._http_exec(stmts)

    def commit(self): pass  # Turso HTTP API auto-commits
    def close(self): pass

def get_db():
    if USE_TURSO:
        return TursoConn(TURSO_URL, TURSO_TOKEN)
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; conn.execute("PRAGMA journal_mode=WAL"); return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user', -- master_admin | admin | moderator | user
        is_active INTEGER DEFAULT 0, is_approved INTEGER DEFAULT 0,
        display_name TEXT DEFAULT '', lang TEXT DEFAULT 'en',
        tour_completed INTEGER DEFAULT 0, onboarding_done INTEGER DEFAULT 0,
        onboarding_data TEXT DEFAULT '{}',
        terms_accepted INTEGER DEFAULT 0, terms_accepted_at TEXT,
        created_at TEXT DEFAULT (datetime('now')), last_login TEXT, last_activity TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        date TEXT NOT NULL, description TEXT NOT NULL, amount REAL NOT NULL,
        category TEXT DEFAULT 'Other', method TEXT DEFAULT 'Unknown',
        type TEXT DEFAULT 'expense', card_name TEXT DEFAULT '',
        is_recurring INTEGER DEFAULT 0, recurring_label TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS budgets (
        user_id INTEGER NOT NULL, category TEXT NOT NULL, amount REAL NOT NULL,
        PRIMARY KEY (user_id, category), FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL, icon TEXT DEFAULT '🎯', target REAL NOT NULL,
        saved REAL DEFAULT 0, color TEXT DEFAULT '#10B981',
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS deletion_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        reason TEXT DEFAULT '', status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL, last_four TEXT DEFAULT '', color TEXT DEFAULT '#3B82F6',
        card_type TEXT DEFAULT 'credit', -- credit | debit
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS households (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, created_by INTEGER NOT NULL,
        invite_code TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS household_members (
        household_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member', -- owner | member
        joined_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY (household_id, user_id),
        FOREIGN KEY (household_id) REFERENCES households(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS ai_tips_cache (
        user_id INTEGER NOT NULL, tips TEXT NOT NULL,
        generated_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY (user_id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    # Migrations for existing DBs
    migrations = [
        ("users","role","TEXT DEFAULT 'user'"),("users","onboarding_done","INTEGER DEFAULT 0"),
        ("users","onboarding_data","TEXT DEFAULT '{}'"),("users","terms_accepted","INTEGER DEFAULT 0"),
        ("users","terms_accepted_at","TEXT"),("users","last_activity","TEXT"),
        ("users","household_id","INTEGER DEFAULT 0"),
        ("users","theme","TEXT DEFAULT 'dark'"),
        ("transactions","card_name","TEXT DEFAULT ''"),("transactions","is_recurring","INTEGER DEFAULT 0"),
        ("transactions","recurring_label","TEXT DEFAULT ''"),
    ]
    for tbl, col, typ in migrations:
        try: conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
        except: pass
    for k, v in [("global_ai_key",""),("currency","₪"),("privacy_policy",""),("terms_of_service","")]:
        conn.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (k,v))
    admin = conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
    if not admin:
        conn.execute("INSERT INTO users (username,password_hash,role,is_active,is_approved,display_name,tour_completed,terms_accepted,onboarding_done) VALUES (?,?,?,1,1,?,1,1,1)",
            (ADMIN_USER, hash_password(ADMIN_PASS), "master_admin", "Administrator"))
        print(f"\n{'='*60}\n  ADMIN: {ADMIN_USER} / {ADMIN_PASS}\n{'='*60}\n")
    else:
        conn.execute("UPDATE users SET role='master_admin' WHERE username=? AND role NOT IN ('master_admin')", (ADMIN_USER,))
    conn.commit(); conn.close()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, f, *a): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        for k,v in [("Content-Type","application/json"),("Content-Length",str(len(body))),
            ("Access-Control-Allow-Origin","*"),("Access-Control-Allow-Headers","Content-Type, Authorization"),
            ("Access-Control-Allow-Methods","GET, POST, PUT, DELETE, OPTIONS")]:
            self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)

    def send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def read_body(self):
        l = int(self.headers.get("Content-Length",0))
        if l == 0: return {}
        try: return json.loads(self.rfile.read(l))
        except: return {}

    def get_user(self):
        auth = self.headers.get("Authorization","")
        if auth.startswith("Bearer "):
            data = verify_signed_token(auth[7:])
            if data:
                conn = get_db(); u = conn.execute("SELECT * FROM users WHERE id=? AND is_active=1",(data["uid"],)).fetchone(); conn.close()
                if u: return dict(u)
        return None

    def client_ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def is_admin(self, u): return u and u.get("role") in ("master_admin","admin")
    def is_moderator(self, u): return u and u.get("role") in ("master_admin","admin","moderator")
    def is_master(self, u): return u and u.get("role") == "master_admin"

    def do_OPTIONS(self):
        self.send_response(204)
        for k,v in [("Access-Control-Allow-Origin","*"),("Access-Control-Allow-Headers","Content-Type, Authorization"),
            ("Access-Control-Allow-Methods","GET, POST, PUT, DELETE, OPTIONS")]: self.send_header(k,v)
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/","/app","/login","/register","/admin"): self.serve_app()
        elif path.startswith("/api/"): self.api_get(path)
        else: self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.api_post(path)
        else: self.send_json({"error":"Not found"},404)

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.api_put(path)
        else: self.send_json({"error":"Not found"},404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"): self.api_delete(path)
        else: self.send_json({"error":"Not found"},404)

    # ════════════════════════ GET ════════════════════════
    def api_get(self, path):
        if path == "/api/me":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            return self.send_json({k:u[k] for k in ["id","username","display_name","role","lang","tour_completed","onboarding_done","onboarding_data","terms_accepted","theme"]})

        elif path == "/api/transactions":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            query = "SELECT * FROM transactions WHERE user_id=?"
            args = [u["id"]]
            if "card" in params: query += " AND card_name=?"; args.append(params["card"][0])
            if "search" in params: query += " AND (description LIKE ? OR category LIKE ?)"; s = f"%{params['search'][0]}%"; args += [s, s]
            if "from" in params: query += " AND date>=?"; args.append(params["from"][0])
            if "to" in params: query += " AND date<=?"; args.append(params["to"][0])
            if "type" in params: query += " AND type=?"; args.append(params["type"][0])
            if "recurring" in params: query += " AND is_recurring=1"
            query += " ORDER BY date DESC"
            if "limit" in params: query += " LIMIT ?"; args.append(int(params["limit"][0]))
            rows = conn.execute(query, args).fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/budgets":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); rows = conn.execute("SELECT * FROM budgets WHERE user_id=?",(u["id"],)).fetchall(); conn.close()
            return self.send_json({r["category"]:r["amount"] for r in rows})

        elif path == "/api/goals":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); rows = conn.execute("SELECT * FROM goals WHERE user_id=?",(u["id"],)).fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/cards":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); rows = conn.execute("SELECT * FROM cards WHERE user_id=?",(u["id"],)).fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])

        elif path == "/api/settings":
            conn = get_db(); rows = conn.execute("SELECT key,value FROM settings").fetchall(); conn.close()
            result = {r["key"]:r["value"] for r in rows}
            u = self.get_user()
            if not u or not self.is_admin(u):
                if "global_ai_key" in result: result["global_ai_key"] = "***" if result["global_ai_key"] else ""
            return self.send_json(result)

        elif path == "/api/stats":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); now = datetime.now()
            ms = now.strftime("%Y-%m-01"); me = (now.replace(day=28)+timedelta(days=4)).replace(day=1).strftime("%Y-%m-%d")
            exp = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?",(u["id"],ms,me)).fetchone()
            inc = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='income' AND date>=? AND date<?",(u["id"],ms,me)).fetchone()
            tc = conn.execute("SELECT COUNT(*) as c FROM transactions WHERE user_id=?",(u["id"],)).fetchone()
            cats = conn.execute("SELECT category,SUM(amount) as total FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? GROUP BY category ORDER BY total DESC",(u["id"],ms,me)).fetchall()
            goals = conn.execute("SELECT * FROM goals WHERE user_id=?",(u["id"],)).fetchall()
            budgets = conn.execute("SELECT category,amount FROM budgets WHERE user_id=?",(u["id"],)).fetchall()
            cards_spend = conn.execute("SELECT card_name,SUM(amount) as total,COUNT(*) as cnt FROM transactions WHERE user_id=? AND type='expense' AND card_name!='' AND date>=? AND date<? GROUP BY card_name ORDER BY total DESC",(u["id"],ms,me)).fetchall()
            recurring = conn.execute("SELECT * FROM transactions WHERE user_id=? AND is_recurring=1 ORDER BY date DESC",(u["id"],)).fetchall()
            # Budget alerts
            budget_map = {r["category"]:r["amount"] for r in budgets}
            cat_map = {dict(c)["category"]:dict(c)["total"] for c in cats}
            alerts = []
            for cat, budget_amt in budget_map.items():
                spent = cat_map.get(cat, 0)
                pct = (spent / budget_amt * 100) if budget_amt > 0 else 0
                if pct >= 80: alerts.append({"category":cat,"budget":budget_amt,"spent":spent,"percent":round(pct)})
            # Anomaly detection: find transactions > 2x the average for that category
            anomalies = []
            all_tx = conn.execute("SELECT * FROM transactions WHERE user_id=? AND type='expense' ORDER BY date DESC LIMIT 200",(u["id"],)).fetchall()
            cat_amounts = defaultdict(list)
            for tx in all_tx: cat_amounts[tx["category"]].append(tx["amount"])
            for tx in conn.execute("SELECT * FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? ORDER BY amount DESC",(u["id"],ms,me)).fetchall():
                avg = sum(cat_amounts[tx["category"]]) / max(len(cat_amounts[tx["category"]]),1)
                if tx["amount"] > avg * 2.5 and tx["amount"] > 50: anomalies.append(dict(tx) | {"avg":round(avg)})
            # Duplicate detection: same amount+description within 3 days
            dupes = []
            recent = conn.execute("SELECT * FROM transactions WHERE user_id=? AND date>=? AND date<? ORDER BY date",(u["id"],ms,me)).fetchall()
            for i, a in enumerate(recent):
                for b in recent[i+1:]:
                    if a["description"]==b["description"] and a["amount"]==b["amount"] and a["id"]!=b["id"]:
                        try:
                            da, db = datetime.strptime(a["date"],"%Y-%m-%d"), datetime.strptime(b["date"],"%Y-%m-%d")
                            if abs((da-db).days) <= 3: dupes.append({"tx1":dict(a),"tx2":dict(b)})
                        except: pass
            onboarding = json.loads(u.get("onboarding_data","{}")) if u.get("onboarding_data") else {}
            # Month-over-month: last month's totals
            last_ms = (datetime.strptime(ms,"%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-01")
            last_me = ms
            prev_exp = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?",(u["id"],last_ms,last_me)).fetchone()
            prev_inc = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='income' AND date>=? AND date<?",(u["id"],last_ms,last_me)).fetchone()
            prev_cats = conn.execute("SELECT category,SUM(amount) as total FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? GROUP BY category ORDER BY total DESC",(u["id"],last_ms,last_me)).fetchall()
            # Spending forecast: daily average * days in month
            days_passed = max(now.day, 1)
            daily_avg = exp["t"] / days_passed if days_passed > 0 else 0
            import calendar
            days_in_month = calendar.monthrange(now.year, now.month)[1]
            forecast = round(daily_avg * days_in_month)
            # Household spending
            household_data = None
            hh_id = u.get("household_id", 0)
            if hh_id:
                hh = conn.execute("SELECT * FROM households WHERE id=?",(hh_id,)).fetchone()
                if hh:
                    members = conn.execute("SELECT u.id,u.display_name,u.username FROM household_members hm JOIN users u ON hm.user_id=u.id WHERE hm.household_id=?",(hh_id,)).fetchall()
                    member_spending = []
                    for m in members:
                        m_exp = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?",(m["id"],ms,me)).fetchone()
                        member_spending.append({"id":m["id"],"name":m["display_name"] or m["username"],"total":m_exp["t"]})
                    hh_total = sum(ms["total"] for ms in member_spending)
                    household_data = {"name":dict(hh)["name"],"invite_code":dict(hh)["invite_code"],"members":member_spending,"total":hh_total}
            # AI tips (cached daily)
            tips = []
            try:
                cached = conn.execute("SELECT tips,generated_at FROM ai_tips_cache WHERE user_id=?",(u["id"],)).fetchone()
                if cached and cached["generated_at"][:10] == now.strftime("%Y-%m-%d"):
                    tips = json.loads(cached["tips"])
            except: pass
            conn.close()
            return self.send_json({
                "month_expenses":exp["t"],"month_income":inc["t"],"total_transactions":tc["c"],
                "month":now.strftime("%Y-%m"),
                "categories":[{"category":c["category"],"total":c["total"]} for c in cats],
                "goals":[dict(g) for g in goals],
                "cards_spend":[dict(c) for c in cards_spend],
                "recurring":[dict(r) for r in recurring[:10]],
                "budget_alerts":alerts, "anomalies":anomalies[:5], "duplicates":dupes[:5],
                "monthly_goal":onboarding.get("monthly_expense_goal",0),
                "prev_month_expenses":prev_exp["t"],"prev_month_income":prev_inc["t"],
                "prev_categories":[{"category":c["category"],"total":c["total"]} for c in prev_cats],
                "forecast":forecast,"daily_avg":round(daily_avg),"days_passed":days_passed,"days_in_month":days_in_month,
                "household":household_data, "ai_tips":tips
            })

        elif path == "/api/export":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            txns = conn.execute("SELECT date,description,amount,category,method,type,card_name,is_recurring FROM transactions WHERE user_id=? ORDER BY date DESC",(u["id"],)).fetchall()
            conn.close()
            lines = ["date,description,amount,category,method,type,card,recurring"]
            for t in txns:
                d = dict(t)
                lines.append(",".join([str(d.get(k,"")).replace(",",";") for k in ["date","description","amount","category","method","type","card_name","is_recurring"]]))
            csv_text = "\n".join(lines)
            body = csv_text.encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type","text/csv; charset=utf-8")
            self.send_header("Content-Disposition","attachment; filename=financiq_export.csv")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers(); self.wfile.write(body); return

        elif path == "/api/admin/users":
            u = self.get_user()
            if not self.is_moderator(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db()
            rows = conn.execute("SELECT id,username,display_name,role,is_active,is_approved,created_at,last_login,lang FROM users ORDER BY created_at DESC").fetchall()
            conn.close(); return self.send_json([dict(r) for r in rows])

        elif path == "/api/admin/settings":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db(); rows = conn.execute("SELECT key,value FROM settings").fetchall(); conn.close()
            return self.send_json({r["key"]:r["value"] for r in rows})

        elif path == "/api/admin/deletion-requests":
            u = self.get_user()
            if not self.is_moderator(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db()
            rows = conn.execute("SELECT d.*, u.username, u.display_name FROM deletion_requests d JOIN users u ON d.user_id=u.id WHERE d.status='pending' ORDER BY d.created_at DESC").fetchall()
            conn.close(); return self.send_json([dict(r) for r in rows])

        else: self.send_json({"error":"Not found"},404)

    # ════════════════════════ POST ════════════════════════
    def api_post(self, path):
        body = self.read_body()

        if path == "/api/register":
            un = body.get("username","").strip().lower(); pw = body.get("password","")
            dn = body.get("display_name",un); lang = body.get("lang","en")
            if not un or not pw: return self.send_json({"error":"Username and password required"},400)
            if len(un)<3 or not re.match(r'^[a-z0-9_]+$',un): return self.send_json({"error":"Username: 3+ lowercase alphanumeric/underscore"},400)
            if len(pw)<6: return self.send_json({"error":"Password must be 6+ characters"},400)
            conn = get_db()
            if conn.execute("SELECT id FROM users WHERE username=?",(un,)).fetchone():
                conn.close(); return self.send_json({"error":"Username taken"},409)
            conn.execute("INSERT INTO users (username,password_hash,display_name,lang,is_active,is_approved) VALUES (?,?,?,?,0,0)",
                (un,hash_password(pw),dn,lang))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"message":"Account created. Waiting for admin approval."})

        elif path == "/api/login":
            ip = self.client_ip()
            if not check_rate_limit(ip):
                return self.send_json({"error":"Too many login attempts. Try again in 5 minutes."},429)
            un = body.get("username","").strip().lower(); pw = body.get("password","")
            conn = get_db(); user = conn.execute("SELECT * FROM users WHERE username=?",(un,)).fetchone()
            if not user or not verify_password(pw, user["password_hash"]):
                conn.close(); record_attempt(ip); return self.send_json({"error":"Invalid credentials"},401)
            if not user["is_approved"]: conn.close(); return self.send_json({"error":"Account pending admin approval"},403)
            if not user["is_active"]: conn.close(); return self.send_json({"error":"Account is deactivated"},403)
            conn.execute("UPDATE users SET last_login=datetime('now'),last_activity=datetime('now') WHERE id=?",(user["id"],))
            conn.commit(); conn.close()
            token = sign_token({"uid":user["id"],"user":user["username"],"role":user["role"],"exp":time.time()+SESSION_HOURS*3600})
            return self.send_json({"ok":True,"token":token,
                "user":{k:user[k] for k in ["id","username","display_name","role","lang","tour_completed","onboarding_done","terms_accepted","theme"]}})

        elif path == "/api/heartbeat":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("UPDATE users SET last_activity=datetime('now') WHERE id=?",(u["id"],)); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/accept-terms":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("UPDATE users SET terms_accepted=1,terms_accepted_at=datetime('now') WHERE id=?",(u["id"],)); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/tour-complete":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("UPDATE users SET tour_completed=1 WHERE id=?",(u["id"],)); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/onboarding":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            conn.execute("UPDATE users SET onboarding_done=1, onboarding_data=? WHERE id=?",(json.dumps(body),u["id"]))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/update-profile":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            conn.execute("UPDATE users SET lang=?,display_name=?,theme=? WHERE id=?",
                (body.get("lang",u.get("lang","en")),body.get("display_name",u.get("display_name","")),body.get("theme",u.get("theme","dark")),u["id"]))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/change-password":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            old = body.get("old_password",""); new = body.get("new_password","")
            if not verify_password(old, u["password_hash"]): return self.send_json({"error":"Current password is incorrect"},401)
            if len(new)<6: return self.send_json({"error":"New password must be 6+ characters"},400)
            conn = get_db(); conn.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(new),u["id"])); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/request-deletion":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            reason = body.get("reason","")
            conn = get_db()
            existing = conn.execute("SELECT id FROM deletion_requests WHERE user_id=? AND status='pending'",(u["id"],)).fetchone()
            if existing: conn.close(); return self.send_json({"error":"Deletion request already pending"},409)
            conn.execute("INSERT INTO deletion_requests (user_id,reason) VALUES (?,?)",(u["id"],reason))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/transactions":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            txns = body.get("transactions",[])
            if not txns: return self.send_json({"error":"No transactions"},400)
            conn = get_db()
            for tx in txns:
                conn.execute("INSERT INTO transactions (user_id,date,description,amount,category,method,type,card_name,is_recurring,recurring_label) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (u["id"],tx.get("date",""),tx.get("description",""),tx.get("amount",0),
                     tx.get("category","Other"),tx.get("method","Unknown"),tx.get("type","expense"),
                     tx.get("card_name",""),1 if tx.get("is_recurring") else 0,tx.get("recurring_label","")))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"count":len(txns)})

        elif path == "/api/budgets":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            for cat,amt in body.get("budgets",{}).items():
                conn.execute("INSERT OR REPLACE INTO budgets (user_id,category,amount) VALUES (?,?,?)",(u["id"],cat,amt))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/goals":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            cur = conn.execute("INSERT INTO goals (user_id,name,icon,target,saved,color) VALUES (?,?,?,?,?,?)",
                (u["id"],body.get("name",""),body.get("icon","🎯"),body.get("target",0),body.get("saved",0),body.get("color","#10B981")))
            conn.commit(); gid=cur.lastrowid; conn.close()
            return self.send_json({"ok":True,"id":gid})

        elif path == "/api/cards":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            cur = conn.execute("INSERT INTO cards (user_id,name,last_four,color,card_type) VALUES (?,?,?,?,?)",
                (u["id"],body.get("name",""),body.get("last_four",""),body.get("color","#3B82F6"),body.get("card_type","credit")))
            conn.commit(); cid=cur.lastrowid; conn.close()
            return self.send_json({"ok":True,"id":cid})

        elif path == "/api/budgets/delete":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            cat = body.get("category","")
            if not cat: return self.send_json({"error":"Category required"},400)
            conn = get_db(); conn.execute("DELETE FROM budgets WHERE user_id=? AND category=?",(u["id"],cat))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/household/create":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            name = body.get("name","My Household")
            invite_code = secrets.token_urlsafe(8)
            conn = get_db()
            cur = conn.execute("INSERT INTO households (name,created_by,invite_code) VALUES (?,?,?)",(name,u["id"],invite_code))
            hid = cur.lastrowid
            conn.execute("INSERT INTO household_members (household_id,user_id,role) VALUES (?,?,?)",(hid,u["id"],"owner"))
            conn.execute("UPDATE users SET household_id=? WHERE id=?",(hid,u["id"]))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"id":hid,"invite_code":invite_code})

        elif path == "/api/household/join":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            code = body.get("invite_code","").strip()
            conn = get_db()
            hh = conn.execute("SELECT * FROM households WHERE invite_code=?",(code,)).fetchone()
            if not hh: conn.close(); return self.send_json({"error":"Invalid invite code"},404)
            existing = conn.execute("SELECT * FROM household_members WHERE household_id=? AND user_id=?",(hh["id"],u["id"])).fetchone()
            if existing: conn.close(); return self.send_json({"error":"Already a member"},409)
            conn.execute("INSERT INTO household_members (household_id,user_id,role) VALUES (?,?,?)",(hh["id"],u["id"],"member"))
            conn.execute("UPDATE users SET household_id=? WHERE id=?",(hh["id"],u["id"]))
            conn.commit(); conn.close()
            return self.send_json({"ok":True,"household_name":hh["name"]})

        elif path == "/api/household/leave":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            hid = u.get("household_id",0)
            if not hid: return self.send_json({"error":"Not in a household"},400)
            conn = get_db()
            conn.execute("DELETE FROM household_members WHERE household_id=? AND user_id=?",(hid,u["id"]))
            conn.execute("UPDATE users SET household_id=0 WHERE id=?",(u["id"],))
            remaining = conn.execute("SELECT COUNT(*) as c FROM household_members WHERE household_id=?",(hid,)).fetchone()
            if remaining["c"]==0: conn.execute("DELETE FROM households WHERE id=?",(hid,))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/generate-tips":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db()
            key_row = conn.execute("SELECT value FROM settings WHERE key='global_ai_key'").fetchone()
            ai_key = key_row["value"] if key_row else ""
            if not ai_key: conn.close(); return self.send_json({"error":"AI not configured"},400)
            now = datetime.now(); ms=now.strftime("%Y-%m-01"); me=(now.replace(day=28)+timedelta(days=4)).replace(day=1).strftime("%Y-%m-%d")
            exp_t = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?",(u["id"],ms,me)).fetchone()
            cats = conn.execute("SELECT category,SUM(amount) as total FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? GROUP BY category ORDER BY total DESC LIMIT 5",(u["id"],ms,me)).fetchall()
            onboarding = json.loads(u.get("onboarding_data","{}") or "{}")
            lang = u.get("lang","en")
            cat_text = ", ".join([f"{dict(c)['category']}:{dict(c)['total']:.0f}" for c in cats])
            prompt = f"""Based on this user's spending data, generate exactly 3 short actionable financial tips. Each tip should be 1 sentence max.
Monthly expenses: {exp_t['t']:.0f}. Top categories: {cat_text}. Goals: {onboarding.get('app_goals',[])}. Monthly target: {onboarding.get('monthly_expense_goal','not set')}.
Respond in {'Hebrew' if lang=='he' else 'English'}. Return ONLY a JSON array of 3 strings, nothing else. Example: ["Tip 1","Tip 2","Tip 3"]"""
            is_anthropic = ai_key.startswith("sk-ant-")
            try:
                if is_anthropic:
                    api_body = json.dumps({"model":"claude-sonnet-4-20250514","max_tokens":300,"messages":[{"role":"user","content":prompt}]}).encode()
                    req = urllib.request.Request("https://api.anthropic.com/v1/messages",data=api_body,
                        headers={"Content-Type":"application/json","x-api-key":ai_key,"anthropic-version":"2023-06-01"})
                    with urllib.request.urlopen(req,timeout=15) as resp: result=json.loads(resp.read())
                    text = result.get("content",[{}])[0].get("text","[]")
                else:
                    api_body = json.dumps({"model":"gpt-4o-mini","messages":[{"role":"user","content":prompt}],"max_tokens":300}).encode()
                    req = urllib.request.Request("https://api.openai.com/v1/chat/completions",data=api_body,
                        headers={"Content-Type":"application/json","Authorization":f"Bearer {ai_key}"})
                    with urllib.request.urlopen(req,timeout=15) as resp: result=json.loads(resp.read())
                    text = result.get("choices",[{}])[0].get("message",{}).get("content","[]")
                # Parse tips
                text = text.strip()
                if text.startswith("```"): text = text.split("```")[1].replace("json","").strip()
                tips = json.loads(text)
                if not isinstance(tips,list): tips = [str(tips)]
                conn.execute("INSERT OR REPLACE INTO ai_tips_cache (user_id,tips,generated_at) VALUES (?,?,datetime('now'))",(u["id"],json.dumps(tips)))
                conn.commit(); conn.close()
                return self.send_json({"ok":True,"tips":tips})
            except Exception as e:
                conn.close()
                return self.send_json({"error":f"Tips generation failed: {str(e)[:200]}"},500)

        elif path == "/api/scan-receipt":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            image_data = body.get("image","")  # base64 encoded image
            if not image_data: return self.send_json({"error":"No image provided"},400)
            conn = get_db()
            key_row = conn.execute("SELECT value FROM settings WHERE key='global_ai_key'").fetchone()
            conn.close()
            ai_key = key_row["value"] if key_row else ""
            if not ai_key: return self.send_json({"error":"AI not configured"},400)
            lang = u.get("lang","en")
            prompt = f"""Extract transaction data from this receipt image. Return ONLY a JSON object with these fields:
{{"date":"YYYY-MM-DD","description":"store/vendor name","amount":number,"category":"one of: Food,Shopping,Transport,Entertainment,Bills,Health,Education,Other"}}
If you can't read the receipt, return {{"error":"Cannot read receipt"}}. Respond in {'Hebrew' if lang=='he' else 'English'} for the description."""
            is_anthropic = ai_key.startswith("sk-ant-")
            try:
                if is_anthropic:
                    # Clean base64
                    if "," in image_data: image_data = image_data.split(",")[1]
                    media_type = "image/jpeg"
                    api_body = json.dumps({"model":"claude-sonnet-4-20250514","max_tokens":300,
                        "messages":[{"role":"user","content":[
                            {"type":"image","source":{"type":"base64","media_type":media_type,"data":image_data}},
                            {"type":"text","text":prompt}]}]}).encode()
                    req = urllib.request.Request("https://api.anthropic.com/v1/messages",data=api_body,
                        headers={"Content-Type":"application/json","x-api-key":ai_key,"anthropic-version":"2023-06-01"})
                    with urllib.request.urlopen(req,timeout=30) as resp: result=json.loads(resp.read())
                    text = result.get("content",[{}])[0].get("text","{}")
                else:
                    if "," not in image_data: image_data = "data:image/jpeg;base64,"+image_data
                    api_body = json.dumps({"model":"gpt-4o-mini","messages":[{"role":"user","content":[
                        {"type":"image_url","image_url":{"url":image_data}},
                        {"type":"text","text":prompt}]}],"max_tokens":300}).encode()
                    req = urllib.request.Request("https://api.openai.com/v1/chat/completions",data=api_body,
                        headers={"Content-Type":"application/json","Authorization":f"Bearer {ai_key}"})
                    with urllib.request.urlopen(req,timeout=30) as resp: result=json.loads(resp.read())
                    text = result.get("choices",[{}])[0].get("message",{}).get("content","{}")
                text = text.strip()
                if text.startswith("```"): text = text.split("```")[1].replace("json","").strip()
                parsed = json.loads(text)
                if "error" in parsed: return self.send_json({"error":parsed["error"]},400)
                return self.send_json({"ok":True,"transaction":parsed})
            except Exception as e:
                return self.send_json({"error":f"Scan failed: {str(e)[:200]}"},500)

        elif path == "/api/admin/approve":
            u = self.get_user()
            if not self.is_moderator(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db(); conn.execute("UPDATE users SET is_approved=1,is_active=1 WHERE id=?",(body.get("user_id"),))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/deactivate":
            u = self.get_user()
            if not self.is_moderator(u): return self.send_json({"error":"Forbidden"},403)
            uid = body.get("user_id")
            conn = get_db(); target = conn.execute("SELECT role FROM users WHERE id=?",(uid,)).fetchone()
            if target and target["role"]=="master_admin": conn.close(); return self.send_json({"error":"Cannot deactivate master admin"},403)
            conn.execute("UPDATE users SET is_active=0 WHERE id=?",(uid,)); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/admin/activate":
            u = self.get_user()
            if not self.is_moderator(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db(); conn.execute("UPDATE users SET is_active=1 WHERE id=?",(body.get("user_id"),))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/set-role":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            uid = body.get("user_id"); new_role = body.get("role","user")
            conn = get_db(); target = conn.execute("SELECT role FROM users WHERE id=?",(uid,)).fetchone()
            if not target: conn.close(); return self.send_json({"error":"User not found"},404)
            if target["role"]=="master_admin": conn.close(); return self.send_json({"error":"Cannot change master admin role"},403)
            if new_role=="master_admin": conn.close(); return self.send_json({"error":"Cannot grant master admin"},403)
            if new_role not in ("admin","moderator","user"): conn.close(); return self.send_json({"error":"Invalid role"},400)
            # Only master_admin can make someone admin
            if new_role=="admin" and not self.is_master(u): conn.close(); return self.send_json({"error":"Only master admin can grant admin role"},403)
            conn.execute("UPDATE users SET role=? WHERE id=?",(new_role,uid)); conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/admin/reset-password":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            np = body.get("new_password","")
            if len(np)<6: return self.send_json({"error":"Password must be 6+ chars"},400)
            conn = get_db(); conn.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(np),body.get("user_id")))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/admin/delete-user":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            uid = body.get("user_id")
            conn = get_db(); target = conn.execute("SELECT role FROM users WHERE id=?",(uid,)).fetchone()
            if not target: conn.close(); return self.send_json({"error":"User not found"},404)
            if target["role"]=="master_admin": conn.close(); return self.send_json({"error":"Cannot delete master admin"},403)
            conn.execute("DELETE FROM transactions WHERE user_id=?",(uid,))
            conn.execute("DELETE FROM budgets WHERE user_id=?",(uid,))
            conn.execute("DELETE FROM goals WHERE user_id=?",(uid,))
            conn.execute("DELETE FROM cards WHERE user_id=?",(uid,))
            conn.execute("DELETE FROM deletion_requests WHERE user_id=?",(uid,))
            conn.execute("DELETE FROM users WHERE id=?",(uid,))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/admin/resolve-deletion":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            rid = body.get("request_id"); action = body.get("action","reject")
            conn = get_db()
            req = conn.execute("SELECT * FROM deletion_requests WHERE id=?",(rid,)).fetchone()
            if not req: conn.close(); return self.send_json({"error":"Not found"},404)
            if action=="approve":
                uid = req["user_id"]
                target = conn.execute("SELECT role FROM users WHERE id=?",(uid,)).fetchone()
                if target and target["role"]=="master_admin": conn.close(); return self.send_json({"error":"Cannot delete master admin"},403)
                conn.execute("DELETE FROM transactions WHERE user_id=?",(uid,))
                conn.execute("DELETE FROM budgets WHERE user_id=?",(uid,))
                conn.execute("DELETE FROM goals WHERE user_id=?",(uid,))
                conn.execute("DELETE FROM cards WHERE user_id=?",(uid,))
                conn.execute("DELETE FROM users WHERE id=?",(uid,))
                conn.execute("UPDATE deletion_requests SET status='approved' WHERE id=?",(rid,))
            else:
                conn.execute("UPDATE deletion_requests SET status='rejected' WHERE id=?",(rid,))
            conn.commit(); conn.close()
            return self.send_json({"ok":True})

        elif path == "/api/admin/settings":
            u = self.get_user()
            if not self.is_admin(u): return self.send_json({"error":"Forbidden"},403)
            conn = get_db()
            for k,v in body.items(): conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",(k,str(v)))
            conn.commit(); conn.close(); return self.send_json({"ok":True})

        elif path == "/api/ai-chat":
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            message = body.get("message","").strip()
            history = body.get("history",[])
            if not message: return self.send_json({"error":"Message required"},400)
            conn = get_db()
            key_row = conn.execute("SELECT value FROM settings WHERE key='global_ai_key'").fetchone()
            now = datetime.now(); ms=now.strftime("%Y-%m-01"); me=(now.replace(day=28)+timedelta(days=4)).replace(day=1).strftime("%Y-%m-%d")
            txns = conn.execute("SELECT date,description,amount,category,type,card_name FROM transactions WHERE user_id=? ORDER BY date DESC LIMIT 40",(u["id"],)).fetchall()
            exp_t = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<?",(u["id"],ms,me)).fetchone()
            inc_t = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE user_id=? AND type='income' AND date>=? AND date<?",(u["id"],ms,me)).fetchone()
            cats = conn.execute("SELECT category,SUM(amount) as total FROM transactions WHERE user_id=? AND type='expense' AND date>=? AND date<? GROUP BY category ORDER BY total DESC",(u["id"],ms,me)).fetchall()
            goals_d = conn.execute("SELECT name,target,saved FROM goals WHERE user_id=?",(u["id"],)).fetchall()
            budgets_d = conn.execute("SELECT category,amount FROM budgets WHERE user_id=?",(u["id"],)).fetchall()
            onboarding = json.loads(u.get("onboarding_data","{}") or "{}")
            conn.close()
            ai_key = key_row["value"] if key_row else ""
            if not ai_key: return self.send_json({"error":"AI API key not configured. Ask admin."},400)
            lang = u.get("lang","en")
            tx_lines = "\n".join([f"  {dict(r)['date']}|{dict(r)['description']}|{dict(r)['amount']}|{dict(r)['category']}|{dict(r)['type']}|{dict(r)['card_name']}" for r in txns[:30]])
            cat_lines = "\n".join([f"  {dict(c)['category']}:{dict(c)['total']:.0f}" for c in cats])
            goal_lines = "\n".join([f"  {dict(g)['name']}:{dict(g)['saved']:.0f}/{dict(g)['target']:.0f}" for g in goals_d])
            budget_lines = "\n".join([f"  {dict(b)['category']}:{dict(b)['amount']:.0f}" for b in budgets_d])
            user_goals_text = ""
            if onboarding:
                user_goals_text = f"\nUser's goals: {onboarding.get('app_goals',[])}. Monthly expense target: {onboarding.get('monthly_expense_goal','not set')}."
            sys_prompt = f"""You are financiQ AI, a helpful financial advisor. Respond in {'Hebrew' if lang=='he' else 'English'}. Be concise, actionable. Use ₪.{user_goals_text}

IMPORTANT: You can add transactions for the user! When the user tells you about an expense or income (e.g. "I spent 50 on coffee" or "I got paid 8000"), extract the details and include this EXACT format at the END of your message on its own line:
[ADD_TX:{{"date":"{now.strftime('%Y-%m-%d')}","description":"...","amount":NUMBER,"category":"...","type":"expense or income"}}]
Categories: Food,Transport,Shopping,Entertainment,Bills,Health,Education,Salary,Freelance,Gift,Mortgage,Insurance,Subscription,Other
If the user doesn't specify a date, use today. If they don't specify a category, guess the best one. Always confirm what you're adding in your text response before the [ADD_TX:...] line.

DATA ({now.strftime('%B %Y')}): Expenses:{exp_t['t']:.0f} Income:{inc_t['t']:.0f} Net:{inc_t['t']-exp_t['t']:.0f}
Categories:\n{cat_lines or 'None'}
Goals:\n{goal_lines or 'None'}
Budgets:\n{budget_lines or 'None'}
Transactions:\n{tx_lines or 'None'}"""
            messages = [{"role":m.get("role","user"),"content":m.get("content","")} for m in history[-10:]]
            messages.append({"role":"user","content":message})
            is_anthropic = ai_key.startswith("sk-ant-")
            try:
                if is_anthropic:
                    api_body = json.dumps({"model":"claude-sonnet-4-20250514","max_tokens":1024,"system":sys_prompt,"messages":messages}).encode()
                    req = urllib.request.Request("https://api.anthropic.com/v1/messages",data=api_body,
                        headers={"Content-Type":"application/json","x-api-key":ai_key,"anthropic-version":"2023-06-01"})
                    with urllib.request.urlopen(req,timeout=30) as resp: result=json.loads(resp.read())
                    reply = result.get("content",[{}])[0].get("text","No response")
                else:
                    api_msgs = [{"role":"system","content":sys_prompt}]+messages
                    api_body = json.dumps({"model":"gpt-4o-mini","messages":api_msgs,"max_tokens":1024}).encode()
                    req = urllib.request.Request("https://api.openai.com/v1/chat/completions",data=api_body,
                        headers={"Content-Type":"application/json","Authorization":f"Bearer {ai_key}"})
                    with urllib.request.urlopen(req,timeout=30) as resp: result=json.loads(resp.read())
                    reply = result.get("choices",[{}])[0].get("message",{}).get("content","No response")
                # Parse ADD_TX commands from AI response
                added_tx = None
                import re as re2
                tx_match = re2.search(r'\[ADD_TX:(\{.*?\})\]', reply)
                if tx_match:
                    try:
                        tx_data = json.loads(tx_match.group(1))
                        conn2 = get_db()
                        conn2.execute("INSERT INTO transactions (user_id,date,description,amount,category,method,type) VALUES (?,?,?,?,?,?,?)",
                            (u["id"], tx_data.get("date",""), tx_data.get("description",""), tx_data.get("amount",0),
                             tx_data.get("category","Other"), "AI Agent", tx_data.get("type","expense")))
                        conn2.commit(); conn2.close()
                        added_tx = tx_data
                        # Clean the command from the visible reply
                        reply = reply.replace(tx_match.group(0), "").strip()
                    except: pass
                return self.send_json({"ok":True,"reply":reply,"added_tx":added_tx})
            except urllib.error.HTTPError as e:
                err = e.read().decode() if e.fp else str(e)
                return self.send_json({"error":f"AI error ({e.code}): {err[:200]}"},502)
            except Exception as e:
                return self.send_json({"error":f"AI failed: {str(e)[:200]}"},500)

        else: self.send_json({"error":"Not found"},404)

    # ════════════════════════ PUT ════════════════════════
    def api_put(self, path):
        m = re.match(r'/api/goals/(\d+)',path)
        if m:
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            body = self.read_body(); conn = get_db()
            conn.execute("UPDATE goals SET saved=? WHERE id=? AND user_id=?",(body.get("saved",0),int(m.group(1)),u["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        m2 = re.match(r'/api/transactions/(\d+)',path)
        if m2:
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            body = self.read_body(); conn = get_db()
            conn.execute("UPDATE transactions SET date=?,description=?,amount=?,category=?,method=?,type=?,card_name=?,is_recurring=?,recurring_label=? WHERE id=? AND user_id=?",
                (body.get("date",""),body.get("description",""),body.get("amount",0),body.get("category","Other"),
                 body.get("method","Unknown"),body.get("type","expense"),body.get("card_name",""),
                 1 if body.get("is_recurring") else 0,body.get("recurring_label",""),int(m2.group(1)),u["id"]))
            conn.commit(); conn.close(); return self.send_json({"ok":True})
        self.send_json({"error":"Not found"},404)

    # ════════════════════════ DELETE ════════════════════════
    def api_delete(self, path):
        m = re.match(r'/api/goals/(\d+)',path)
        if m:
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("DELETE FROM goals WHERE id=? AND user_id=?",(int(m.group(1)),u["id"])); conn.commit(); conn.close()
            return self.send_json({"ok":True})
        m2 = re.match(r'/api/transactions/(\d+)',path)
        if m2:
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("DELETE FROM transactions WHERE id=? AND user_id=?",(int(m2.group(1)),u["id"])); conn.commit(); conn.close()
            return self.send_json({"ok":True})
        m3 = re.match(r'/api/cards/(\d+)',path)
        if m3:
            u = self.get_user()
            if not u: return self.send_json({"error":"Unauthorized"},401)
            conn = get_db(); conn.execute("DELETE FROM cards WHERE id=? AND user_id=?",(int(m3.group(1)),u["id"])); conn.commit(); conn.close()
            return self.send_json({"ok":True})
        self.send_json({"error":"Not found"},404)

    def serve_app(self):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),"app.html")
        if os.path.exists(p):
            with open(p,"r",encoding="utf-8") as f: self.send_html(f.read())
        else: self.send_html("<h1>app.html not found</h1>",500)

if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer((HOST,PORT),Handler)
    print(f"\n  financiQ Server running at http://localhost:{PORT}\n  Admin: {ADMIN_USER} / {ADMIN_PASS}\n")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nShutting down..."); server.shutdown()

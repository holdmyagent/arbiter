import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.isoformat()

SCHEMA_VERSION = 5

def _migrate_0_to_1(conn):
    """Baseline v1 schema; also normalizes pre-versioning DBs created by the
    old executescript+try/except-ALTER path (columns may already exist)."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS requests(
      id TEXT PRIMARY KEY, created_at TEXT, title TEXT, description TEXT,
      action_type TEXT, payload TEXT, severity TEXT, status TEXT,
      ttl_seconds INTEGER, expires_at TEXT, decided_at TEXT, decided_by TEXT);
    CREATE TABLE IF NOT EXISTS devices(
      id TEXT PRIMARY KEY, apns_token TEXT UNIQUE, name TEXT, registered_at TEXT);
    CREATE TABLE IF NOT EXISTS audit(
      id TEXT PRIMARY KEY, request_id TEXT, event TEXT, at TEXT, detail TEXT);
    """)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    if "min_severity" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN min_severity TEXT DEFAULT 'low'")
    if "notifications_enabled" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN notifications_enabled INTEGER DEFAULT 1")
    if "sound" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN sound INTEGER DEFAULT 1")

def _migrate_1_to_2(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(requests)")}
    if "target" not in cols:
        conn.execute("ALTER TABLE requests ADD COLUMN target TEXT")
    if "callback_url" not in cols:
        conn.execute("ALTER TABLE requests ADD COLUMN callback_url TEXT")

def _migrate_2_to_3(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    if "severities" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN severities TEXT")
    if "badge" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN badge INTEGER DEFAULT 0")

def _migrate_3_to_4(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tokens(
      id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('agent','warden','app')),
      token_hash TEXT NOT NULL,
      scopes TEXT,
      created_at TEXT NOT NULL, expires_at TEXT, last_used_at TEXT, revoked_at TEXT);
    """)

def _migrate_4_to_5(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(requests)")}
    for col in ("canonical_action", "action_hash", "verdict_jws", "verdict_kid",
                "consumed_at", "idempotency_key", "requested_by"):
        if col not in cols:
            conn.execute(f"ALTER TABLE requests ADD COLUMN {col} TEXT")
    conn.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_idem
      ON requests(requested_by, idempotency_key)
      WHERE idempotency_key IS NOT NULL""")

MIGRATIONS = [_migrate_0_to_1, _migrate_1_to_2, _migrate_2_to_3, _migrate_3_to_4, _migrate_4_to_5]

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        v = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if v == 0 and self.conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='requests'").fetchone()[0]:
            pass  # pre-versioning DB: run every migration; each is idempotent
        for i in range(v, SCHEMA_VERSION):
            MIGRATIONS[i](self.conn)
        if v < SCHEMA_VERSION:
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.conn.commit()

    def _row_to_request(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["payload"] = json.loads(d["payload"])
        return d

    def _row_to_device(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["severities"] = json.loads(d["severities"]) if d["severities"] is not None else None
        return d

    def add_audit(self, request_id: str, event: str, detail: dict | None = None):
        self.conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), request_id, event, _iso(_utcnow()), json.dumps(detail or {})),
        )
        self.conn.commit()

    def create_request(self, c, requested_by: str | None = None) -> dict:
        now = _utcnow()
        rid = str(uuid.uuid4())
        expires = now + timedelta(seconds=c.ttl_seconds)
        self.conn.execute(
            "INSERT INTO requests(id,created_at,title,description,action_type,payload,"
            "severity,status,ttl_seconds,expires_at,decided_at,decided_by,target,callback_url,"
            "requested_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, _iso(now), c.title, c.description, c.action_type,
             json.dumps(c.payload), c.severity, "pending", c.ttl_seconds,
             _iso(expires), None, None, c.target, c.callback_url, requested_by),
        )
        self.conn.commit()
        self.add_audit(rid, "created", {"severity": c.severity})
        return self.get_request(rid)

    def get_request(self, rid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return self._row_to_request(r) if r else None

    def list_requests(self, status: str | None = None) -> list[dict]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM requests WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM requests ORDER BY created_at DESC").fetchall()
        return [self._row_to_request(r) for r in rows]

    def set_decision(self, rid: str, decision: str, by: str) -> dict | None:
        r = self.get_request(rid)
        if not r or r["status"] != "pending":
            return None
        status = "approved" if decision == "approve" else "denied"
        self.conn.execute(
            "UPDATE requests SET status=?, decided_at=?, decided_by=? WHERE id=?",
            (status, _iso(_utcnow()), by, rid))
        self.conn.commit()
        self.add_audit(rid, status, {"by": by})
        return self.get_request(rid)

    def expire_due(self, now: datetime | None = None) -> list[dict]:
        now = now or _utcnow()
        rows = self.conn.execute(
            "SELECT id FROM requests WHERE status='pending' AND expires_at < ?",
            (_iso(now),)).fetchall()
        for r in rows:
            self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
            self.add_audit(r["id"], "expired", {})
        return [self.get_request(r["id"]) for r in rows]

    def register_device(self, apns_token: str, name: str, min_severity: str = "low",
                        notifications_enabled: bool = True, sound: bool = True,
                        severities: dict | None = None, badge: bool = False) -> dict:
        ne_int = 1 if notifications_enabled else 0
        snd_int = 1 if sound else 0
        badge_int = 1 if badge else 0
        sev_json = json.dumps(severities) if severities is not None else None
        existing = self.conn.execute(
            "SELECT * FROM devices WHERE apns_token=?", (apns_token,)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE devices SET name=?, min_severity=?, notifications_enabled=?, sound=?, "
                "severities=?, badge=? WHERE apns_token=?",
                (name, min_severity, ne_int, snd_int, sev_json, badge_int, apns_token))
        else:
            self.conn.execute(
                "INSERT INTO devices(id, apns_token, name, registered_at, min_severity, "
                "notifications_enabled, sound, severities, badge)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), apns_token, name, _iso(_utcnow()), min_severity,
                 ne_int, snd_int, sev_json, badge_int))
        self.conn.commit()
        return self._row_to_device(self.conn.execute("SELECT * FROM devices WHERE apns_token=?", (apns_token,)).fetchone())

    def list_devices(self) -> list[dict]:
        return [self._row_to_device(r) for r in self.conn.execute("SELECT * FROM devices").fetchall()]

    def get_audit(self, rid: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM audit WHERE request_id=? ORDER BY at", (rid,)).fetchall()]

    def list_audit(self, request_id: str | None = None, limit: int = 200) -> list[dict]:
        # LEFT JOIN requests for severity/title/decided_by, plus a scalar subquery
        # (not a JOIN on devices.name) to resolve the deciding device: a JOIN on
        # name could fan out an audit row if two devices ever shared a name.
        base = (
            "SELECT a.id, a.request_id, a.event, a.at, a.detail,"
            " r.severity AS severity, r.title AS req_title, r.status AS req_status,"
            " r.decided_by AS decided_by,"
            " (SELECT d.name FROM devices d WHERE d.name = r.decided_by LIMIT 1) AS decided_device"
            " FROM audit a LEFT JOIN requests r ON a.request_id = r.id"
        )
        if request_id:
            rows = self.conn.execute(
                base + " WHERE a.request_id = ? ORDER BY a.at DESC LIMIT ?",
                (request_id, limit)).fetchall()
        else:
            rows = self.conn.execute(
                base + " ORDER BY a.at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def rename_device(self, device_id: str, name: str) -> dict | None:
        self.conn.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
        self.conn.commit()
        r = self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return dict(r) if r else None

    def delete_device(self, device_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # ── tokens (per-identity bearer credentials, hashed at rest) ────────────

    def _row_to_token(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["scopes"] = json.loads(d["scopes"]) if d["scopes"] is not None else None
        return d

    def create_token(self, name: str, role: str, token_hash: str,
                     scopes: dict | None = None, expires_at: str | None = None) -> dict:
        tid = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,expires_at,"
            "last_used_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, name, role, token_hash,
             json.dumps(scopes) if scopes is not None else None,
             _iso(_utcnow()), expires_at, None, None))
        self.conn.commit()
        return self._row_to_token(
            self.conn.execute("SELECT * FROM tokens WHERE id=?", (tid,)).fetchone())

    def get_token_by_hash(self, token_hash: str) -> dict | None:
        r = self.conn.execute(
            "SELECT * FROM tokens WHERE token_hash=?", (token_hash,)).fetchone()
        return self._row_to_token(r) if r else None

    def list_tokens(self) -> list[dict]:
        return [self._row_to_token(r) for r in self.conn.execute(
            "SELECT * FROM tokens ORDER BY created_at").fetchall()]

    def revoke_token(self, name: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM tokens WHERE name=?", (name,)).fetchone()
        if r is None:
            return None
        if r["revoked_at"] is None:
            self.conn.execute("UPDATE tokens SET revoked_at=? WHERE name=?",
                              (_iso(_utcnow()), name))
            self.conn.commit()
        return self._row_to_token(
            self.conn.execute("SELECT * FROM tokens WHERE name=?", (name,)).fetchone())

    def touch_token_last_used(self, token_id: str) -> None:
        self.conn.execute("UPDATE tokens SET last_used_at=? WHERE id=?",
                          (_iso(_utcnow()), token_id))
        self.conn.commit()

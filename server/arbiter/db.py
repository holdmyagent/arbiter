import json, sqlite3, uuid
from datetime import datetime, timedelta, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.isoformat()

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY, created_at TEXT, title TEXT, description TEXT,
  action_type TEXT, payload TEXT, severity TEXT, status TEXT,
  ttl_seconds INTEGER, expires_at TEXT, decided_at TEXT, decided_by TEXT);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, apns_token TEXT UNIQUE, name TEXT, registered_at TEXT,
  min_severity TEXT DEFAULT 'low',
  notifications_enabled INTEGER DEFAULT 1,
  sound INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit(
  id TEXT PRIMARY KEY, request_id TEXT, event TEXT, at TEXT, detail TEXT);
"""

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        # Migration guards: add columns to pre-existing devices tables that lack them.
        try:
            self.conn.execute("ALTER TABLE devices ADD COLUMN min_severity TEXT DEFAULT 'low'")
        except sqlite3.OperationalError:
            pass  # column already exists — normal for fresh DBs created by SCHEMA above
        try:
            self.conn.execute("ALTER TABLE devices ADD COLUMN notifications_enabled INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            self.conn.execute("ALTER TABLE devices ADD COLUMN sound INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        self.conn.commit()

    def _row_to_request(self, r: sqlite3.Row) -> dict:
        d = dict(r); d["payload"] = json.loads(d["payload"]); return d

    def add_audit(self, request_id: str, event: str, detail: dict | None = None):
        self.conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), request_id, event, _iso(_utcnow()), json.dumps(detail or {})),
        ); self.conn.commit()

    def create_request(self, c) -> dict:
        now = _utcnow(); rid = str(uuid.uuid4())
        expires = now + timedelta(seconds=c.ttl_seconds)
        self.conn.execute(
            "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, _iso(now), c.title, c.description, c.action_type,
             json.dumps(c.payload), c.severity, "pending", c.ttl_seconds,
             _iso(expires), None, None),
        ); self.conn.commit()
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
            (status, _iso(_utcnow()), by, rid)); self.conn.commit()
        self.add_audit(rid, status, {"by": by})
        return self.get_request(rid)

    def expire_due(self, now: datetime | None = None) -> int:
        now = now or _utcnow()
        rows = self.conn.execute(
            "SELECT id FROM requests WHERE status='pending' AND expires_at < ?",
            (_iso(now),)).fetchall()
        for r in rows:
            self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
            self.add_audit(r["id"], "expired", {})
        return len(rows)

    def register_device(self, apns_token: str, name: str, min_severity: str = "low",
                        notifications_enabled: bool = True, sound: bool = True) -> dict:
        ne_int = 1 if notifications_enabled else 0
        snd_int = 1 if sound else 0
        existing = self.conn.execute(
            "SELECT * FROM devices WHERE apns_token=?", (apns_token,)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE devices SET name=?, min_severity=?, notifications_enabled=?, sound=? WHERE apns_token=?",
                (name, min_severity, ne_int, snd_int, apns_token))
        else:
            self.conn.execute(
                "INSERT INTO devices(id, apns_token, name, registered_at, min_severity, notifications_enabled, sound)"
                " VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), apns_token, name, _iso(_utcnow()), min_severity, ne_int, snd_int))
        self.conn.commit()
        return dict(self.conn.execute("SELECT * FROM devices WHERE apns_token=?", (apns_token,)).fetchone())

    def list_devices(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM devices").fetchall()]

    def get_audit(self, rid: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM audit WHERE request_id=? ORDER BY at", (rid,)).fetchall()]

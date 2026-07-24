import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.isoformat()

SCHEMA_VERSION = 11

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

def _migrate_5_to_6(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS outbox(
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      event TEXT NOT NULL,
      payload TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      request_expires_at TEXT NOT NULL)""")

def _migrate_6_to_7(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS pairings(
      code_hash TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT)""")

def _migrate_7_to_8(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS notify_sent(
      request_id TEXT NOT NULL,
      event TEXT NOT NULL,
      sent_at TEXT NOT NULL,
      PRIMARY KEY(request_id, event))""")

def _migrate_8_to_9(conn):
    # resolve_identity looks tokens up by hash on EVERY authenticated request
    # (get_token_by_hash); without an index that's a table scan (warden RR).
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash)")

def _migrate_9_to_10(conn):
    """DB-level duplicate-collapse backstop for the in-route check (app.py
    create / find_duplicate_pending): at most one PENDING row per
    (requested_by, action_hash) for hash-bound creates and per
    (requested_by, title) for unbound ones. Pre-existing duplicates (raced in
    before this index existed) are collapsed first — the oldest row per group
    (the one earlier creates were handed back) stays pending, later twins flip
    to 'expired' with an audit row, mirroring invalidate_in_flight's style.
    The strict (created_at, id)-minimum of each group is never selected (no
    earlier witness exists for it), so exactly one row per group survives.
    requested_by IS NULL rows are exempt (SQLite UNIQUE treats NULLs as
    distinct): for legacy unstamped creates the in-route check remains the
    only collapse, exactly as before."""
    dupes = conn.execute("""
        SELECT id FROM requests AS r
        WHERE status='pending' AND requested_by IS NOT NULL
          AND EXISTS (SELECT 1 FROM requests AS k
                      WHERE k.status='pending'
                        AND k.requested_by = r.requested_by
                        AND ((r.action_hash IS NOT NULL AND k.action_hash = r.action_hash)
                             OR (r.action_hash IS NULL AND k.action_hash IS NULL
                                 AND k.title = r.title))
                        AND (k.created_at < r.created_at
                             OR (k.created_at = r.created_at AND k.id < r.id)))""").fetchall()
    for row in dupes:
        conn.execute("UPDATE requests SET status='expired' WHERE id=?", (row[0],))
        conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                     (str(uuid.uuid4()), row[0], "expired", _iso(_utcnow()),
                      json.dumps({"reason": "duplicate_collapsed"})))
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_dup_hash
        ON requests(requested_by, action_hash)
        WHERE status='pending' AND action_hash IS NOT NULL""")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_dup_title
        ON requests(requested_by, title)
        WHERE status='pending' AND action_hash IS NULL""")

def _migrate_10_to_11(conn):
    """Gate-policy store (feature: server-mediated gate policy). Per-cell:
    named presets, one overlay row, one active-selection row, and a monotonic
    meta counter (version) + generation (epoch, for cache-adoption keying)."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS policy_presets(
      name TEXT PRIMARY KEY,
      block_patterns TEXT NOT NULL,
      allow_patterns TEXT NOT NULL,
      tool_allowlist TEXT NOT NULL,
      default_decision TEXT NOT NULL CHECK(default_decision IN ('ask','allow')));
    CREATE TABLE IF NOT EXISTS policy_kv(
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL);
    """)
    conn.execute("INSERT OR IGNORE INTO policy_kv(k,v) VALUES ('version','0')")
    conn.execute("INSERT OR IGNORE INTO policy_kv(k,v) VALUES ('epoch','1')")
    conn.execute("INSERT OR IGNORE INTO policy_kv(k,v) VALUES ('overlay',?)",
                 (json.dumps({"always_ask": [], "always_allow": []}),))

MIGRATIONS = [_migrate_0_to_1, _migrate_1_to_2, _migrate_2_to_3, _migrate_3_to_4, _migrate_4_to_5,
              _migrate_5_to_6, _migrate_6_to_7, _migrate_7_to_8, _migrate_8_to_9, _migrate_9_to_10,
              _migrate_10_to_11]

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # One shared connection used from FastAPI's threadpool (sync endpoints)
        # AND the auth dependency, which does a read + write per authenticated
        # request (get_token_by_hash + touch_token_last_used). Concurrent
        # execute()/commit() sequences on the same sqlite3.Connection from
        # multiple OS threads raise sqlite3.InterfaceError ("bad parameter or
        # other API misuse") or return corrupted rows even though
        # sqlite3.threadsafety reports 3 — the binding serializes individual C
        # calls, not Python-level statement sequences. So every method that
        # touches the connection takes this lock, reads included (a read's
        # execute/fetch racing another thread's write/commit hits the same
        # interleaving window). Same discipline as warden/hold_warden/db.py's
        # WardenDB; RLock (not Lock) because these methods nest
        # (create_request -> add_audit -> ..., set_decision -> get_request).
        self._lock = threading.RLock()
        with self._lock:
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

    def ping(self) -> None:
        """Cheap liveness check for /health — raises if the connection is dead.

        Takes self._lock like every other method: /health runs sync (threadpool)
        and would otherwise race concurrent reads/writes on the shared connection.
        """
        with self._lock:
            self.conn.execute("SELECT 1")

    def checkpoint_and_close(self) -> None:
        """Fold the WAL back into the main file and close the connection. Called
        by the registry ONLY on eviction of a refcount==0 cell, and NEVER while
        the registry map lock is held (the map lock is the outer lock; this takes
        only this connection's own inner RLock). After this returns the cell's
        connection is dead — the cell object must be unreachable from the map."""
        with self._lock:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.conn.commit()
            finally:
                self.conn.close()

    def add_audit(self, request_id: str, event: str, detail: dict | None = None):
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), request_id, event, _iso(_utcnow()), json.dumps(detail or {})),
            )
            self.conn.commit()

    def outbox_add(self, request_id: str, event: str, payload: dict,
                   request_expires_at: str) -> str:
        oid = str(uuid.uuid4())
        with self._lock:
            self.conn.execute(
                "INSERT INTO outbox(id,request_id,event,payload,attempts,created_at,"
                "request_expires_at) VALUES (?,?,?,?,0,?,?)",
                (oid, request_id, event, json.dumps(payload), _iso(_utcnow()),
                 request_expires_at))
            self.conn.commit()
            return oid

    def outbox_delete(self, outbox_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM outbox WHERE id=?", (outbox_id,))
            self.conn.commit()

    def outbox_bump_attempts(self, outbox_id: str) -> int:
        with self._lock:
            self.conn.execute(
                "UPDATE outbox SET attempts=attempts+1 WHERE id=?", (outbox_id,))
            self.conn.commit()
            row = self.conn.execute(
                "SELECT attempts FROM outbox WHERE id=?", (outbox_id,)).fetchone()
            return row["attempts"] if row else 0

    def outbox_pending(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM outbox ORDER BY created_at").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d["payload"])
                out.append(d)
            return out

    def notify_reserve(self, request_id: str, event: str) -> bool:
        """Reserve the (request, event) dedupe key. Returns True iff newly
        reserved; False if this outward action was already claimed. Reserve is
        committed BEFORE the outward call so a re-drain (process restart) or a
        cell reopened after churn observes the claim and never re-fires it."""
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO notify_sent(request_id,event,sent_at) VALUES (?,?,?)",
                    (request_id, event, _iso(_utcnow())))
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def create_request(self, c, requested_by: str | None = None) -> dict:
        now = _utcnow()
        rid = str(uuid.uuid4())
        expires = now + timedelta(seconds=c.ttl_seconds)
        with self._lock:
            self.conn.execute(
                "INSERT INTO requests(id,created_at,title,description,action_type,payload,"
                "severity,status,ttl_seconds,expires_at,decided_at,decided_by,target,callback_url,"
                "canonical_action,action_hash,requested_by,idempotency_key)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, _iso(now), c.title, c.description, c.action_type,
                 json.dumps(c.payload), c.severity, "pending", c.ttl_seconds,
                 _iso(expires), None, None, c.target, c.callback_url,
                 c.canonical_action, c.action_hash, requested_by, c.idempotency_key),
            )
            self.conn.commit()
            self.add_audit(rid, "created", {"severity": c.severity})
            return self.get_request(rid)

    def get_request(self, rid: str) -> dict | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            return self._row_to_request(r) if r else None

    def get_request_by_idem(self, requested_by: str | None, key: str) -> dict | None:
        with self._lock:
            if requested_by is None:
                r = self.conn.execute(
                    "SELECT * FROM requests WHERE requested_by IS NULL AND idempotency_key=?",
                    (key,)).fetchone()
            else:
                r = self.conn.execute(
                    "SELECT * FROM requests WHERE requested_by=? AND idempotency_key=?",
                    (requested_by, key)).fetchone()
            return self._row_to_request(r) if r else None

    def find_duplicate_pending(self, requested_by: str | None, action_hash: str | None,
                               title: str) -> dict | None:
        """Duplicate-collapse lookup (spec key: action_hash|title). Hash-bound
        creates match pending rows on action_hash; unbound creates match
        pending rows with action_hash IS NULL on title."""
        if action_hash is not None:
            match, args = "action_hash=?", (action_hash,)
        else:
            match, args = "action_hash IS NULL AND title=?", (title,)
        with self._lock:
            if requested_by is None:
                r = self.conn.execute(
                    "SELECT * FROM requests WHERE requested_by IS NULL AND " + match +
                    " AND status='pending'", args).fetchone()
            else:
                r = self.conn.execute(
                    "SELECT * FROM requests WHERE requested_by=? AND " + match +
                    " AND status='pending'", (requested_by, *args)).fetchone()
            return self._row_to_request(r) if r else None

    def get_token_scopes(self, name: str) -> dict | None:
        with self._lock:
            r = self.conn.execute(
                "SELECT scopes FROM tokens WHERE name=? AND revoked_at IS NULL",
                (name,)).fetchone()
            if not r or r["scopes"] is None:
                return None
            return json.loads(r["scopes"])

    def list_requests(self, status: str | None = None) -> list[dict]:
        with self._lock:
            if status:
                rows = self.conn.execute(
                    "SELECT * FROM requests WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM requests ORDER BY created_at DESC").fetchall()
            return [self._row_to_request(r) for r in rows]

    def set_decision(self, rid: str, decision: str, by: str) -> dict | None:
        """Single-shot and race-safe: the UPDATE itself guards on status='pending'
        AND a live deadline, so concurrent decisions (or a decide racing the 1s
        expiry sweeper) have exactly one winner. Returns None for the loser."""
        status = "approved" if decision == "approve" else "denied"
        now = _iso(_utcnow())
        with self._lock:
            cur = self.conn.execute(
                "UPDATE requests SET status=?, decided_at=?, decided_by=?"
                " WHERE id=? AND status='pending' AND expires_at > ?",
                (status, now, by, rid, now))
            self.conn.commit()
            if cur.rowcount != 1:
                return None
            self.add_audit(rid, status, {"by": by})
            return self.get_request(rid)

    def set_verdict(self, rid: str, jws: str, kid: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE requests SET verdict_jws=?, verdict_kid=? WHERE id=?",
                              (jws, kid, rid))
            self.conn.commit()

    def expire_request_with_verdict(self, rid: str, jws: str, kid: str,
                                    now: datetime | None = None) -> dict | None:
        """Atomically flip an overdue pending row to 'expired', store its
        'expired' verdict, and write both audit rows in ONE transaction. The
        UPDATE guards on status='pending' AND expires_at<=now so a concurrent
        set_decision (which moved the row to approved/denied) wins and this
        returns None — closing the two-commit window that could otherwise strand
        an expired row with no verdict (permanent verdict-404). Audit rows are
        inlined (not add_audit) so the whole flip commits exactly once."""
        now = now or _utcnow()
        with self._lock:
            cur = self.conn.execute(
                "UPDATE requests SET status='expired', verdict_jws=?, verdict_kid=?"
                " WHERE id=? AND status='pending' AND expires_at <= ?",
                (jws, kid, rid, _iso(now)))
            if cur.rowcount != 1:
                self.conn.rollback()
                return None
            self.conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                              (str(uuid.uuid4()), rid, "expired", _iso(now), json.dumps({})))
            self.conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                              (str(uuid.uuid4()), rid, "verdict_issued", _iso(now),
                               json.dumps({"decision": "expired", "kid": kid})))
            self.conn.commit()
            return self.get_request(rid)

    def open_deadline_rows(self) -> list[dict]:
        """Rows that still carry a live deadline: pending (expiry deadline =
        expires_at) and approved-unconsumed (staleness deadline =
        decided_at + approval_ttl). Used to seed/rescan the ExpiryScheduler heap
        so a dropped heap-push cannot leave a request un-expired forever."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM requests WHERE status='pending'"
                " OR (status='approved' AND consumed_at IS NULL)").fetchall()
            return [self._row_to_request(r) for r in rows]

    def expired_without_verdict(self) -> list[dict]:
        """Recovery scan: rows flipped to 'expired' whose verdict never committed
        (a crash between the flip and the sign in any non-atomic path). The
        scheduler re-signs these at startup so no expired request is a
        permanent verdict-404."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM requests WHERE status='expired' AND verdict_jws IS NULL").fetchall()
            return [self._row_to_request(r) for r in rows]

    def expire_due(self, now: datetime | None = None) -> list[dict]:
        now = now or _utcnow()
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM requests WHERE status='pending' AND expires_at < ?",
                (_iso(now),)).fetchall()
            for r in rows:
                self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
                self.add_audit(r["id"], "expired", {})
            return [self.get_request(r["id"]) for r in rows]

    def consume_request(self, rid: str, *, approval_ttl_seconds: int,
                        now: datetime | None = None) -> tuple[int, dict | None]:
        """Single-use consumption. Returns (http_code, row):
        200 consumed now; 404 unknown; 409 not approved / already consumed;
        410 approved-but-stale (decided_at + approval_ttl_seconds < now).
        The guarded UPDATE is the atomic core — concurrent consumers race on
        rowcount, exactly one wins; self._lock (see __init__) keeps the shared
        connection safe under real OS-thread concurrency."""
        now = now or _utcnow()
        with self._lock:
            if not self.get_request(rid):
                return 404, None
            cutoff = _iso(now - timedelta(seconds=approval_ttl_seconds))
            cur = self.conn.execute(
                "UPDATE requests SET consumed_at=? WHERE id=? AND status='approved'"
                " AND consumed_at IS NULL AND decided_at >= ?",
                (_iso(now), rid, cutoff))
            self.conn.commit()
            row = self.get_request(rid)
            if cur.rowcount == 1:
                return 200, row
            if row["status"] == "approved" and row["consumed_at"] is None:
                return 410, row     # only staleness can fail the guard on this state
            return 409, row

    def expire_stale_approvals(self, approval_ttl_seconds: int,
                               now: datetime | None = None) -> list[dict]:
        """Flip approved, unconsumed rows whose decided_at is older than the
        approval window to 'expired' so the UI reflects reality. The original
        decision verdict (verdict_jws/verdict_kid) is deliberately kept."""
        now = now or _utcnow()
        cutoff = _iso(now - timedelta(seconds=approval_ttl_seconds))
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM requests WHERE status='approved' AND consumed_at IS NULL"
                " AND decided_at < ?", (cutoff,)).fetchall()
            for r in rows:
                self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
                self.add_audit(r["id"], "expired", {"reason": "stale_approval"})
            self.conn.commit()
            return [self.get_request(r["id"]) for r in rows]

    def invalidate_in_flight(self) -> int:
        """Restore-safety (§12): flip every in-flight approval (pending, or
        approved-and-unconsumed) to 'expired' so a rolled-back cell cannot
        re-execute an already-consumed action or resurrect a stale approval.
        The agent must re-propose. Returns the number of rows invalidated."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM requests WHERE status='pending'"
                " OR (status='approved' AND consumed_at IS NULL)").fetchall()
            for r in rows:
                self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
                self.add_audit(r["id"], "expired", {"reason": "cell_restored"})
            self.conn.commit()
            return len(rows)

    def backup_to(self, dest: str) -> None:
        """Online consistent snapshot of this cell DB (VACUUM INTO), safe under
        concurrent writers. dest must not already exist."""
        with self._lock:
            self.conn.execute("VACUUM INTO ?", (dest,))

    def register_device(self, apns_token: str, name: str, min_severity: str = "low",
                        notifications_enabled: bool = True, sound: bool = True,
                        severities: dict | None = None, badge: bool = False) -> dict:
        ne_int = 1 if notifications_enabled else 0
        snd_int = 1 if sound else 0
        badge_int = 1 if badge else 0
        sev_json = json.dumps(severities) if severities is not None else None
        with self._lock:
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
        with self._lock:
            return [self._row_to_device(r) for r in self.conn.execute("SELECT * FROM devices").fetchall()]

    def get_audit(self, rid: str) -> list[dict]:
        with self._lock:
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
        with self._lock:
            if request_id:
                rows = self.conn.execute(
                    base + " WHERE a.request_id = ? ORDER BY a.at DESC LIMIT ?",
                    (request_id, limit)).fetchall()
            else:
                rows = self.conn.execute(
                    base + " ORDER BY a.at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def iter_audit(self, batch: int = 500):
        """Yield every audit row oldest-first, detail parsed to a dict.
        Keyset-paginated: fetches `batch` rows per lock hold instead of
        materializing the whole table (warden RR) — a cursor can't be held
        across lock releases on the shared connection, so each batch re-seeks
        past the last (at, id) seen. Same (at, id) order as before; rows
        committed behind the cursor position mid-export are simply not
        revisited (the export was never a point-in-time snapshot)."""
        last_at, last_id = "", ""
        while True:
            with self._lock:
                rows = self.conn.execute(
                    "SELECT id, request_id, event, at, detail FROM audit"
                    " WHERE (at, id) > (?, ?) ORDER BY at, id LIMIT ?",
                    (last_at, last_id, batch)).fetchall()
            if not rows:
                return
            for r in rows:
                d = dict(r)
                d["detail"] = json.loads(d["detail"])
                yield d
            last_at, last_id = rows[-1]["at"], rows[-1]["id"]

    def rename_device(self, device_id: str, name: str) -> dict | None:
        with self._lock:
            self.conn.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
            self.conn.commit()
            r = self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            return dict(r) if r else None

    def delete_device(self, device_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
            self.conn.commit()
            return cur.rowcount > 0

    # ── device pairing (tenant-bound, single-use, short-expiry) ─────────────

    def mint_pairing(self, code_hash: str, expires_at: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO pairings(code_hash,created_at,expires_at,consumed_at)"
                " VALUES (?,?,?,NULL)", (code_hash, _iso(_utcnow()), expires_at))
            self.conn.commit()

    def redeem_pairing(self, code_hash: str,
                       now: datetime | None = None) -> tuple[int, dict | None]:
        """Single-use redemption of a pairing credential. Mirrors consume_request:
        the guarded UPDATE is the atomic core, so concurrent redemptions race on
        rowcount and exactly one wins. Returns (200, row) redeemed-now;
        (404, None) unknown; (410, row) expired; (409, row) already-consumed."""
        now = now or _utcnow()
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM pairings WHERE code_hash=?", (code_hash,)).fetchone()
            if r is None:
                return 404, None
            cur = self.conn.execute(
                "UPDATE pairings SET consumed_at=? WHERE code_hash=?"
                " AND consumed_at IS NULL AND expires_at > ?",
                (_iso(now), code_hash, _iso(now)))
            self.conn.commit()
            row = dict(self.conn.execute(
                "SELECT * FROM pairings WHERE code_hash=?", (code_hash,)).fetchone())
            if cur.rowcount == 1:
                return 200, row
            if row["consumed_at"] is None:   # guard failed but never consumed ⇒ expiry
                return 410, row
            return 409, row

    # ── tokens (per-identity bearer credentials, hashed at rest) ────────────

    def _row_to_token(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["scopes"] = json.loads(d["scopes"]) if d["scopes"] is not None else None
        return d

    def create_token(self, name: str, role: str, token_hash: str,
                     scopes: dict | None = None, expires_at: str | None = None) -> dict:
        tid = str(uuid.uuid4())
        with self._lock:
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
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM tokens WHERE token_hash=?", (token_hash,)).fetchone()
            return self._row_to_token(r) if r else None

    def list_tokens(self) -> list[dict]:
        with self._lock:
            return [self._row_to_token(r) for r in self.conn.execute(
                "SELECT * FROM tokens ORDER BY created_at").fetchall()]

    def active_token_hashes(self) -> set[str]:
        """token_hash of every unrevoked token — the reconciler's liveness set (§12)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT token_hash FROM tokens WHERE revoked_at IS NULL").fetchall()
            return {r["token_hash"] for r in rows}

    def revoke_token(self, name: str) -> dict | None:
        with self._lock:
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
        with self._lock:
            self.conn.execute("UPDATE tokens SET last_used_at=? WHERE id=?",
                              (_iso(_utcnow()), token_id))
            self.conn.commit()

    # ── gate policy store (server-mediated gate policy) ─────────────────────

    def _policy_kv_get(self, k: str, default=None):
        with self._lock:
            r = self.conn.execute("SELECT v FROM policy_kv WHERE k=?", (k,)).fetchone()
            return r["v"] if r else default

    def _policy_kv_set(self, k: str, v: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO policy_kv(k,v) VALUES (?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
            self.conn.commit()

    def policy_get_active(self) -> str | None:
        return self._policy_kv_get("active")

    def policy_set_active(self, name: str) -> None:
        self._policy_kv_set("active", name)

    def _row_to_preset(self, r: sqlite3.Row) -> dict:
        return {"name": r["name"],
                "block_patterns": json.loads(r["block_patterns"]),
                "allow_patterns": json.loads(r["allow_patterns"]),
                "tool_allowlist": json.loads(r["tool_allowlist"]),
                "default_decision": r["default_decision"]}

    def policy_list_presets(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM policy_presets ORDER BY name").fetchall()
            return [self._row_to_preset(r) for r in rows]

    def policy_get_preset(self, name: str) -> dict | None:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM policy_presets WHERE name=?", (name,)).fetchone()
            return self._row_to_preset(r) if r else None

    def policy_put_preset(self, name: str, block_patterns: list, allow_patterns: list,
                          tool_allowlist: list, default_decision: str) -> dict:
        with self._lock:
            self.conn.execute(
                "INSERT INTO policy_presets(name,block_patterns,allow_patterns,"
                "tool_allowlist,default_decision) VALUES (?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET block_patterns=excluded.block_patterns,"
                "allow_patterns=excluded.allow_patterns,tool_allowlist=excluded.tool_allowlist,"
                "default_decision=excluded.default_decision",
                (name, json.dumps(block_patterns), json.dumps(allow_patterns),
                 json.dumps(tool_allowlist), default_decision))
            self.conn.commit()
            return self.policy_get_preset(name)

    def policy_delete_preset(self, name: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM policy_presets WHERE name=?", (name,))
            self.conn.commit()
            return cur.rowcount > 0

    def policy_get_overlay(self) -> dict:
        return json.loads(self._policy_kv_get(
            "overlay", '{"always_ask": [], "always_allow": []}'))

    def policy_set_overlay(self, always_ask: list, always_allow: list) -> None:
        self._policy_kv_set("overlay", json.dumps(
            {"always_ask": always_ask, "always_allow": always_allow}))

    def policy_meta(self) -> dict:
        return {"version": int(self._policy_kv_get("version", "0")),
                "epoch": int(self._policy_kv_get("epoch", "1"))}

    def policy_bump_version(self) -> int:
        with self._lock:
            cur = self.conn.execute(
                "UPDATE policy_kv SET v=CAST(CAST(v AS INTEGER)+1 AS TEXT) WHERE k='version'")
            if cur.rowcount == 0:
                self.conn.execute("INSERT INTO policy_kv(k,v) VALUES ('version','1')")
            self.conn.commit()
            return int(self.conn.execute(
                "SELECT v FROM policy_kv WHERE k='version'").fetchone()["v"])

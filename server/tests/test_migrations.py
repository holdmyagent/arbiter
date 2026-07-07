import sqlite3

import pytest

from arbiter.db import Database, SCHEMA_VERSION

V1_SCHEMA = """
CREATE TABLE requests(
  id TEXT PRIMARY KEY, created_at TEXT, title TEXT, description TEXT,
  action_type TEXT, payload TEXT, severity TEXT, status TEXT,
  ttl_seconds INTEGER, expires_at TEXT, decided_at TEXT, decided_by TEXT);
CREATE TABLE devices(
  id TEXT PRIMARY KEY, apns_token TEXT UNIQUE, name TEXT, registered_at TEXT);
CREATE TABLE audit(
  id TEXT PRIMARY KEY, request_id TEXT, event TEXT, at TEXT, detail TEXT);
"""

def _make_v1(path):
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    conn.execute("INSERT INTO requests VALUES ('r1','2026-01-01T00:00:00+00:00','t','d','generic','{}','high','pending',300,'2027-01-01T00:00:00+00:00',NULL,NULL)")
    conn.execute("INSERT INTO devices(id,apns_token,name,registered_at) VALUES ('d1','tok','iPhone','2026-01-01T00:00:00+00:00')")
    conn.commit()
    conn.close()

def test_fresh_db_at_latest_version(tmp_path):
    db = Database(str(tmp_path / "f.sqlite3"))
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

def test_v1_db_migrates_in_place_without_data_loss(tmp_path):
    p = str(tmp_path / "v1.sqlite3")
    _make_v1(p)
    db = Database(p)
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    r = db.get_request("r1")
    assert r["title"] == "t" and r["target"] is None and r["callback_url"] is None
    d = db.list_devices()[0]
    assert d["min_severity"] == "low" and d["notifications_enabled"] == 1

def test_wal_mode(tmp_path):
    db = Database(str(tmp_path / "w.sqlite3"))
    assert db.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

def test_expire_due_returns_expired_requests(db, make):
    req = db.create_request(make(ttl_seconds=-1))
    expired = db.expire_due()
    assert [e["id"] for e in expired] == [req["id"]] and expired[0]["status"] == "expired"

# ── migrations 4 + 5 (tokens table, enforcement columns, idempotency index) ──

def test_migration_4_creates_tokens_table(tmp_path):
    db = Database(str(tmp_path / "m4.sqlite3"))
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(tokens)")}
    assert cols == {"id", "name", "role", "token_hash", "scopes",
                    "created_at", "expires_at", "last_used_at", "revoked_at"}

def test_migration_5_adds_enforcement_columns_and_index(tmp_path):
    p = str(tmp_path / "m5.sqlite3")
    _make_v1(p)
    db = Database(p)
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 5
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(requests)")}
    assert {"canonical_action", "action_hash", "verdict_jws", "verdict_kid",
            "consumed_at", "idempotency_key", "requested_by"} <= cols
    assert "idx_requests_idem" in [r[1] for r in db.conn.execute("PRAGMA index_list(requests)")]
    # _row_to_request surfaces the new columns (as None) on pre-migration rows
    r = db.get_request("r1")
    assert r["requested_by"] is None and r["consumed_at"] is None
    assert r["action_hash"] is None and r["idempotency_key"] is None

def test_reopen_and_pre_versioning_rerun_are_idempotent(tmp_path):
    """Guards the new migrations: the pre-versioning path in Database.__init__
    (db.py:58-60) re-runs EVERY migration, so 4 and 5 must be idempotent.
    (This test passes pre-change for migrations 1-3; it must stay green.)"""
    p = str(tmp_path / "re.sqlite3")
    Database(p)
    db2 = Database(p)  # plain re-open at the latest version
    assert db2.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA user_version=0")
    conn.commit()
    conn.close()
    db3 = Database(p)  # forces the run-everything-again path
    assert db3.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

def test_idem_index_is_partial_unique(db, make):
    a = db.create_request(make())
    b = db.create_request(make())
    c = db.create_request(make())
    db.conn.execute("UPDATE requests SET requested_by='hermes', idempotency_key='k1' WHERE id=?",
                    (a["id"],))
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute("UPDATE requests SET requested_by='hermes', idempotency_key='k1' WHERE id=?",
                        (b["id"],))
    # partial index: rows with NULL idempotency_key never collide
    db.conn.execute("UPDATE requests SET requested_by='hermes' WHERE id=?", (c["id"],))

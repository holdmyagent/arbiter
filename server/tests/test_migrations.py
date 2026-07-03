import sqlite3
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
    conn.commit(); conn.close()

def test_fresh_db_at_latest_version(tmp_path):
    db = Database(str(tmp_path / "f.sqlite3"))
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

def test_v1_db_migrates_in_place_without_data_loss(tmp_path):
    p = str(tmp_path / "v1.sqlite3"); _make_v1(p)
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

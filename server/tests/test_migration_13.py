"""Migration 12→13: devices.token_name — additive, nullable, zero row rewrite."""
from arbiter.db import Database, SCHEMA_VERSION


def test_schema_version_is_13():
    assert SCHEMA_VERSION == 13


def test_fresh_db_has_token_name_column(tmp_path):
    db = Database(str(tmp_path / "a.sqlite3"))
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(devices)")}
    assert "token_name" in cols


def test_migration_preserves_existing_device_rows(tmp_path):
    path = str(tmp_path / "b.sqlite3")
    db = Database(path)
    dev = db.register_device("apns-abc", "Kevin's iPhone")
    assert dev["token_name"] is None          # pre-existing rows get NULL, no DEFAULT rewrite
    db.set_device_token_name(dev["id"], "kevin-s-iphone")
    again = Database(path)                    # ladder re-run is a no-op
    row = again.conn.execute("SELECT token_name FROM devices WHERE id=?", (dev["id"],)).fetchone()
    assert row[0] == "kevin-s-iphone"
    assert again.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_set_device_token_name_none_clears(tmp_path):
    db = Database(str(tmp_path / "c.sqlite3"))
    dev = db.register_device("apns-x", "iPhone")
    db.set_device_token_name(dev["id"], "iphone")
    db.set_device_token_name(dev["id"], None)
    row = db.conn.execute("SELECT token_name FROM devices WHERE id=?", (dev["id"],)).fetchone()
    assert row[0] is None

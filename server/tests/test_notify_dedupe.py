from arbiter.db import Database, SCHEMA_VERSION


def test_migration_8_creates_notify_sent_table():
    db = Database(":memory:")
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "notify_sent" in names
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION >= 8


def test_reserve_is_true_once_then_false():
    db = Database(":memory:")
    assert db.notify_reserve("r1", "request.decided") is True
    assert db.notify_reserve("r1", "request.decided") is False   # dedupe
    # a different event for the same request is a distinct key
    assert db.notify_reserve("r1", "request.created") is True

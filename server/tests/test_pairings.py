from datetime import datetime, timedelta, timezone

from arbiter.db import Database, SCHEMA_VERSION


def _iso(dt):
    return dt.isoformat()


def test_migration_7_creates_pairings_table():
    db = Database(":memory:")
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "pairings" in names
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION >= 7


def test_mint_then_redeem_once():
    db = Database(":memory:")
    exp = _iso(datetime.now(timezone.utc) + timedelta(minutes=15))
    db.mint_pairing("hash-a", exp)
    code, row = db.redeem_pairing("hash-a")
    assert code == 200 and row["consumed_at"] is not None
    # second redemption of the same code is rejected (single-use)
    code2, _ = db.redeem_pairing("hash-a")
    assert code2 == 409


def test_redeem_unknown_is_404():
    db = Database(":memory:")
    code, row = db.redeem_pairing("nope")
    assert code == 404 and row is None


def test_redeem_expired_is_410():
    db = Database(":memory:")
    past = _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
    db.mint_pairing("hash-old", past)
    code, _ = db.redeem_pairing("hash-old")
    assert code == 410

"""Migration 13→14: the `grants` table — a new table, additive, idempotent."""
from arbiter.db import Database, SCHEMA_VERSION

GRANT_COLUMNS = {"id", "agent", "tool", "granted_by", "granted_via",
                 "request_id", "created_at", "expires_at", "revoked_at"}


def test_schema_version_is_14():
    assert SCHEMA_VERSION == 14


def test_fresh_db_has_grants_table_with_exactly_the_designed_columns(tmp_path):
    db = Database(str(tmp_path / "a.sqlite3"))
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(grants)")}
    assert cols == GRANT_COLUMNS


def test_ladder_rerun_is_a_no_op_and_preserves_grant_rows(tmp_path):
    path = str(tmp_path / "b.sqlite3")
    db = Database(path)
    g = db.create_grant(agent="hermes", tool="skill_manage", granted_by="kevin-phone",
                        granted_via="app-token", request_id="r1", ttl_seconds=300)
    again = Database(path)                     # re-open: every migration re-runs
    row = again.conn.execute("SELECT * FROM grants WHERE id=?", (g["id"],)).fetchone()
    assert row["agent"] == "hermes" and row["tool"] == "skill_manage"
    assert again.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_v1_database_gains_the_grants_table(tmp_path):
    """A pre-versioning DB re-runs the WHOLE ladder (db.py:211-213), so the
    grants migration has to survive being applied to a database that already
    went through every earlier step."""
    from tests.test_migrations import _make_v1
    path = str(tmp_path / "v1.sqlite3")
    _make_v1(path)
    db = Database(path)
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(grants)")}
    assert cols == GRANT_COLUMNS
    assert db.get_request("r1")["title"] == "t"      # nothing lost on the way


def test_grants_index_exists_after_migration(tmp_path):
    """Controller decision (Train 1a whole-branch review): the audit-retention
    sweep issues `DELETE FROM audit WHERE at < ?` with no index on audit.at, so
    idx_audit_at rides migration 14 for free alongside the grants table."""
    db = Database(str(tmp_path / "c.sqlite3"))
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_audit_at" in names


def test_grants_index_survives_ladder_rerun(tmp_path):
    """IF NOT EXISTS keeps a re-run of the whole ladder safe."""
    path = str(tmp_path / "d.sqlite3")
    Database(path)
    again = Database(path)                     # re-open: every migration re-runs
    names = {r[0] for r in again.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_audit_at" in names

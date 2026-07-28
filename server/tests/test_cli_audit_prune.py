"""0.7 S6 — `hma audit prune --days N`, the manual twin of the daily sweep."""
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from arbiter.cli import _cell_db_for, _control, main
from arbiter.config import Config


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "data" / "arbiter.sqlite3"))


def _cell_db(tenant_id):
    """Re-open the tenant's cell DB the same way the CLI resolves it."""
    return _cell_db_for(_control(Config.load()), tenant_id)


def test_audit_prune_deletes_old_rows_and_prints_the_count(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    assert CliRunner().invoke(main, ["tenant", "create", "acme"]).exit_code == 0

    db = _cell_db("acme")
    db.add_audit("-", "stale")
    db.add_audit("-", "fresh")
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    with db._lock:
        db.conn.execute("UPDATE audit SET at=? WHERE event='stale'", (old,))
        db.conn.commit()

    r = CliRunner().invoke(main, ["audit", "prune", "--days", "30", "--tenant", "acme"])
    assert r.exit_code == 0, r.output
    assert "pruned 1 audit rows older than 30 days" in r.output
    events = [a["event"] for a in _cell_db("acme").list_audit()]
    assert "stale" not in events and "fresh" in events


def test_audit_prune_rejects_an_unknown_tenant(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    assert CliRunner().invoke(main, ["tenant", "create", "acme"]).exit_code == 0
    r = CliRunner().invoke(main, ["audit", "prune", "--days", "30", "--tenant", "ghost"])
    assert r.exit_code != 0
    assert "no such tenant 'ghost'" in r.output


def test_audit_prune_rejects_a_zero_window(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    r = CliRunner().invoke(main, ["audit", "prune", "--days", "0"])
    assert r.exit_code != 0
    assert "--days must be >= 1" in r.output

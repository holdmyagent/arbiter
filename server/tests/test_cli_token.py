import hashlib
import re

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from arbiter.apns import APNsSender
from arbiter.app import create_app
from arbiter.cli import main
from arbiter.config import Config
from arbiter.db import Database

from tests.conftest import build_registry_env

TOKEN_RE = r"hma_(agent|warden|app)_[0-9a-f]{48}"

def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "arbiter.sqlite3"))

def test_token_create_list_revoke_roundtrip(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    r = CliRunner().invoke(main, ["token", "create", "hermes", "--role", "agent",
                                  "--action-types", "deploy,restart",
                                  "--max-severity", "high", "--expires-days", "30"])
    assert r.exit_code == 0, r.output
    value = re.search(TOKEN_RE, r.output).group(0)
    assert value.startswith("hma_agent_")
    lst = CliRunner().invoke(main, ["token", "list"])
    assert lst.exit_code == 0
    assert "hermes" in lst.output and "role=agent" in lst.output and "active" in lst.output
    # list never shows the secret or its hash
    assert value not in lst.output
    assert hashlib.sha256(value.encode()).hexdigest() not in lst.output
    rev = CliRunner().invoke(main, ["token", "revoke", "hermes"])
    assert rev.exit_code == 0
    assert "revoked" in CliRunner().invoke(main, ["token", "list"]).output

def test_token_create_persists_scopes_and_expiry(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    CliRunner().invoke(main, ["token", "create", "scoped", "--role", "warden",
                              "--action-types", "deploy", "--max-severity", "medium",
                              "--expires-days", "7"])
    db = Database(Config.load().db_path_expanded())
    row = [t for t in db.list_tokens() if t["name"] == "scoped"][0]
    assert row["role"] == "warden"
    assert row["scopes"] == {"action_types": ["deploy"], "max_severity": "medium"}
    assert row["expires_at"] is not None

def test_token_create_rejects_reserved_and_duplicate_names(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    for reserved in ("agent", "app"):
        r = CliRunner().invoke(main, ["token", "create", reserved, "--role", "agent"])
        assert r.exit_code != 0 and "reserved" in r.output
    assert CliRunner().invoke(main, ["token", "create", "dup", "--role", "agent"]).exit_code == 0
    r2 = CliRunner().invoke(main, ["token", "create", "dup", "--role", "warden"])
    assert r2.exit_code != 0 and "already exists" in r2.output

def test_token_revoke_unknown_name_errors(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["token", "revoke", "ghost"])
    assert r.exit_code != 0 and "no token named" in r.output

def test_token_audit_events_written_without_secret(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    out = CliRunner().invoke(main, ["token", "create", "hermes", "--role", "agent"]).output
    value = re.search(TOKEN_RE, out).group(0)
    CliRunner().invoke(main, ["token", "revoke", "hermes"])
    db = Database(Config.load().db_path_expanded())
    rows = db.conn.execute(
        "SELECT event, detail FROM audit WHERE request_id='-' ORDER BY at").fetchall()
    events = [r["event"] for r in rows]
    assert "token_created" in events and "token_revoked" in events
    joined = " ".join(r["detail"] for r in rows)
    assert value not in joined  # secrets never land in audit rows

@pytest.mark.xfail(
    reason="require_role reads app.state.db, removed per C1 §15.1; ported per-cell in C4-C8",
    strict=False)
def test_created_token_authenticates_and_revocation_bites(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    out = CliRunner().invoke(main, ["token", "create", "hermes", "--role", "agent"]).output
    value = re.search(TOKEN_RE, out).group(0)
    cfg = Config.load()
    db = Database(cfg.db_path_expanded())
    env = build_registry_env(cfg, tmp_path / "registry")
    app = create_app(cfg, env.registry, env.control, sender=APNsSender(cfg))
    client = TestClient(app)
    r = client.post("/v1/requests", headers={"Authorization": f"Bearer {value}"},
                    json={"title": "Deploy", "severity": "high", "ttl_seconds": 300})
    assert r.status_code == 200 and r.json()["requested_by"] == "hermes"
    assert CliRunner().invoke(main, ["token", "revoke", "hermes"]).exit_code == 0
    r2 = client.post("/v1/requests", headers={"Authorization": f"Bearer {value}"},
                     json={"title": "Again"})
    assert r2.status_code == 403

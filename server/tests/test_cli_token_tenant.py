import hashlib
import re

from click.testing import CliRunner

from arbiter.cli import main
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.provisioning import control_path_for, tenants_root_for


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "data" / "arbiter.sqlite3"))


def _h(v):
    return hashlib.sha256(v.encode()).hexdigest()


def test_token_create_into_tenant_routes_to_that_cell(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    CliRunner().invoke(main, ["tenant", "create", "acme"])
    out = CliRunner().invoke(main, ["token", "create", "hermes", "--role", "agent",
                                    "--tenant", "acme"]).output
    value = re.search(r"hma_agent_[0-9a-f]{48}", out).group(0)
    control = ControlPlane.open(control_path_for(Config.load()).parent, tenants_root_for(Config.load()))
    assert control.resolve(_h(value))[0] == "acme"
    # list scoped to the tenant shows it
    lst = CliRunner().invoke(main, ["token", "list", "--tenant", "acme"]).output
    assert "hermes" in lst and value not in lst
    # revoke drops both cell row + route
    CliRunner().invoke(main, ["token", "revoke", "hermes", "--tenant", "acme"])
    assert control.resolve(_h(value)) is None


def test_token_create_nonexistent_tenant_fails_cleanly(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["token", "create", "ghost-token", "--role", "agent",
                                  "--tenant", "bogus"])
    assert r.exit_code != 0
    assert "no such tenant 'bogus'" in r.output
    assert "Traceback" not in r.output
    assert "KeyError" not in r.output


def test_token_list_nonexistent_tenant_fails_cleanly(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["token", "list", "--tenant", "bogus"])
    assert r.exit_code != 0
    assert "no such tenant 'bogus'" in r.output
    assert "Traceback" not in r.output
    assert "KeyError" not in r.output


def test_token_revoke_nonexistent_tenant_fails_cleanly(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["token", "revoke", "ghost-token", "--tenant", "bogus"])
    assert r.exit_code != 0
    assert "no such tenant 'bogus'" in r.output
    assert "Traceback" not in r.output
    assert "KeyError" not in r.output

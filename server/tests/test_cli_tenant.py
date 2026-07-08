import re
from click.testing import CliRunner
from arbiter.cli import main
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.provisioning import control_path_for, tenants_root_for

def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "data" / "arbiter.sqlite3"))

def test_tenant_create_prints_tokens_once_and_registers(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    r = CliRunner().invoke(main, ["tenant", "create", "acme"])
    assert r.exit_code == 0, r.output
    assert re.search(r"hma_app_[0-9a-f]{48}", r.output)
    assert re.search(r"hma_warden_[0-9a-f]{48}", r.output)
    control = ControlPlane.open(control_path_for(Config.load()).parent, tenants_root_for(Config.load()))
    assert "acme" in [t["tenant_id"] for t in control.list_tenants()]

def test_tenant_list_disable_delete(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    CliRunner().invoke(main, ["tenant", "create", "acme"])
    assert "acme" in CliRunner().invoke(main, ["tenant", "list"]).output
    assert CliRunner().invoke(main, ["tenant", "disable", "acme"]).exit_code == 0
    assert "disabled" in CliRunner().invoke(main, ["tenant", "list"]).output.lower()
    assert CliRunner().invoke(main, ["tenant", "delete", "acme"]).exit_code == 0

def test_tenant_create_rejects_bad_id(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["tenant", "create", "Bad_Name"])
    assert r.exit_code != 0 and "a-z0-9-" in r.output

def test_tenant_disable_nonexistent_fails_not_false_success(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["tenant", "disable", "ghost"])
    assert r.exit_code != 0
    assert "disabled ghost" not in r.output.lower()

def test_tenant_delete_nonexistent_fails_not_false_success(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["tenant", "delete", "ghost"])
    assert r.exit_code != 0
    assert "tombstoned ghost" not in r.output.lower()

from click.testing import CliRunner

from arbiter.cli import main
from arbiter.config import Config
from arbiter.db import Database


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "arbiter.sqlite3"))


def _legacy_db():
    return Database(Config.load().db_path_expanded())


def _seed(db, tool="skill_manage", ttl=900):
    return db.create_grant(agent="hermes", tool=tool, granted_by="kevin-phone",
                           granted_via="app-token", request_id="r1", ttl_seconds=ttl)


def test_list_says_so_when_there_are_none(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    assert CliRunner().invoke(main, ["init"]).exit_code == 0
    r = CliRunner().invoke(main, ["grant", "list"])
    assert r.exit_code == 0 and "no grants" in r.output


def test_list_shows_scope_grantor_and_state(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    g = _seed(_legacy_db())
    r = CliRunner().invoke(main, ["grant", "list"])
    assert r.exit_code == 0, r.output
    assert g["id"][:8] in r.output
    assert "hermes" in r.output and "skill_manage" in r.output
    assert "kevin-phone" in r.output and "active" in r.output


def test_revoke_by_full_id(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    g = _seed(_legacy_db())
    r = CliRunner().invoke(main, ["grant", "revoke", g["id"]])
    assert r.exit_code == 0 and "revoked" in r.output
    assert _legacy_db().get_grant(g["id"])["state"] == "revoked"


def test_revoke_by_unique_prefix(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    g = _seed(_legacy_db())
    r = CliRunner().invoke(main, ["grant", "revoke", g["id"][:8]])
    assert r.exit_code == 0 and g["id"] in r.output
    assert _legacy_db().get_grant(g["id"])["state"] == "revoked"


def test_ambiguous_prefix_lists_the_candidates_and_revokes_nothing(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    db = _legacy_db()
    a, b = _seed(db, tool="one"), _seed(db, tool="two")
    r = CliRunner().invoke(main, ["grant", "revoke", ""])       # "" prefixes everything
    assert r.exit_code != 0
    assert "matches 2 grants" in r.output and a["id"] in r.output and b["id"] in r.output
    fresh = _legacy_db()
    assert fresh.get_grant(a["id"])["revoked_at"] is None
    assert fresh.get_grant(b["id"])["revoked_at"] is None


def test_revoke_unknown_id_errors(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    r = CliRunner().invoke(main, ["grant", "revoke", "ghost"])
    assert r.exit_code != 0 and "no grant matching" in r.output


def test_revoke_twice_is_not_an_error(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    g = _seed(_legacy_db())
    assert CliRunner().invoke(main, ["grant", "revoke", g["id"]]).exit_code == 0
    again = CliRunner().invoke(main, ["grant", "revoke", g["id"]])
    assert again.exit_code == 0 and "already revoked" in again.output
    rows = [a for a in _legacy_db().list_audit(request_id="-")
            if a["event"] == "grant_revoked"]
    assert len(rows) == 1


def test_grant_commands_follow_the_tenant_cell_once_one_exists(tmp_path, monkeypatch):
    """Same dual-path rule as `hma token`: once a control plane exists, the
    grant commands read and write the tenant's CELL database, not the legacy
    single-tenant file."""
    from arbiter.provisioning import control_path_for, tenants_root_for
    from arbiter.control import ControlPlane

    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    assert CliRunner().invoke(main, ["tenant", "create", "default"]).exit_code == 0
    cfg = Config.load()
    control = ControlPlane.open(control_path_for(cfg).parent, tenants_root_for(cfg))
    # tenant_dir returns a Path; the cell db filename is a convention shared
    # with cli._cell_db_for and tests/conftest.provision_tenant.
    cell = Database(str(control.tenant_dir("default") / "arbiter.sqlite3"))
    g = _seed(cell)
    out = CliRunner().invoke(main, ["grant", "list"]).output
    assert g["id"][:8] in out
    assert CliRunner().invoke(main, ["grant", "revoke", g["id"][:8]]).exit_code == 0


def test_unknown_tenant_errors(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    CliRunner().invoke(main, ["init"])
    CliRunner().invoke(main, ["tenant", "create", "default"])
    r = CliRunner().invoke(main, ["grant", "list", "--tenant", "ghost"])
    assert r.exit_code != 0 and "no such tenant" in r.output

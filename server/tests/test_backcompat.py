import hashlib

from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.db import Database
from arbiter.provisioning import migrate_to_multitenant


def _h(v):
    return hashlib.sha256(v.encode()).hexdigest()


def test_migrate_wraps_single_db_as_default(tmp_path):
    legacy = tmp_path / "data" / "arbiter.sqlite3"
    legacy.parent.mkdir(parents=True)
    db = Database(str(legacy))
    db.create_token("hermes", "agent", _h("hma_agent_live"))
    db.create_token("gone", "app", _h("hma_app_gone"))
    db.revoke_token("gone")
    db.register_device("apns1", "iPhone")
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.server.db_path = str(legacy)
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")

    migrate_to_multitenant(cfg, control, tmp_path / "tenants")

    tenant_ids = [t["tenant_id"] for t in control.list_tenants()]
    assert "default" in tenant_ids
    assert control.tenant_dir("default").resolve() == legacy.parent.resolve()
    assert control.resolve(_h("hma_agent_live"))[0] == "default"   # live token routed
    assert control.resolve(_h("hma_app_gone")) is None             # revoked token NOT routed
    assert len(Database(str(legacy)).list_devices()) == 1          # devices stay in default cell

    # idempotent
    migrate_to_multitenant(cfg, control, tmp_path / "tenants")
    assert [t["tenant_id"] for t in control.list_tenants()].count("default") == 1

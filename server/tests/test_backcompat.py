import hashlib

import pytest

from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.db import Database
from arbiter.provisioning import ensure_default_cell, migrate_to_multitenant


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


def test_migrate_raises_loud_on_mis_registered_default(tmp_path):
    # An empty "default" was bootstrapped at cells/default BEFORE migrate ran
    # (the serve-before-migrate race, §14/C1) — migrate must not silently
    # no-op and strand the legacy DB; it must fail loud and actionable.
    legacy = tmp_path / "data" / "arbiter.sqlite3"
    legacy.parent.mkdir(parents=True)
    Database(str(legacy)).create_token("hermes", "agent", _h("hma_agent_live"))
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.server.db_path = str(legacy)
    control = ControlPlane.open(tmp_path / "control", tmp_path / "cells")
    empty_default_dir = tmp_path / "cells" / "default"
    empty_default_dir.mkdir(parents=True)
    control.create_tenant("default", str(empty_default_dir.resolve()))

    with pytest.raises((ValueError, RuntimeError), match="already registered"):
        migrate_to_multitenant(cfg, control, tmp_path / "cells")

    # still mis-registered — no silent partial mutation
    assert control.tenant_dir("default").resolve() == empty_default_dir.resolve()


def test_ensure_default_cell_auto_migrates_upgraded_install(tmp_path):
    # Upgraded iOS-0.5.0 install: a legacy single-tenant DB with a live token
    # sits at db_path, and "default" is NOT yet registered — `hma serve`
    # running before `hma admin migrate` must auto-migrate, not mint an empty
    # default at cells/default.
    legacy = tmp_path / "data" / "arbiter.sqlite3"
    legacy.parent.mkdir(parents=True)
    Database(str(legacy)).create_token("hermes", "app", _h("hma_app_live"))
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.server.db_path = str(legacy)
    control = ControlPlane.open(tmp_path / "control", tmp_path / "cells")

    ensure_default_cell(cfg, control, tmp_path / "cells")

    assert control.epoch_of("default") is not None
    assert control.tenant_dir("default").resolve() == legacy.parent.resolve()
    assert control.resolve(_h("hma_app_live"))[0] == "default"
    assert not (tmp_path / "cells" / "default").exists()  # no empty default minted


def test_ensure_default_cell_fresh_install_mints_empty_default(tmp_path):
    # No legacy DB at all — unchanged behavior: an empty "default" cell is
    # provisioned at <tenants_root>/default.
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.server.db_path = str(tmp_path / "data" / "arbiter.sqlite3")
    control = ControlPlane.open(tmp_path / "control", tmp_path / "cells")

    ensure_default_cell(cfg, control, tmp_path / "cells")

    assert control.epoch_of("default") is not None
    assert control.tenant_dir("default").resolve() == (tmp_path / "cells" / "default").resolve()
    assert not (tmp_path / "data" / "arbiter.sqlite3").exists()  # legacy DB untouched (never existed)

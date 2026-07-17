import asyncio
import hashlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from arbiter.auth import Identity, resolve_identity
from arbiter.control import ControlPlane
from arbiter.db import Database


class FakeCell:
    def __init__(self, epoch, db):
        self.epoch = epoch
        self.db = db


class FakeRegistry:
    def __init__(self, cell):
        self.cell = cell
        self.acquired = 0
        self.released = 0

    async def acquire(self, tenant_id, epoch):
        self.acquired += 1
        return self.cell

    def release(self, cell):
        self.released += 1


def _cfg():
    return SimpleNamespace(auth=SimpleNamespace(app_token="test-app", agent_token="test-agent"))


def _req(cfg, authorization=None):
    headers = {} if authorization is None else {"authorization": authorization}
    return SimpleNamespace(
        headers=headers, app=SimpleNamespace(state=SimpleNamespace(cfg=cfg)))


def _hash(bearer):
    return hashlib.sha256(bearer.encode()).hexdigest()


def _control(tmp_path, tenant="acme"):
    cp = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    (tmp_path / "tenants").mkdir(exist_ok=True)
    cp.create_tenant(tenant, str(tmp_path / "tenants" / tenant))    # epoch 1
    return cp


def _run(coro):
    return asyncio.run(coro)


def test_db_token_happy_path_returns_pinned_cell(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_secret"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), {"max_severity": "high"}, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    reg = FakeRegistry(FakeCell(1, db))
    ident, cell = _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert isinstance(ident, Identity)
    assert (ident.tenant_id, ident.name, ident.role, ident.epoch, ident.legacy) == \
        ("acme", "bot", "agent", 1, False)
    assert ident.scopes == {"max_severity": "high"}
    assert cell is reg.cell
    assert reg.acquired == 1 and reg.released == 0    # pin kept for the caller


def test_missing_bearer_is_generic_403(tmp_path):
    cp = _control(tmp_path)
    reg = FakeRegistry(FakeCell(1, Database(":memory:")))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(_cfg(), None), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 0                           # never pinned


def test_route_hit_but_no_cell_token_403_and_released(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_ghost"
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")                # route exists...
    reg = FakeRegistry(FakeCell(1, Database(":memory:")))  # ...but cell has no token
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 1 and reg.released == 1     # pinned then released exactly once


def test_disabled_tenant_403s_hot_busy_cell_before_acquire(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_x"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    cp.disable_tenant("acme")
    reg = FakeRegistry(FakeCell(1, db))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 0                           # disabled -> never pins the hot cell


def test_epoch_mismatch_fails_closed_and_releases(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_y"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")                # resolves to epoch 1
    reg = FakeRegistry(FakeCell(2, db))                # cell reopened at a newer epoch
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 1 and reg.released == 1


def test_revoked_in_cell_token_403(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_z"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    db.revoke_token("bot")
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    reg = FakeRegistry(FakeCell(1, db))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.released == 1


def test_legacy_app_token_resolves_strictly_to_default(tmp_path):
    cfg = _cfg()
    db = Database(":memory:")
    cp = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    (tmp_path / "tenants").mkdir(exist_ok=True)
    cp.create_tenant("default", str(tmp_path / "tenants" / "default"))   # epoch 1
    reg = FakeRegistry(FakeCell(1, db))
    ident, cell = _run(resolve_identity(_req(cfg, "Bearer test-app"), reg, cp))
    assert (ident.tenant_id, ident.role, ident.legacy) == ("default", "app", True)
    assert reg.acquired == 1 and reg.released == 0


def test_expired_in_cell_token_403(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_old"
    db = Database(":memory:")
    db.create_token("old", "agent", _hash(bearer), None, "2020-01-01T00:00:00+00:00")
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    reg = FakeRegistry(FakeCell(1, db))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 1 and reg.released == 1    # pinned then released exactly once

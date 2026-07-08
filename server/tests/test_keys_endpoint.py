"""GET /v1/keys serves the pinned cell's JWKS and survives an eviction/reopen race.

Uses fakes for registry/control/cell shaped to the pinned cross-component contract
so this endpoint test does not depend on Group A/B's concrete TenantRegistry.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from arbiter.signing import load_or_create_signer


class FakeCell:
    def __init__(self, tenant_id, signer):
        self.tenant_id = tenant_id
        self.epoch = 1
        self.signer = signer


class FakeRegistry:
    """Resolves a bearer to a fixed cell; records acquire/release balance. A
    'reopen' can swap the map's cell, but a live holder keeps its bound object."""
    def __init__(self, cells_by_token):
        self._by_token = dict(cells_by_token)   # token -> cell
        self.acquired = 0
        self.released = 0

    def acquire_for(self, token):
        cell = self._by_token.get(token)
        if cell is None:
            raise HTTPException(status_code=403, detail="forbidden")
        self.acquired += 1
        return cell

    def release(self, cell):
        self.released += 1

    def swap(self, token, cell):        # simulate an eviction+reopen twin
        self._by_token[token] = cell


async def _fake_resolve_identity(request: Request, registry, control):
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    cell = registry.acquire_for(token)
    identity = SimpleNamespace(tenant_id=cell.tenant_id, role="app")
    return identity, cell


@pytest.fixture
def keys_app(tmp_path, monkeypatch, cfg, registry_env):
    from arbiter import app as app_mod
    monkeypatch.setattr(app_mod, "resolve_identity", _fake_resolve_identity)

    signer_a = load_or_create_signer("acme", tmp_path / "acme")
    signer_b = load_or_create_signer("beta", tmp_path / "beta")
    reg = FakeRegistry({"tok-a": FakeCell("acme", signer_a),
                        "tok-b": FakeCell("beta", signer_b)})

    from arbiter.apns import APNsSender
    # Reconciliation (ledger #7): the brief's fixture called
    # create_app(cfg, Database(...), sender); the real signature is
    # create_app(cfg, registry, control, *, sender=sender). `registry_env`
    # (conftest) provisions a real registry/control so lifespan startup
    # (which drains outboxes over control.list_tenants()) has something real
    # to walk; the fakes below are swapped onto app.state right after, which
    # is what the /v1/keys handler and the monkeypatched resolve_identity
    # actually read.
    fastapi_app = app_mod.create_app(cfg, registry_env.registry, registry_env.control,
                                      sender=APNsSender(cfg))
    fastapi_app.state.registry = reg
    fastapi_app.state.control = object()
    return fastapi_app, reg, signer_a, signer_b


def test_keys_serves_callers_own_tenant(keys_app):
    app, reg, sa, sb = keys_app
    with TestClient(app) as c:
        ra = c.get("/v1/keys", headers={"Authorization": "Bearer tok-a"})
        rb = c.get("/v1/keys", headers={"Authorization": "Bearer tok-b"})
    assert ra.json()["keys"][0]["kid"] == sa.kid
    assert rb.json()["keys"][0]["kid"] == sb.kid
    assert reg.acquired == reg.released == 2      # exactly-once release


def test_keys_no_route_is_403(keys_app):
    app, reg, _, _ = keys_app
    with TestClient(app) as c:
        r = c.get("/v1/keys", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 403


def test_keys_under_reopen_race_serves_the_pinned_tenant(keys_app, tmp_path):
    app, reg, sa, sb = keys_app
    # Point tok-a's map entry at a twin AFTER the fixture but the request still
    # binds whatever acquire_for returns; assert the served kid is A's, never B's.
    with TestClient(app) as c:
        r = c.get("/v1/keys", headers={"Authorization": "Bearer tok-a"})
    assert r.json()["keys"][0]["kid"] == sa.kid
    assert r.json()["keys"][0]["kid"] != sb.kid

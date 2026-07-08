import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arbiter.db import Database
from arbiter.enroll import resolve_pairing
from arbiter.errors import generic_403
from arbiter.models import DeviceRegister


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _iso(dt):
    return dt.isoformat()


class FakeCell:
    def __init__(self, tenant_id, epoch, db):
        self.tenant_id, self.epoch, self.db = tenant_id, epoch, db


class FakeRegistry:
    def __init__(self, cells):
        self._cells = cells

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        yield self._cells[tenant_id]


class FakeControl:
    def __init__(self, routes):
        self._routes = routes

    def resolve(self, h):
        return self._routes.get(h)

    def is_disabled(self, t):
        return False


def _mk_app(reg, ctrl):
    app = FastAPI()
    app.state.registry, app.state.control = reg, ctrl

    @app.post("/v1/devices/enroll")
    async def enroll(body: DeviceRegister, request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise generic_403()
        code = auth.removeprefix("Bearer ")
        async with resolve_pairing(code, request.app.state.registry,
                                   request.app.state.control) as cell:
            dev = cell.db.register_device(
                body.apns_token, body.name, body.min_severity,
                body.notifications_enabled, body.sound,
                severities=body.severities, badge=body.badge)
            return {**dev, "tenant_id": cell.tenant_id}

    return app


def _two_tenant_setup():
    dbs = {"A": Database(":memory:"), "B": Database(":memory:")}
    exp = _iso(datetime.now(timezone.utc) + timedelta(minutes=15))
    dbs["A"].mint_pairing(_sha("code-A"), exp)
    cells = {"A": FakeCell("A", 1, dbs["A"]), "B": FakeCell("B", 1, dbs["B"])}
    reg = FakeRegistry(cells)
    ctrl = FakeControl({_sha("code-A"): ("A", 1)})
    return dbs, _mk_app(reg, ctrl)


def test_device_paired_to_A_lands_only_in_A_never_B():
    dbs, app = _two_tenant_setup()
    c = TestClient(app)
    r = c.post("/v1/devices/enroll",
               headers={"Authorization": "Bearer code-A"},
               json={"apns_token": "tok-phone-1", "name": "iPhone"})
    assert r.status_code == 200 and r.json()["tenant_id"] == "A"
    # the device row exists in A's cell and NOT in B's — no global device table,
    # so B's dispatcher can never see (and thus never push to) this token.
    assert [d["apns_token"] for d in dbs["A"].list_devices()] == ["tok-phone-1"]
    assert dbs["B"].list_devices() == []


def test_replayed_code_rejected_generic_403():
    _, app = _two_tenant_setup()
    c = TestClient(app)
    hdr = {"Authorization": "Bearer code-A"}
    assert c.post("/v1/devices/enroll", headers=hdr,
                  json={"apns_token": "t1", "name": "iPhone"}).status_code == 200
    r2 = c.post("/v1/devices/enroll", headers=hdr,
                json={"apns_token": "t2", "name": "iPhone"})
    assert r2.status_code == 403


def test_forged_code_rejected_and_body_has_no_pii():
    _, app = _two_tenant_setup()
    c = TestClient(app)
    r = c.post("/v1/devices/enroll",
               headers={"Authorization": "Bearer totally-made-up"},
               json={"apns_token": "t", "name": "iPhone"})
    assert r.status_code == 403
    body = r.text.lower()
    for leaky in ("tenant", "route", "disabled", "no such", "code-a", "a\":", "acme"):
        assert leaky not in body

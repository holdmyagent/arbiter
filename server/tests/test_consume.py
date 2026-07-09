import asyncio
import hashlib
import json
import secrets as pysecrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.scheduler import ExpiryScheduler

from tests.conftest import build_registry_env

AGENT = {"Authorization": "Bearer test-agent"}
APP = {"Authorization": "Bearer test-app"}


class FakeSender:
    async def send(self, token, payload):
        return "sent"


def mint_token(client, name, role, scopes=None):
    """Insert a DB token row straight against the migration-4 DDL AND register
    its control-plane route (mirrors conftest.mint_cell_token) — a bare
    db.create_token()-equivalent insert is invisible to resolve_identity,
    which routes through the control plane first."""
    tok = f"hma_{role}_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    client.db.conn.execute(
        "INSERT INTO tokens(id, name, role, token_hash, scopes, created_at,"
        " expires_at, last_used_at, revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), name, role, th,
         json.dumps(scopes) if scopes is not None else None,
         datetime.now(timezone.utc).isoformat()))
    client.db.conn.commit()
    client.env.control.add_route(th, "default")
    return tok


def _client(cfg, tmp_path):
    sender = FakeSender()
    env = build_registry_env(cfg, tmp_path, sender=sender)
    sched = ExpiryScheduler(env.registry, env.control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
    app = create_app(cfg, env.registry, env.control, sender=sender, scheduler=sched)
    c = TestClient(app)
    c.db = env.default_db
    c.env = env
    c.app_ref = app
    c.cfg = cfg
    c.sched = sched
    return c


@pytest.fixture
def client(cfg, tmp_path):
    return _client(cfg, tmp_path)


@pytest.fixture
def warden_headers(client):
    tok = mint_token(client, "warden1", "warden")
    return {"Authorization": f"Bearer {tok}"}


def _approved_request(client):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers=APP,
                    json={"decision": "approve"})
    assert d.status_code == 200
    return rid


def test_consume_happy_path(client, warden_headers):
    rid = _approved_request(client)
    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers)
    assert r.status_code == 200 and r.json()["consumed_at"]
    row = client.db.get_request(rid)
    assert row["status"] == "approved"                 # status enum unchanged
    assert row["consumed_at"] == r.json()["consumed_at"]


def test_consume_requires_warden_role(client, warden_headers):
    rid = _approved_request(client)
    assert client.post(f"/v1/requests/{rid}/consume", headers=AGENT).status_code == 403
    assert client.post(f"/v1/requests/{rid}/consume", headers=APP).status_code == 403


def test_consume_pending_409_and_unknown_404(client, warden_headers):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    assert client.post(f"/v1/requests/{rid}/consume", headers=warden_headers).status_code == 409
    assert client.post("/v1/requests/nope/consume", headers=warden_headers).status_code == 404


def test_double_consume_concurrent_exactly_one_wins(client, warden_headers):
    rid = _approved_request(client)
    barrier = threading.Barrier(2)
    codes = []
    def hit():
        barrier.wait()
        codes.append(client.post(f"/v1/requests/{rid}/consume",
                                 headers=warden_headers).status_code)
    threads = [threading.Thread(target=hit) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes) == [200, 409]


def test_stale_approval_410(cfg, tmp_path):
    cfg.policy.approval_ttl_seconds = 0     # everything is instantly stale — no sleeping
    client = _client(cfg, tmp_path)
    tok = mint_token(client, "warden1", "warden")
    rid = _approved_request(client)
    r = client.post(f"/v1/requests/{rid}/consume",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 410
    assert client.db.get_request(rid)["consumed_at"] is None


def test_db_consume_stale_with_explicit_clock(db, make):
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "tester")
    late = datetime.now(timezone.utc) + timedelta(seconds=601)
    code, row = db.consume_request(r["id"], approval_ttl_seconds=600, now=late)
    assert code == 410 and row["consumed_at"] is None


def _force_stale_decided_at(client, rid):
    """Push decided_at far enough into the past that decided_at+approval_ttl
    is already overdue, mirroring test_scheduler.py's cold-cell pattern."""
    stale_ttl = client.cfg.policy.approval_ttl_seconds
    past = (datetime.now(timezone.utc) - timedelta(seconds=stale_ttl + 10)).isoformat()
    with client.db._lock:
        client.db.conn.execute("UPDATE requests SET decided_at=? WHERE id=?", (past, rid))
        client.db.conn.commit()


def test_sweeper_flips_stale_approval_keeps_verdict(client, warden_headers):
    rid = _approved_request(client)
    jws_before = client.db.get_request(rid)["verdict_jws"]
    assert jws_before
    _force_stale_decided_at(client, rid)

    async def _run():
        await client.sched._fire_one((0, 0, "default", rid))
        for t in list(client.sched._bg):
            await t
    asyncio.run(_run())

    row = client.db.get_request(rid)
    assert row["status"] == "expired"
    assert row["verdict_jws"] == jws_before   # original approved verdict kept


def test_sweeper_leaves_consumed_approvals_alone(client, warden_headers):
    rid = _approved_request(client)
    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    _force_stale_decided_at(client, rid)

    async def _run():
        await client.sched._fire_one((0, 0, "default", rid))
        for t in list(client.sched._bg):
            await t
    asyncio.run(_run())

    assert client.db.get_request(rid)["status"] == "approved"

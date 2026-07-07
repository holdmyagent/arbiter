import hashlib
import json
import secrets as pysecrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.db import Database

AGENT = {"Authorization": "Bearer test-agent"}
APP = {"Authorization": "Bearer test-app"}


class FakeSender:
    async def send(self, token, payload):
        return "sent"


def mint_token(db, name, role, scopes=None):
    tok = f"hma_{role}_{pysecrets.token_hex(24)}"
    db.conn.execute(
        "INSERT INTO tokens(id, name, role, token_hash, scopes, created_at,"
        " expires_at, last_used_at, revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), name, role, hashlib.sha256(tok.encode()).hexdigest(),
         json.dumps(scopes) if scopes is not None else None,
         datetime.now(timezone.utc).isoformat()))
    db.conn.commit()
    return tok


def _client(cfg):
    db = Database(":memory:")
    app = create_app(cfg, db, FakeSender())
    c = TestClient(app)
    c.db = db
    c.app_ref = app
    return c


def test_consumed_and_verdict_issued_events(cfg):
    client = _client(cfg)
    wh = {"Authorization": f"Bearer {mint_token(client.db, 'warden1', 'warden')}"}
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers=APP, json={"decision": "approve"})
    assert client.post(f"/v1/requests/{rid}/consume", headers=wh).status_code == 200
    events = {a["event"] for a in client.db.get_audit(rid)}
    assert {"created", "approved", "verdict_issued", "consumed"} <= events


def test_expiry_verdict_issued_event(cfg):
    client = _client(cfg)
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    future = datetime.now(timezone.utc) + timedelta(seconds=7200)
    client.app_ref.state.expire_pass(now=future)
    events = [a["event"] for a in client.db.get_audit(rid)]
    assert "expired" in events and "verdict_issued" in events


def test_policy_denied_and_rate_limited_events(cfg):
    cfg.policy.deny_action_types = ["db.drop"]
    cfg.policy.rate_limit_per_minute = 1
    client = _client(cfg)
    assert client.post("/v1/requests", headers=AGENT,
                       json={"title": "t", "action_type": "db.drop"}).status_code == 403
    assert client.post("/v1/requests", headers=AGENT,
                       json={"title": "t"}).status_code == 200
    assert client.post("/v1/requests", headers=AGENT,
                       json={"title": "t"}).status_code == 429
    all_events = [a["event"] for a in client.db.list_audit(limit=500)]
    assert "policy_denied" in all_events and "rate_limited" in all_events


def test_export_jsonl_stream_includes_new_events(cfg):
    client = _client(cfg)
    wh = {"Authorization": f"Bearer {mint_token(client.db, 'warden1', 'warden')}"}
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers=APP, json={"decision": "approve"})
    client.post(f"/v1/requests/{rid}/consume", headers=wh)
    r = client.get("/v1/audit/export", headers=APP)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    lines = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    assert all(isinstance(line["detail"], dict) for line in lines)
    events = [line["event"] for line in lines]
    assert {"created", "approved", "verdict_issued", "consumed"} <= set(events)
    assert len(lines) == len(client.db.list_audit(limit=10000))   # ALL rows exported


def test_export_requires_app_role_or_admin_session(cfg):
    client = _client(cfg)
    assert client.get("/v1/audit/export").status_code == 403
    assert client.get("/v1/audit/export", headers=AGENT).status_code == 403
    login = client.post("/dashboard/login", data={"password": "test-admin"},
                        follow_redirects=False)
    assert login.status_code == 303
    assert client.get("/v1/audit/export").status_code == 200   # session cookie carried


def test_export_unknown_format_422(cfg):
    client = _client(cfg)
    r = client.get("/v1/audit/export", params={"format": "csv"}, headers=APP)
    assert r.status_code == 422


def test_export_auth_failures_rate_limited(cfg):
    # parity with require_role: repeated bad tokens trip the shared auth
    # limiter (10/60s) — mirrors test_security.test_auth_failures_rate_limited
    client = _client(cfg)
    bad = {"Authorization": "Bearer wrong"}
    codes = [client.get("/v1/audit/export", headers=bad).status_code for _ in range(12)]
    assert codes[0] == 403 and 429 in codes

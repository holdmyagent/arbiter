import asyncio
import base64
import hashlib
import json
import secrets as pysecrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.scheduler import ExpiryScheduler

from tests.conftest import build_registry_env

AGENT = {"Authorization": "Bearer test-agent"}
APP = {"Authorization": "Bearer test-app"}

class FakeSender:
    def __init__(self): self.calls = []
    async def send(self, token, payload):
        self.calls.append((token, payload))
        return "sent"


def mint_token(client, name, role, scopes=None):
    """Insert a DB token row AND register its control-plane route (mirrors
    conftest.mint_cell_token) — a bare token-row insert is invisible to
    resolve_identity, which routes through the control plane first."""
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


@pytest.fixture
def client(cfg, tmp_path):
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


def _pubkey(client):
    # /v1/keys now requires a bearer (§7: the JWKS is "that tenant's", derived
    # from the pinned cell) — AGENT is as good a credential as any for this.
    jwks = client.get("/v1/keys", headers=AGENT).json()
    k = jwks["keys"][0]
    raw = base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4))
    return k["kid"], Ed25519PublicKey.from_public_bytes(raw)


# /v1/keys now requires a bearer (§7 — see _pubkey above); the pre-multi-tenant
# unauthenticated-JWKS behavior this test used to pin is superseded.
def test_keys_requires_token_then_returns_jwks_shape(client):
    assert client.get("/v1/keys").status_code == 403
    r = client.get("/v1/keys", headers=AGENT)
    assert r.status_code == 200
    k = r.json()["keys"][0]
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["kid"] and k["x"]


def test_verdict_404_while_pending(client):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    r = client.get(f"/v1/requests/{rid}/verdict", headers=AGENT)
    assert r.status_code == 404
    assert r.json()["detail"] == "no verdict yet"


def test_verdict_unknown_request_404(client):
    r = client.get("/v1/requests/nope/verdict", headers=AGENT)
    assert r.status_code == 404
    assert r.json()["detail"] == "not found"


def test_decide_issues_verifiable_verdict(client):
    canonical = ('{"action":"x","adapter":"command","params":{},'
                 '"resolved":{"argv":["echo"]},"v":1,"warden":"w"}')
    ah = hashlib.sha256(canonical.encode()).hexdigest()
    rid = client.post("/v1/requests", headers=AGENT,
                      json={"title": "t", "canonical_action": canonical,
                            "action_hash": ah}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers=APP,
                    json={"decision": "approve"})
    assert d.status_code == 200
    v = client.get(f"/v1/requests/{rid}/verdict", headers=APP)
    assert v.status_code == 200
    kid, pub = _pubkey(client)
    assert v.json()["kid"] == kid
    # aud is tenant-bound (aud=f"hma-verdict:{tenant_id}"), not the bare
    # "hma-verdict" this test used to pin — spec-mandated by C6/D2 (§7, §15.8/9).
    claims = jwt.decode(v.json()["verdict"], key=pub, algorithms=["EdDSA"],
                        audience="hma-verdict:default")
    assert claims["iss"] == "hma" and claims["jti"] == rid
    hma = claims["hma"]
    assert hma["request_id"] == rid and hma["decision"] == "approved"
    assert hma["action_hash"] == ah
    assert hma["decided_at"] and hma["approval_ttl_seconds"] == 600


def test_unbound_request_verdict_has_null_action_hash(client):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "plain"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers=APP, json={"decision": "deny"})
    v = client.get(f"/v1/requests/{rid}/verdict", headers=AGENT)
    assert v.status_code == 200
    _, pub = _pubkey(client)
    claims = jwt.decode(v.json()["verdict"], key=pub, algorithms=["EdDSA"],
                        audience="hma-verdict:default")  # tenant-bound aud (§7, C6/D2)
    assert claims["hma"]["action_hash"] is None
    assert claims["hma"]["decision"] == "denied"


def test_warden_token_cannot_read_foreign_verdict(client):
    # foreign row: created by the legacy agent token (requested_by NULL)
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers=APP, json={"decision": "approve"})
    wh = {"Authorization": f"Bearer {mint_token(client, 'warden1', 'warden')}"}
    r = client.get(f"/v1/requests/{rid}/verdict", headers=wh)
    assert r.status_code == 404
    assert r.json()["detail"] == "not found"
    # its OWN request's verdict is still readable
    own = client.post("/v1/requests", headers=wh, json={"title": "mine"}).json()["id"]
    client.post(f"/v1/requests/{own}/decision", headers=APP, json={"decision": "approve"})
    assert client.get(f"/v1/requests/{own}/verdict", headers=wh).status_code == 200


# The single-tenant sweep hook is gone (§15.1 — nothing tenant-scoped/
# process-local lives on app.state); expiry is now driven by the per-cell
# ExpiryScheduler wired into create_app (task F9). Drive the same scheduler
# instance the app was built with, exactly as the running server would.
def test_expiry_verdict_signed_by_sweep_pass(client):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    with client.db._lock:
        client.db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?", (past, rid))
        client.db.conn.commit()

    async def _run():
        await client.sched._fire_one((0, 0, "default", rid))
        for t in list(client.sched._bg):
            await t
    asyncio.run(_run())

    v = client.get(f"/v1/requests/{rid}/verdict", headers=AGENT)
    assert v.status_code == 200
    _, pub = _pubkey(client)
    claims = jwt.decode(v.json()["verdict"], key=pub, algorithms=["EdDSA"],
                        audience="hma-verdict:default")
    assert claims["hma"]["decision"] == "expired"
    assert claims["hma"]["action_hash"] is None


def test_create_hash_mismatch_422(client):
    r = client.post("/v1/requests", headers=AGENT,
                    json={"title": "t", "canonical_action": "{}",
                          "action_hash": "deadbeef"})
    assert r.status_code == 422
    # supplying only one of the pair is also a 422
    r2 = client.post("/v1/requests", headers=AGENT,
                     json={"title": "t", "action_hash": "deadbeef"})
    assert r2.status_code == 422
    # matching pair is stored and echoed back
    canonical = '{"params":{},"v":1}'
    ah = hashlib.sha256(canonical.encode()).hexdigest()
    r3 = client.post("/v1/requests", headers=AGENT,
                     json={"title": "t", "canonical_action": canonical,
                           "action_hash": ah})
    assert r3.status_code == 200 and r3.json()["action_hash"] == ah

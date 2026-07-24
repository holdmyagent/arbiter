import hashlib, base64, hmac, struct, time
import pytest
from fastapi import HTTPException
from arbiter import step_up
from arbiter.app import capabilities_for, assert_cap
from arbiter.auth import Identity

import json, uuid, secrets as pysecrets
from datetime import datetime, timezone
from arbiter import gate_policy as gp

APP = {"Authorization": "Bearer test-app"}
AGENT = {"Authorization": "Bearer test-agent"}


def _totp(secret_b32, now, step=30):
    key = base64.b32decode(secret_b32)
    counter = int(now // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    val = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{val:06d}"


def test_verify_totp_accepts_current_and_adjacent_window():
    secret = base64.b32encode(b"0123456789").decode()
    now = 1_700_000_000.0
    assert step_up.verify_totp(secret, _totp(secret, now), now)
    assert step_up.verify_totp(secret, _totp(secret, now - 30), now)     # prev step
    assert step_up.verify_totp(secret, _totp(secret, now + 30), now)     # next step
    assert not step_up.verify_totp(secret, _totp(secret, now - 90), now)
    assert not step_up.verify_totp(secret, "000000", now) or _totp(secret, now) == "000000"


def test_capabilities_role_defaults():
    app_id = Identity(name="app", role="app", tenant_id="default")
    agent_id = Identity(name="gate", role="agent", tenant_id="default")
    assert "policy:write" in capabilities_for(app_id)
    assert capabilities_for(agent_id) == {"policy:read-resolved"}


def test_capabilities_explicit_scope_wins():
    tok = Identity(name="bot", role="agent", tenant_id="default",
                   scopes={"capabilities": ["policy:read-resolved", "policy:read"]})
    assert capabilities_for(tok) == {"policy:read-resolved", "policy:read"}


def test_assert_cap_denies():
    agent_id = Identity(name="gate", role="agent", tenant_id="default")
    with pytest.raises(HTTPException) as e:
        assert_cap(agent_id, "policy:write")
    assert e.value.status_code == 403


def test_get_policy_default_is_most_restrictive_not_empty(client):
    r = client.get("/v1/policy", headers=AGENT)      # gate token = agent role
    assert r.status_code == 200
    body = r.json()
    assert body["default_decision"] == "ask"
    assert body["categorical_ask"]                   # NON-EMPTY
    assert body["active_preset"] is None
    assert body["tool_allowlist"] == []


def test_get_policy_reflects_active_preset(client):
    client.db.policy_put_preset("dangerous-shell", ["rm -rf"], [], ["run_shell"], "allow")
    client.db.policy_set_active("dangerous-shell")
    client.db.policy_bump_version()
    r = client.get("/v1/policy", headers=APP)
    assert r.status_code == 200
    assert r.json()["active_preset"] == "dangerous-shell"
    assert "rm -rf" in r.json()["ask_patterns"]


def test_get_policy_read_resolved_only_still_allowed_for_gate(client):
    # A minted agent token scoped to ONLY policy:read-resolved can read /v1/policy.
    tok = f"hma_agent_{pysecrets.token_hex(24)}"
    import hashlib
    th = hashlib.sha256(tok.encode()).hexdigest()
    client.db.conn.execute(
        "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,expires_at,"
        "last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), "gate", "agent", th,
         json.dumps({"capabilities": ["policy:read-resolved"]}),
         datetime.now(timezone.utc).isoformat()))
    client.db.conn.commit()
    client.env.control.add_route(th, "default")
    r = client.get("/v1/policy", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200

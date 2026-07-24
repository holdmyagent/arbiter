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


def test_verify_totp_canonical_rfc6238_vector():
    # RFC 6238 Appendix B canonical SHA1 test seed, ASCII "12345678901234567890",
    # computed here as LITERALS (not via _totp/verify_totp's own helper) so this
    # is an external cross-check against the published vectors, not a
    # tautology against our own code. The RFC's 8-digit values (94287082 at
    # T=59; 07081804 at T=1111111109) truncate to this impl's 6-digit HOTP
    # (value % 1_000_000) as 287082 / 081804 respectively.
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert secret == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert step_up.verify_totp(secret, "287082", now=59) is True
    assert step_up.verify_totp(secret, "081804", now=1111111109) is True
    assert step_up.verify_totp(secret, "000000", now=59) is False


# ── Active + presets CRUD (write path: step-up, validation, audit, stream) ──

STEP_SECRET = base64.b32encode(b"policywritekey!!").decode()


def _step_headers(base):
    key = base64.b32decode(STEP_SECRET)
    counter = int(time.time() // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = f"{(struct.unpack('>I', mac[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"
    return {**base, "X-Step-Up-Code": code}


@pytest.fixture
def wclient(cfg, tmp_path):
    from tests.conftest import build_registry_env
    from arbiter.app import create_app
    from fastapi.testclient import TestClient
    cfg.auth.step_up_totp_secret = STEP_SECRET
    env = build_registry_env(cfg, tmp_path)
    app = create_app(cfg, env.registry, env.control)
    c = TestClient(app)
    c.db = env.default_db
    c.env = env
    return c


def test_create_and_activate_preset(wclient, monkeypatch):
    # Single-use step-up (RFC-6238 §5.2 anti-replay): a code authorizes ONE
    # write, so a test chaining two writes must present a code from a NEWER
    # TOTP window for the second one -- exactly what a second real approval
    # tap would produce. A monkeypatched clock (shared by the test's own code
    # generation and the server's verification) advances it deterministically
    # instead of sleeping 30 real seconds.
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    r = wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                     json={"name": "dangerous-shell", "block_patterns": ["rm -rf"],
                           "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r.status_code == 200, r.text
    assert wclient.get("/v1/policy/presets", headers=APP).json()[0]["name"] == "dangerous-shell"
    clock[0] += 30
    a = wclient.put("/v1/policy/active", headers=_step_headers(APP),
                    json={"preset": "dangerous-shell"})
    assert a.status_code == 200
    assert wclient.get("/v1/policy/active", headers=APP).json()["preset"] == "dangerous-shell"
    assert wclient.get("/v1/policy", headers=APP).json()["active_preset"] == "dangerous-shell"


def test_write_requires_step_up(wclient):
    r = wclient.post("/v1/policy/presets", headers=APP,   # no X-Step-Up-Code
                     json={"name": "p", "block_patterns": ["rm -rf"],
                           "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r.status_code == 403


def test_write_rejects_fail_open_preset_400(wclient):
    r = wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                     json={"name": "empty", "default_decision": "allow"})
    assert r.status_code == 400
    assert "gates NOTHING" in r.json()["detail"]


def test_delete_active_preset_409(wclient, monkeypatch):
    # Three step-up-gated writes chained in one test -> three distinct TOTP
    # windows (see test_create_and_activate_preset for why).
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                 json={"name": "dangerous-shell", "block_patterns": ["rm -rf"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    clock[0] += 30
    wclient.put("/v1/policy/active", headers=_step_headers(APP),
                json={"preset": "dangerous-shell"})
    clock[0] += 30
    r = wclient.delete("/v1/policy/presets/dangerous-shell", headers=_step_headers(APP))
    assert r.status_code == 409


def test_mutation_bumps_version_and_audits(wclient):
    before = wclient.get("/v1/policy", headers=APP).json()["version"]
    wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                 json={"name": "p", "block_patterns": ["rm -rf"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    after = wclient.get("/v1/policy", headers=APP).json()["version"]
    assert after == before + 1
    audit = wclient.db.list_audit()
    assert any(a["event"] == "policy_updated" for a in audit)


def test_step_up_code_is_single_use(wclient, monkeypatch):
    """Addition 1: the SAME step-up code must authorize at most one write. A
    captured/replayed code (still inside its ~60-90s verify_totp window) has
    to be rejected, while a code from the NEXT TOTP window keeps working."""
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    headers = _step_headers(APP)
    r1 = wclient.post("/v1/policy/presets", headers=headers,
                      json={"name": "p1", "block_patterns": ["rm -rf"],
                            "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r1.status_code == 200, r1.text
    # Same code, clock unchanged -> replay of an already-consumed counter.
    r2 = wclient.post("/v1/policy/presets", headers=headers,
                      json={"name": "p2", "block_patterns": ["rm -rf"],
                            "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r2.status_code == 403, r2.text
    # A fresh code from the NEXT window still authorizes.
    clock[0] += 30
    r3 = wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                      json={"name": "p3", "block_patterns": ["rm -rf"],
                            "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r3.status_code == 200, r3.text

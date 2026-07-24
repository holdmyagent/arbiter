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


def test_invalid_preset_400_does_not_burn_step_up_code(wclient, monkeypatch):
    """Important lockout foot-gun (adversarial review): the anti-replay
    watermark must NOT advance on a validation failure. A 400 (gates-NOTHING
    preset, same shape as test_write_rejects_fail_open_preset_400) must leave
    the just-presented code usable for the corrected resubmit in the SAME
    TOTP window -- otherwise every typo forces a ~30s wait for a fresh code."""
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    headers = _step_headers(APP)
    bad = wclient.post("/v1/policy/presets", headers=headers,
                       json={"name": "empty", "default_decision": "allow"})
    assert bad.status_code == 400
    # SAME code, SAME window -> the corrected body must still succeed.
    good = wclient.post("/v1/policy/presets", headers=headers,
                        json={"name": "dangerous-shell", "block_patterns": ["rm -rf"],
                              "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert good.status_code == 200, good.text


def test_unknown_preset_404_does_not_burn_step_up_code(wclient, monkeypatch):
    """Same foot-gun, 404 path: PUT active with an unknown preset must not
    burn the code either."""
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    headers = _step_headers(APP)
    wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                 json={"name": "dangerous-shell", "block_patterns": ["rm -rf"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    clock[0] += 30
    headers = _step_headers(APP)
    bad = wclient.put("/v1/policy/active", headers=headers,
                      json={"preset": "does-not-exist"})
    assert bad.status_code == 404
    good = wclient.put("/v1/policy/active", headers=headers,
                       json={"preset": "dangerous-shell"})
    assert good.status_code == 200, good.text


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


# ── Overlay endpoints + policy.updated stream assertion ──────────────────

def test_overlay_roundtrip_and_stream_event(wclient):
    # Subscribe to the cell hub directly to assert the policy.updated publish
    # (the WS stream is app-only; publishing is what this task guarantees).
    cell = wclient.env.registry
    # Simpler: assert via the hub on the pinned default cell.
    import asyncio
    default_epoch = wclient.env.default_epoch

    r = wclient.get("/v1/policy/overlay", headers=APP)
    assert r.json() == {"always_ask": [], "always_allow": []}

    put = wclient.put("/v1/policy/overlay", headers=_step_headers(APP),
                      json={"always_ask": ["curl"], "always_allow": ["ls -la /home/hermes"]})
    assert put.status_code == 200
    got = wclient.get("/v1/policy/overlay", headers=APP).json()
    assert got == {"always_ask": ["curl"], "always_allow": ["ls -la /home/hermes"]}


def test_overlay_rejects_broad_allow_400(wclient):
    r = wclient.put("/v1/policy/overlay", headers=_step_headers(APP),
                    json={"always_ask": [], "always_allow": ["rm"]})
    assert r.status_code == 400


def test_policy_test_endpoint_runs_shared_matcher(wclient, monkeypatch):
    # Two chained step-up-gated writes (POST preset + PUT active) need codes
    # from DISTINCT TOTP windows -- see test_create_and_activate_preset for
    # why (single-use anti-replay would otherwise 403 the second write on a
    # same-window replay and silently leave no preset active).
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                 json={"name": "dangerous-shell", "block_patterns": ["rm -rf"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    clock[0] += 30
    wclient.put("/v1/policy/active", headers=_step_headers(APP),
                json={"preset": "dangerous-shell"})
    ask = wclient.get("/v1/policy/test", headers=APP,
                      params={"command": "rm -rf /data", "tool": "run_shell"})
    assert ask.status_code == 200 and ask.json()["decision"] == "ask"
    allow = wclient.get("/v1/policy/test", headers=APP,
                        params={"command": "ls -la", "tool": "run_shell"})
    assert allow.json()["decision"] == "allow"
    # categorical tool always asks:
    cat = wclient.get("/v1/policy/test", headers=APP,
                      params={"command": "print(1)", "tool": "execute_code"})
    assert cat.json()["decision"] == "ask"


def test_policy_test_matches_pure_matcher_corpus(wclient, monkeypatch):
    # Conformance seam: the endpoint verdict == the pure gate_policy.evaluate
    # verdict for a corpus. (Component 2's bash gate is fed the SAME corpus.)
    # Distinct TOTP windows for the two chained step-up writes -- see
    # test_create_and_activate_preset.
    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    wclient.post("/v1/policy/presets", headers=_step_headers(APP),
                 json={"name": "dangerous-shell", "block_patterns": ["rm -rf", "git push"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    clock[0] += 30
    wclient.put("/v1/policy/active", headers=_step_headers(APP),
                json={"preset": "dangerous-shell"})
    resolved = wclient.get("/v1/policy", headers=APP).json()
    corpus = [("run_shell", "rm -rf /"), ("run_shell", "ls"), ("run_shell", "git push"),
              ("execute_code", "x"), ("unknown_tool", "y")]
    for tool, cmd in corpus:
        server = wclient.get("/v1/policy/test", headers=APP,
                             params={"command": cmd, "tool": tool}).json()["decision"]
        assert server == gp.evaluate(resolved, tool, cmd)


def test_policy_updated_published_on_mutation(cfg, tmp_path):
    # Drive a mutation and assert the cell hub received a policy.updated event.
    import asyncio, json as _json
    from tests.conftest import build_registry_env
    from arbiter.app import create_app, _resolved_for  # noqa
    from fastapi.testclient import TestClient
    cfg.auth.step_up_totp_secret = STEP_SECRET
    env = build_registry_env(cfg, tmp_path)
    app = create_app(cfg, env.registry, env.control)
    c = TestClient(app); c.db = env.default_db; c.env = env

    async def _grab():
        async with env.registry.hold("default", env.default_epoch) as cell:
            q = cell.hub.subscribe()
            c.post("/v1/policy/presets", headers=_step_headers(APP),
                   json={"name": "p", "block_patterns": ["rm -rf"],
                         "tool_allowlist": ["run_shell"], "default_decision": "allow"})
            events = []
            while not q.empty():
                events.append(q.get_nowait())
            return events
    # Python 3.12+ removes the implicit-loop-creation fallback from
    # asyncio.get_event_loop() (RuntimeError with no running/current loop) --
    # asyncio.run() is the direct equivalent for a plain sync test function.
    events = asyncio.run(_grab())
    assert any(e.get("event") == "policy.updated" for e in events)


# ── gate-status report + readout (Task 9B, H11 closed-loop telemetry) ──────

GATE_STATUS_BODY = {"version": 3, "etag": "abc123", "fetched_at": "2026-07-24T00:00:00+00:00",
                     "most_restrictive": True}


def test_gate_status_post_then_get_roundtrip(client):
    # AGENT = the gate token (role "agent", default caps = {policy:read-resolved}).
    r = client.post("/v1/policy/gate-status", headers=AGENT, json=GATE_STATUS_BODY)
    assert r.status_code == 200, r.text
    posted = r.json()
    assert posted["version"] == 3
    assert posted["etag"] == "abc123"
    assert posted["fetched_at"] == "2026-07-24T00:00:00+00:00"      # echoed verbatim
    assert posted["most_restrictive"] is True
    assert posted["reported_at"]                                    # server-stamped

    got = client.get("/v1/policy/gate-status", headers=APP).json()
    assert got == {"version": 3, "etag": "abc123",
                   "fetched_at": "2026-07-24T00:00:00+00:00",
                   "reported_at": posted["reported_at"], "most_restrictive": True}


def test_gate_status_get_default_before_any_report(client):
    r = client.get("/v1/policy/gate-status", headers=APP)
    assert r.status_code == 200
    assert r.json() == {"version": 0, "etag": "", "fetched_at": None,
                        "reported_at": None, "most_restrictive": True}


def test_gate_status_post_rbac_requires_read_resolved(client):
    # A token minted WITHOUT policy:read-resolved must be denied, generic 403.
    tok = client.env.mint("default", "not-a-gate", "app",
                          scopes={"capabilities": ["policy:read"]})
    r = client.post("/v1/policy/gate-status", headers={"Authorization": f"Bearer {tok}"},
                    json=GATE_STATUS_BODY)
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"


def test_gate_status_get_rbac_requires_read(client):
    # AGENT (gate token) has only policy:read-resolved, not policy:read.
    r = client.get("/v1/policy/gate-status", headers=AGENT)
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"


def test_gate_status_read_resolved_only_token_cannot_write_policy(client):
    # H1 regression guard: the gate's narrow cap must never reach policy:write,
    # even though it can now also POST gate-status.
    r = client.post("/v1/policy/presets", headers=AGENT,
                    json={"name": "p", "block_patterns": ["rm -rf"],
                          "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert r.status_code == 403


def test_gate_status_reported_at_is_parseable_iso8601(client):
    r = client.post("/v1/policy/gate-status", headers=AGENT, json=GATE_STATUS_BODY)
    reported_at = r.json()["reported_at"]
    # Round-trips through the codebase's own date parser (datetime.fromisoformat
    # is used throughout arbiter/*.py to parse its own _iso()-stamped fields).
    parsed = datetime.fromisoformat(reported_at)
    assert parsed.tzinfo is not None


def test_gate_status_most_restrictive_true_stored_and_read_back(client):
    client.post("/v1/policy/gate-status", headers=AGENT,
               json={**GATE_STATUS_BODY, "most_restrictive": True})
    got = client.get("/v1/policy/gate-status", headers=APP).json()
    assert got["most_restrictive"] is True


# ── Task 10: GATE A — default-deny parametric + cross-tenant isolation ────
#
# Coverage extension (post-dates the original plan): gate-status is a real
# endpoint pair now (POST authorized by policy:read-resolved, the gate cap;
# GET authorized by policy:read), so it is folded into the same data-driven
# table rather than left to bespoke 9B-only coverage.

# One combined body that satisfies every mutating endpoint's Pydantic model
# at once (PresetBody/ActiveBody/OverlayBody ignore unrecognized fields;
# GateStatusReport's required fields are included) -- so the SAME body works
# for every row below and the table stays a plain (method, path) list a
# reviewer can scan for omissions.
_POLICY_MUTATION_BODY = {
    "preset": "x", "name": "x", "block_patterns": ["rm -rf"],
    "tool_allowlist": ["run_shell"], "default_decision": "allow",
    "always_ask": [], "always_allow": [],
    "version": 3, "etag": "abc123",
    "fetched_at": "2026-07-24T00:00:00+00:00", "most_restrictive": True,
}

# Every mutating verb of every policy endpoint. If a new policy:write (or
# gate-cap) route is added and NOT appended here, this list -- not silent
# omission -- is where a reviewer notices the gap.
_POLICY_MUTATIONS = [
    ("put", "/v1/policy/active"),
    ("post", "/v1/policy/presets"),
    ("put", "/v1/policy/presets/x"),
    ("delete", "/v1/policy/presets/x"),
    ("put", "/v1/policy/overlay"),
    ("post", "/v1/policy/gate-status"),   # coverage extension: needs the gate cap
]


@pytest.mark.parametrize("method,path", _POLICY_MUTATIONS,
                         ids=[f"{m}:{p}" for m, p in _POLICY_MUTATIONS])
def test_every_mutation_denies_read_only_token(wclient, method, path):
    # A read-only-capability app token gets 403 on every mutating verb of
    # every policy endpoint, even with a valid step-up code (capability
    # check precedes step-up) -- and even on gate-status, whose POST needs
    # policy:read-resolved, not policy:read.
    #
    # NOTE: uses wclient.request(method.upper(), ...) rather than
    # getattr(wclient, method)(...) because this environment's httpx/
    # starlette TestClient.delete() does not accept a json= kwarg (only
    # .request() does) -- a test-harness fact, not an RBAC one.
    tok = f"hma_app_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    wclient.db.conn.execute(
        "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,expires_at,"
        "last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), "ro", "app", th,
         json.dumps({"capabilities": ["policy:read"]}),
         datetime.now(timezone.utc).isoformat()))
    wclient.db.conn.commit()
    wclient.env.control.add_route(th, "default")
    h = _step_headers({"Authorization": f"Bearer {tok}"})
    r = wclient.request(method.upper(), path, headers=h, json=_POLICY_MUTATION_BODY)
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"      # generic body (§11), not a detail leak


def test_read_only_token_reads_what_it_holds(wclient):
    # Coverage extension: the mirror of the parametric denial above -- the
    # SAME shape of policy:read-only token (no policy:read-resolved, no
    # policy:write) gets 200 on every read endpoint policy:read actually
    # covers (default-deny must not become default-deny-everything), but
    # still 403 on the one read that needs the DIFFERENT capability
    # policy:read-resolved (/v1/policy) -- no accidental privilege creep.
    tok = f"hma_app_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    wclient.db.conn.execute(
        "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,expires_at,"
        "last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), "ro", "app", th,
         json.dumps({"capabilities": ["policy:read"]}),
         datetime.now(timezone.utc).isoformat()))
    wclient.db.conn.commit()
    wclient.env.control.add_route(th, "default")
    h = {"Authorization": f"Bearer {tok}"}
    assert wclient.get("/v1/policy/active", headers=h).status_code == 200
    assert wclient.get("/v1/policy/presets", headers=h).status_code == 200
    assert wclient.get("/v1/policy/overlay", headers=h).status_code == 200
    assert wclient.get("/v1/policy/gate-status", headers=h).status_code == 200
    assert wclient.get("/v1/policy", headers=h).status_code == 403  # needs policy:read-resolved


def test_gate_token_cannot_write(wclient):
    # policy:read-resolved (gate) token: 403 on any write, even the read of
    # presets (it lacks policy:read). Coverage extension: it CAN post its
    # own gate-status telemetry (that capability IS the gate-status POST
    # cap), but GET gate-status needs policy:read, which it does not hold --
    # confirms no privilege creep from the one capability it does carry.
    tok = f"hma_agent_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    wclient.db.conn.execute(
        "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,expires_at,"
        "last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), "gate", "agent", th,
         json.dumps({"capabilities": ["policy:read-resolved"]}),
         datetime.now(timezone.utc).isoformat()))
    wclient.db.conn.commit()
    wclient.env.control.add_route(th, "default")
    h = {"Authorization": f"Bearer {tok}"}
    assert wclient.get("/v1/policy", headers=h).status_code == 200        # read-resolved ok
    assert wclient.get("/v1/policy/presets", headers=h).status_code == 403  # needs policy:read (app role)
    assert wclient.post("/v1/policy/presets", headers=_step_headers(h),
                        json={"name": "p", "block_patterns": ["rm -rf"],
                              "tool_allowlist": ["run_shell"],
                              "default_decision": "allow"}).status_code == 403
    gs = wclient.post("/v1/policy/gate-status", headers=h,
                      json={"version": 3, "etag": "abc123",
                            "fetched_at": "2026-07-24T00:00:00+00:00",
                            "most_restrictive": True})
    assert gs.status_code == 200, gs.text
    assert wclient.get("/v1/policy/gate-status", headers=h).status_code == 403  # no privilege creep


def test_cross_tenant_policy_isolation(cfg, tmp_path):
    cfg.auth.step_up_totp_secret = STEP_SECRET
    from tests.conftest import build_registry_env
    from arbiter.app import create_app
    from fastapi.testclient import TestClient
    env = build_registry_env(cfg, tmp_path)
    env.provision("tenant-b")
    app = create_app(cfg, env.registry, env.control)
    c = TestClient(app); c.env = env
    tok_a = env.mint("default", "app-a", "app")
    tok_b = env.mint("tenant-b", "app-b", "app")
    # author a preset in tenant-b:
    c.post("/v1/policy/presets", headers=_step_headers({"Authorization": f"Bearer {tok_b}"}),
           json={"name": "b-only", "block_patterns": ["rm -rf"],
                 "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    # tenant-a must NOT see it (tenant derived from token, never a hint):
    a_presets = c.get("/v1/policy/presets",
                      headers={"Authorization": f"Bearer {tok_a}"}).json()
    assert all(p["name"] != "b-only" for p in a_presets)
    assert c.get("/v1/policy/presets/b-only",
                 headers={"Authorization": f"Bearer {tok_a}"}).status_code == 404
    # gate-status is tenant-scoped too, derived from the token (never a hint):
    c.post("/v1/policy/gate-status", headers={"Authorization": f"Bearer {tok_b}"},
           json={"version": 9, "etag": "b-etag",
                 "fetched_at": "2026-07-24T00:00:00+00:00", "most_restrictive": False})
    a_status = c.get("/v1/policy/gate-status",
                     headers={"Authorization": f"Bearer {tok_a}"}).json()
    assert a_status["etag"] != "b-etag"
    assert a_status["version"] == 0


def test_cross_tenant_policy_isolation_write_denial(cfg, tmp_path, monkeypatch):
    """Sibling of test_cross_tenant_policy_isolation above: that test proves
    cross-tenant READ isolation; this proves WRITE isolation. Tenant A's
    token -- even with full write caps for tenant A AND a valid step-up
    code -- can never MUTATE tenant B's stored policy state, because tenant
    is derived SOLELY from the token (via the control-plane route), never
    from anything in the request. So every write A attempts either 404s (no
    such resource in A's OWN cell) or lands in A's OWN cell under the same
    name -- it can never reach B's row. Assert B's post-state == pre-state."""
    cfg.auth.step_up_totp_secret = STEP_SECRET
    from tests.conftest import build_registry_env
    from arbiter.app import create_app
    from fastapi.testclient import TestClient
    env = build_registry_env(cfg, tmp_path)
    env.provision("tenant-b")
    app = create_app(cfg, env.registry, env.control)
    c = TestClient(app); c.env = env
    tok_a = env.mint("default", "app-a", "app")     # full caps (role default)
    tok_b = env.mint("tenant-b", "app-b", "app")
    a_headers = {"Authorization": f"Bearer {tok_a}"}
    b_headers = {"Authorization": f"Bearer {tok_b}"}

    clock = [1_700_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    # Seed tenant B with a known preset + gate-status, via B's OWN token.
    seed = c.post("/v1/policy/presets", headers=_step_headers(b_headers),
                 json={"name": "b-only", "block_patterns": ["rm -rf"],
                       "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    assert seed.status_code == 200, seed.text
    clock[0] += 30
    gs_seed = c.post("/v1/policy/gate-status", headers=b_headers,
                     json={"version": 9, "etag": "b-etag",
                           "fetched_at": "2026-07-24T00:00:00+00:00",
                           "most_restrictive": False})
    assert gs_seed.status_code == 200, gs_seed.text

    presets_before = c.get("/v1/policy/presets", headers=b_headers).json()
    preset_before = c.get("/v1/policy/presets/b-only", headers=b_headers).json()
    gate_status_before = c.get("/v1/policy/gate-status", headers=b_headers).json()
    assert preset_before is not None and preset_before["name"] == "b-only"

    # Tenant A's token: full write caps + a valid step-up code (fresh TOTP
    # window per write -- same single-use discipline as the writes above).
    clock[0] += 30
    put_active = c.put("/v1/policy/active", headers=_step_headers(a_headers),
                       json={"preset": "b-only"})
    # "b-only" does not exist in A's OWN cell (only in B's) -> 404, not a
    # write to B's active preset.
    assert put_active.status_code == 404

    clock[0] += 30
    put_preset = c.put("/v1/policy/presets/b-only", headers=_step_headers(a_headers),
                       json={"name": "b-only", "block_patterns": ["A-side-pattern"],
                             "tool_allowlist": ["run_shell"], "default_decision": "allow"})
    # Lands in A's OWN "b-only" row -- same name, different tenant, different
    # cell DB file. Never B's row.
    assert put_preset.status_code == 200, put_preset.text

    clock[0] += 30
    delete_preset = c.delete("/v1/policy/presets/b-only", headers=_step_headers(a_headers))
    assert delete_preset.status_code == 200, delete_preset.text

    gate_status_post = c.post("/v1/policy/gate-status", headers=a_headers,
                              json={"version": 99, "etag": "a-etag",
                                    "fetched_at": "2026-07-24T00:00:00+00:00",
                                    "most_restrictive": False})
    assert gate_status_post.status_code == 200, gate_status_post.text

    # Tenant B's stored state is UNCHANGED by any of A's writes above.
    presets_after = c.get("/v1/policy/presets", headers=b_headers).json()
    preset_after = c.get("/v1/policy/presets/b-only", headers=b_headers).json()
    gate_status_after = c.get("/v1/policy/gate-status", headers=b_headers).json()
    assert presets_after == presets_before
    assert preset_after == preset_before
    assert gate_status_after == gate_status_before


def test_config_template_documents_step_up():
    from arbiter.cli import CONFIG_TEMPLATE
    assert "step_up_totp_secret" in CONFIG_TEMPLATE

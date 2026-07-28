"""Auto-approval on POST /v1/requests under a live (agent, tool) grant."""
import pytest
from fastapi.testclient import TestClient

from arbiter.apns import APNsSender
from arbiter.app import create_app
from arbiter.scheduler import ExpiryScheduler

PAYLOAD = {"agent": "hermes", "tool": "skill_manage", "verb": "create"}


@pytest.fixture
def client(cfg, registry_env):
    app = create_app(cfg, registry_env.registry, registry_env.control, sender=APNsSender(cfg))
    with TestClient(app) as c:
        c.db = registry_env.default_db
        c.env = registry_env
        yield c


def _grant(client, agent="hermes", tool="skill_manage", ttl=900, by="kevin-phone"):
    return client.db.create_grant(agent=agent, tool=tool, granted_by=by,
                                  granted_via="app-token", request_id=None,
                                  ttl_seconds=ttl)


def _create(client, agent_headers, payload=None, severity="high", title="Hermes: x"):
    body = {"title": title, "severity": severity,
            "payload": payload if payload is not None else dict(PAYLOAD)}
    r = client.post("/v1/requests", headers=agent_headers, json=body)
    assert r.status_code == 200
    return r.json()


def _events(client, rid):
    return [r["event"] for r in client.db.list_audit(request_id=rid)]


def test_matching_grant_decides_the_request_immediately(client, agent_headers):
    g = _grant(client)
    body = _create(client, agent_headers)
    assert body["status"] == "approved"
    row = client.db.get_request(body["id"])
    assert row["status"] == "approved"
    assert row["decided_via"] == "grant"          # a distinct authority class
    assert row["decided_by"] == g["granted_by"]   # the operator who granted it
    assert "auto_approved" in _events(client, body["id"])


def test_auto_approval_is_never_dressed_up_as_a_device_tap(client, agent_headers):
    _grant(client)
    rid = _create(client, agent_headers)["id"]
    row = client.db.get_request(rid)
    assert row["attestation"] is None and row["attest_key_id"] is None
    assert all(r["decided_device"] is None for r in client.db.list_audit(request_id=rid))


def test_auto_approved_request_has_a_verdict_the_warden_can_fetch(client):
    """The warden polls GET /v1/requests/{rid}/verdict and treats 404 as
    retryable, so an approved-but-verdict-less row would never execute.

    Mirrors warden/hold_warden/arbiter.py's real usage: one ArbiterClient
    bearer both creates the request and later polls its own verdict -- the
    ownership check on a DB token's rows (own rows only) means create and
    fetch must be the same identity, exactly as the real warden does it.
    """
    _grant(client)
    tok = client.env.mint("default", "warden1", "warden")
    wh = {"Authorization": f"Bearer {tok}"}
    rid = _create(client, wh)["id"]
    row = client.db.get_request(rid)
    assert row["verdict_jws"] and row["verdict_kid"]
    v = client.get(f"/v1/requests/{rid}/verdict", headers=wh)
    assert v.status_code == 200 and v.json()["verdict"] == row["verdict_jws"]
    assert "verdict_issued" in _events(client, rid)


@pytest.mark.parametrize("payload,severity,why", [
    ({"agent": "iris", "tool": "skill_manage"}, "high", "agent mismatch"),
    ({"agent": "hermes", "tool": "shell"}, "high", "tool mismatch"),
    ({"agent": "HERMES", "tool": "skill_manage"}, "high", "case is not folded"),
    ({"agent": "hermes"}, "high", "no tool key"),
    ({"tool": "skill_manage"}, "high", "no agent key"),
    ({}, "high", "empty payload — the live 0.6 incident shape"),
    ({"agent": "", "tool": "skill_manage"}, "high", "empty agent string"),
    ({"agent": "hermes", "tool": ""}, "high", "empty tool string"),
    ({"agent": 1, "tool": 2}, "high", "non-string keys"),
    ({"agent": "hermes", "tool": "skill_manage"}, "critical", "critical never auto-approves"),
])
def test_anything_short_of_an_exact_match_still_asks(client, agent_headers,
                                                     payload, severity, why):
    _grant(client)
    body = _create(client, agent_headers, payload=payload, severity=severity, title=why)
    assert body["status"] == "pending", why
    assert "auto_approved" not in _events(client, body["id"])


def test_an_expired_grant_still_asks(client, agent_headers):
    from datetime import datetime, timedelta, timezone
    g = _grant(client, ttl=60)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    client.db.conn.execute("UPDATE grants SET expires_at=? WHERE id=?", (past, g["id"]))
    client.db.conn.commit()
    assert _create(client, agent_headers)["status"] == "pending"


def test_a_revoked_grant_still_asks(client, agent_headers):
    g = _grant(client)
    client.db.revoke_grant(g["id"])
    assert _create(client, agent_headers)["status"] == "pending"


def test_the_gate_needs_no_change_the_row_is_simply_already_decided(client, agent_headers):
    """The gate polls GET /v1/requests/{rid}. Under a grant it finds the answer
    on the first poll instead of waiting for a tap -- no new gate behaviour."""
    _grant(client)
    rid = _create(client, agent_headers)["id"]
    r = client.get(f"/v1/requests/{rid}", headers=agent_headers)
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_created_then_decided_both_publish_on_the_hub_in_that_order(client, agent_headers,
                                                                    app_headers):
    _grant(client)
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        rid = _create(client, agent_headers)["id"]
        first = ws.receive_json()
        assert first["event"] == "request.created" and first["request"]["status"] == "pending"
        second = ws.receive_json()
        assert second["event"] == "request.decided"
        assert second["request"]["id"] == rid
        assert second["request"]["decided_via"] == "grant"


def test_auto_approval_arms_the_staleness_deadline(cfg, registry_env, agent_headers):
    """An auto-approved request must go stale on the same clock as a tapped
    one, or it would stay consumable forever. Driven with the REAL scheduler
    (the lifespan calls run()/stop()/_bg on it, so a stub would have to
    reimplement the class) and asserted on its deadline heap: both deadlines
    are minutes away, so nothing fires during the test."""
    sched = ExpiryScheduler(registry_env.registry, registry_env.control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
    app = create_app(cfg, registry_env.registry, registry_env.control,
                     sender=APNsSender(cfg), scheduler=sched)
    with TestClient(app) as c:
        registry_env.default_db.create_grant(
            agent="hermes", tool="skill_manage", granted_by="kevin-phone",
            granted_via="app-token", request_id=None, ttl_seconds=900)
        r = c.post("/v1/requests", headers=agent_headers,
                   json={"title": "t", "severity": "high", "ttl_seconds": 300,
                         "payload": dict(PAYLOAD)})
        rid = r.json()["id"]
        assert r.json()["status"] == "approved"
        # heap entries are (deadline_ts, seq, tenant_id, request_id)
        mine = sorted(e[0] for e in sched._heap if e[3] == rid)
    # one deadline for the request's own TTL, one for the approval's staleness
    assert len(mine) == 2 and mine[0] != mine[1]


def test_a_grant_never_widens_what_the_agent_may_see(client, agent_headers):
    """The auto-approved row goes back through _redact_for like every other
    return site, so an agent-role caller never gains exec_* visibility."""
    _grant(client)
    body = _create(client, agent_headers)
    assert body["exec_ran"] is None and body["exec_output"] is None

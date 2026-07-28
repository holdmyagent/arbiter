"""Issuing a scoped grant alongside an approval, via POST /v1/requests/{rid}/decision."""
import pytest
from fastapi.testclient import TestClient

from arbiter.apns import APNsSender
from arbiter.app import create_app
from arbiter.grants import GRANT_TTL_MAX_SECONDS

PAYLOAD = {"agent": "hermes", "tool": "skill_manage", "verb": "create"}


@pytest.fixture
def client(cfg, registry_env):
    app = create_app(cfg, registry_env.registry, registry_env.control, sender=APNsSender(cfg))
    with TestClient(app) as c:
        c.db = registry_env.default_db
        c.env = registry_env
        yield c


def _create(client, agent_headers, payload=None, severity="high"):
    body = {"title": "Hermes: skill_manage create", "severity": severity,
            "payload": payload if payload is not None else dict(PAYLOAD)}
    r = client.post("/v1/requests", headers=agent_headers, json=body)
    assert r.status_code == 200
    return r.json()["id"]


def _decide(client, headers, rid, **body):
    return client.post(f"/v1/requests/{rid}/decision", headers=headers,
                       json={"decision": "approve", **body})


def _audit_events(client, rid):
    return [(r["event"], r["detail"]) for r in client.db.list_audit(request_id=rid)]


def test_approve_with_ttl_issues_a_grant_with_honest_provenance(client, agent_headers):
    tok = client.env.mint("default", "kevin-phone", "app")
    rid = _create(client, agent_headers)
    r = _decide(client, {"Authorization": f"Bearer {tok}"}, rid, grant_ttl_seconds=900)
    assert r.status_code == 200 and r.json()["status"] == "approved"

    grants = client.db.list_grants()
    assert len(grants) == 1
    g = grants[0]
    assert g["agent"] == "hermes" and g["tool"] == "skill_manage"
    assert g["granted_by"] == "kevin-phone"       # the identity, not a role
    assert g["granted_via"] == "app-token"        # mirrors decided_via
    assert g["request_id"] == rid and g["state"] == "active"


def test_grant_via_mirrors_a_legacy_token_decision(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    assert _decide(client, app_headers, rid, grant_ttl_seconds=300).status_code == 200
    g = client.db.list_grants()[0]
    assert g["granted_via"] == "legacy-token"
    assert g["granted_by"] == "app (legacy token)"


def test_grant_created_audit_names_the_scope(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    _decide(client, app_headers, rid, grant_ttl_seconds=300)
    created = [d for e, d in _audit_events(client, rid) if e == "grant_created"]
    assert len(created) == 1
    detail = created[0]
    assert '"agent": "hermes"' in detail and '"tool": "skill_manage"' in detail
    assert '"ttl": 300' in detail


def test_no_ttl_means_no_grant(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    assert _decide(client, app_headers, rid).status_code == 200
    assert client.db.list_grants() == []
    assert "grant_skipped" not in [e for e, _ in _audit_events(client, rid)]


def test_deny_with_ttl_denies_and_skips_the_grant(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    r = client.post(f"/v1/requests/{rid}/decision", headers=app_headers,
                    json={"decision": "deny", "grant_ttl_seconds": 300})
    assert r.status_code == 200 and r.json()["status"] == "denied"
    assert client.db.list_grants() == []
    skipped = [d for e, d in _audit_events(client, rid) if e == "grant_skipped"]
    assert len(skipped) == 1 and "denied" in skipped[0]


def test_request_without_agent_tool_keys_still_approves(client, agent_headers, app_headers):
    """The live 0.6 incident shape: payload = {}. The approval must land; only
    the grant part is dropped, with a note saying why. Never a 500."""
    rid = _create(client, agent_headers, payload={})
    r = _decide(client, app_headers, rid, grant_ttl_seconds=300)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert client.db.list_grants() == []
    skipped = [d for e, d in _audit_events(client, rid) if e == "grant_skipped"]
    assert len(skipped) == 1 and "missing_agent_tool" in skipped[0]


def test_request_with_empty_string_keys_still_approves(client, agent_headers, app_headers):
    rid = _create(client, agent_headers, payload={"agent": "", "tool": "skill_manage"})
    assert _decide(client, app_headers, rid, grant_ttl_seconds=300).status_code == 200
    assert client.db.list_grants() == []


def test_ttl_at_the_cap_is_accepted(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    r = _decide(client, app_headers, rid, grant_ttl_seconds=GRANT_TTL_MAX_SECONDS)
    assert r.status_code == 200
    assert len(client.db.list_grants()) == 1


def test_ttl_over_the_cap_is_422_with_no_decision_side_effect(client, agent_headers, app_headers):
    rid = _create(client, agent_headers)
    r = _decide(client, app_headers, rid, grant_ttl_seconds=GRANT_TTL_MAX_SECONDS + 1)
    assert r.status_code == 422
    row = client.db.get_request(rid)
    assert row["status"] == "pending"        # the decision never landed
    assert row["decided_at"] is None and row["decided_by"] is None
    assert client.db.list_grants() == []
    # and the request is still decidable afterwards — the 422 cost nothing
    assert _decide(client, app_headers, rid).status_code == 200


def test_zero_and_negative_ttl_are_422(client, agent_headers, app_headers):
    for bad in (0, -1):
        rid = _create(client, agent_headers)
        assert _decide(client, app_headers, rid, grant_ttl_seconds=bad).status_code == 422
        assert client.db.get_request(rid)["status"] == "pending"


def test_a_losing_decision_leaves_no_grant_behind(client, agent_headers, app_headers):
    """set_decision has exactly one winner. The loser gets a 409 and must not
    mint a grant off a decision it did not make."""
    rid = _create(client, agent_headers)
    assert _decide(client, app_headers, rid, grant_ttl_seconds=300).status_code == 200
    assert len(client.db.list_grants()) == 1
    second = _decide(client, app_headers, rid, grant_ttl_seconds=300)
    assert second.status_code == 409
    assert len(client.db.list_grants()) == 1      # still one, not two


def test_grant_created_event_follows_request_decided_on_the_hub(client, agent_headers,
                                                                app_headers):
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        rid = _create(client, agent_headers)
        assert ws.receive_json()["event"] == "request.created"
        assert _decide(client, app_headers, rid, grant_ttl_seconds=300).status_code == 200
        assert ws.receive_json()["event"] == "request.decided"
        evt = ws.receive_json()
        assert evt["event"] == "grant.created"
        assert evt["grant"]["agent"] == "hermes" and evt["grant"]["tool"] == "skill_manage"
        assert evt["grant"]["state"] == "active"


def test_no_grant_event_when_no_grant_was_issued(client, agent_headers, app_headers):
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        rid = _create(client, agent_headers)
        assert ws.receive_json()["event"] == "request.created"
        assert _decide(client, app_headers, rid).status_code == 200
        assert ws.receive_json()["event"] == "request.decided"
        rid2 = _create(client, agent_headers, payload={"agent": "iris", "tool": "shell"})
        # the next message is the SECOND create, not a stray grant.created
        assert ws.receive_json()["event"] == "request.created"
        assert client.db.get_request(rid2)["status"] == "pending"

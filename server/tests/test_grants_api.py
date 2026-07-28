"""GET /v1/grants and POST /v1/grants/{id}/revoke — the operator's control surface."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from arbiter.apns import APNsSender
from arbiter.app import create_app
from arbiter.grants import GRANT_RECENT_SECONDS

PAYLOAD = {"agent": "hermes", "tool": "skill_manage"}
GRANT_FIELDS = {"id", "agent", "tool", "granted_by", "granted_via", "request_id",
                "created_at", "expires_at", "revoked_at", "state"}


@pytest.fixture
def client(cfg, registry_env):
    app = create_app(cfg, registry_env.registry, registry_env.control, sender=APNsSender(cfg))
    with TestClient(app) as c:
        c.db = registry_env.default_db
        c.env = registry_env
        yield c


def _grant(client, tool="skill_manage", ttl=900):
    return client.db.create_grant(agent="hermes", tool=tool, granted_by="kevin-phone",
                                  granted_via="app-token", request_id="r1", ttl_seconds=ttl)


def _age_out(client, grant_id, seconds):
    past = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    client.db.conn.execute("UPDATE grants SET expires_at=? WHERE id=?", (past, grant_id))
    client.db.conn.commit()


def test_list_requires_the_app_role(client, agent_headers, app_headers):
    assert client.get("/v1/grants", headers=agent_headers).status_code == 403
    tok = client.env.mint("default", "warden1", "warden")
    assert client.get("/v1/grants",
                      headers={"Authorization": f"Bearer {tok}"}).status_code == 403
    assert client.get("/v1/grants", headers=app_headers).status_code == 200


def test_list_returns_the_schema_and_nothing_else(client, app_headers):
    """A grants row carries names and timestamps -- never request content -- so
    _redact_for has nothing to do here. This test is the guard that keeps it
    that way: a future field carrying command text would fail it."""
    _grant(client)
    body = client.get("/v1/grants", headers=app_headers).json()
    assert set(body) == {"grants"} and len(body["grants"]) == 1
    assert set(body["grants"][0]) == GRANT_FIELDS


def test_list_orders_active_first_then_recent_each_newest_first(client, app_headers):
    older = _grant(client, tool="a")
    newer = _grant(client, tool="b")
    gone = _grant(client, tool="c")
    client.db.revoke_grant(gone["id"])
    got = client.get("/v1/grants", headers=app_headers).json()["grants"]
    assert [g["id"] for g in got] == [newer["id"], older["id"], gone["id"]]
    assert [g["state"] for g in got] == ["active", "active", "revoked"]


def test_list_drops_grants_inert_for_more_than_a_day(client, app_headers):
    fresh = _grant(client, tool="fresh")
    _age_out(client, fresh["id"], 60)
    stale = _grant(client, tool="stale")
    _age_out(client, stale["id"], GRANT_RECENT_SECONDS + 60)
    ids = [g["id"] for g in client.get("/v1/grants", headers=app_headers).json()["grants"]]
    assert ids == [fresh["id"]]


def test_revoke_requires_the_app_role(client, agent_headers):
    g = _grant(client)
    r = client.post(f"/v1/grants/{g['id']}/revoke", headers=agent_headers)
    assert r.status_code == 403
    assert client.db.get_grant(g["id"])["revoked_at"] is None


def test_revoke_stamps_audits_and_returns_the_row(client, app_headers):
    g = _grant(client)
    r = client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers)
    assert r.status_code == 200
    assert r.json()["state"] == "revoked" and r.json()["revoked_at"] is not None
    rows = [a for a in client.db.list_audit(request_id="-") if a["event"] == "grant_revoked"]
    assert len(rows) == 1 and g["id"] in rows[0]["detail"]


def test_revoke_is_idempotent(client, app_headers):
    g = _grant(client)
    first = client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers).json()
    second = client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers)
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first["revoked_at"]     # not re-stamped
    rows = [a for a in client.db.list_audit(request_id="-") if a["event"] == "grant_revoked"]
    assert len(rows) == 1                                          # and not re-audited


def test_revoking_an_expired_grant_succeeds(client, app_headers):
    g = _grant(client)
    _age_out(client, g["id"], 60)
    r = client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers)
    assert r.status_code == 200 and r.json()["state"] == "revoked"


def test_revoke_unknown_grant_is_404(client, app_headers):
    assert client.post("/v1/grants/no-such-grant/revoke",
                       headers=app_headers).status_code == 404


def test_revoke_publishes_grant_revoked_on_the_hub(client, app_headers):
    g = _grant(client)
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        assert client.post(f"/v1/grants/{g['id']}/revoke",
                           headers=app_headers).status_code == 200
        evt = ws.receive_json()
        assert evt["event"] == "grant.revoked"
        assert evt["grant"]["id"] == g["id"] and evt["grant"]["state"] == "revoked"


def test_an_idempotent_revoke_publishes_nothing(client, app_headers):
    g = _grant(client)
    client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers)
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers)
        # nothing to see: the next message is the ask we deliberately create
        rid = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                          json={"title": "t", "payload": dict(PAYLOAD)}).json()["id"]
        assert ws.receive_json()["event"] == "request.created"
        assert client.db.get_request(rid)["status"] == "pending"


def test_revoke_bites_on_the_very_next_create(client, agent_headers, app_headers):
    """The full lifecycle the design asks for: a matching create auto-approves,
    the operator revokes, the next create asks again. Nothing in flight is
    disturbed -- the first request stays approved."""
    g = _grant(client)
    first = client.post("/v1/requests", headers=agent_headers,
                        json={"title": "one", "payload": dict(PAYLOAD)}).json()
    assert first["status"] == "approved"
    assert client.post(f"/v1/grants/{g['id']}/revoke", headers=app_headers).status_code == 200
    second = client.post("/v1/requests", headers=agent_headers,
                         json={"title": "two", "payload": dict(PAYLOAD)}).json()
    assert second["status"] == "pending"
    assert client.db.get_request(first["id"])["status"] == "approved"

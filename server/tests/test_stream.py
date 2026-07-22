import pytest

# E7 (task-E7-brief): /v1/stream now delegates to run_stream against the
# request's acquired cell.hub (no more process-global `hub`) — these tests
# pass for real again.


def test_stream_rejects_without_auth(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/v1/stream"):
            pass


def test_stream_emits_created_and_decided(client, agent_headers, app_headers):
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        rid = client.post("/v1/requests", headers=agent_headers, json={"title": "x"}).json()["id"]
        evt = ws.receive_json()
        assert evt["event"] == "request.created" and evt["request"]["id"] == rid
        client.post(f"/v1/requests/{rid}/decision", headers=app_headers, json={"decision": "approve"})
        evt = ws.receive_json()
        assert evt["event"] == "request.decided" and evt["request"]["status"] == "approved"


def test_stream_emits_device_updated(client, app_headers):
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        client.post("/v1/devices", headers=app_headers, json={"apns_token": "t1", "name": "iPhone"})
        evt = ws.receive_json()
        assert evt["event"] == "device.updated" and evt["device"]["name"] == "iPhone"


def test_stream_heartbeat(cfg, tmp_path):
    from arbiter.apns import APNsSender
    from arbiter.app import create_app
    from fastapi.testclient import TestClient
    from tests.conftest import build_registry_env
    env = build_registry_env(cfg, tmp_path, sender=APNsSender(cfg))
    app = create_app(cfg, env.registry, env.control, sender=APNsSender(cfg), ws_heartbeat=0.05)
    with TestClient(app) as c:
        with c.websocket_connect("/v1/stream", headers={"Authorization": f"Bearer {cfg.auth.app_token}"}) as ws:
            assert ws.receive_json()["event"] == "ping"


# --- #19: /v1/stream is app-role ONLY (capability matrix; #14 least-privilege) ---
# The feed of every approval request must not be watchable by an agent/warden
# credential. Legacy app_token opening the stream is already covered by
# test_stream_emits_* / test_stream_heartbeat above; the admin session cookie by
# test_dashboard.test_stream_accepts_session_cookie — so neither is duplicated here.


def test_stream_db_app_token_opens(client, agent_headers):
    tok = client.env.mint("default", "streamer", "app")
    with client.websocket_connect("/v1/stream",
                                  headers={"Authorization": f"Bearer {tok}"}) as ws:
        rid = client.post("/v1/requests", headers=agent_headers,
                          json={"title": "x"}).json()["id"]
        evt = ws.receive_json()
        assert evt["event"] == "request.created" and evt["request"]["id"] == rid


def test_stream_db_agent_token_rejected(client):
    tok = client.env.mint("default", "worker", "agent")
    with pytest.raises(Exception):
        with client.websocket_connect("/v1/stream",
                                      headers={"Authorization": f"Bearer {tok}"}):
            pass


def test_stream_db_warden_token_rejected(client):
    tok = client.env.mint("default", "gate", "warden")
    with pytest.raises(Exception):
        with client.websocket_connect("/v1/stream",
                                      headers={"Authorization": f"Bearer {tok}"}):
            pass


def test_stream_legacy_agent_token_rejected(client, agent_headers):
    with pytest.raises(Exception):
        with client.websocket_connect("/v1/stream", headers=agent_headers):
            pass

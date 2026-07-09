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

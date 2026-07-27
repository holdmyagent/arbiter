import json
import time

import httpx
import pytest


def _approved_request(client, agent_headers, app_headers):
    rid = client.post("/v1/requests", headers=agent_headers, json={"title": "t"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers=app_headers,
                    json={"decision": "approve"})
    assert d.status_code == 200
    return rid


def _warden_headers(client):
    tok = client.env.mint("default", "warden1", "warden")
    return {"Authorization": f"Bearer {tok}"}


def _wait_until(predicate, timeout=2.0, interval=0.02):
    """Bounded poll for the live app's background (loop-thread) publish tasks
    to catch up with a sync-thread assertion. Used both to wait for an
    expected event (returns True promptly) and, with a short timeout, to
    prove one did NOT happen within a generous window (returns False)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _patch_async_client(monkeypatch, handler):
    """WebhookNotifier is built with transport=None on the live registry path
    (no seam threads a MockTransport through create_app/TenantRegistry), so
    intercept httpx.AsyncClient itself -- same Cap-subclass technique
    test_cli.py uses for httpx.Client -- and force our MockTransport in."""
    import arbiter.notify.webhook as webhook_mod
    real = webhook_mod.httpx.AsyncClient

    class Cap(real):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(webhook_mod.httpx, "AsyncClient", Cap)


def test_exec_report_publishes_request_executed_on_hub(client, agent_headers, app_headers):
    warden_headers = _warden_headers(client)
    with client.websocket_connect("/v1/stream", headers=app_headers) as ws:
        rid = client.post("/v1/requests", headers=agent_headers, json={"title": "t"}).json()["id"]
        assert ws.receive_json()["event"] == "request.created"
        d = client.post(f"/v1/requests/{rid}/decision", headers=app_headers,
                        json={"decision": "approve"})
        assert d.status_code == 200
        assert ws.receive_json()["event"] == "request.decided"

        assert client.post(f"/v1/requests/{rid}/consume",
                           headers=warden_headers).status_code == 200
        r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                        json={"mode": "exec_result", "exit_code": 3,
                              "ran": "systemctl restart nginx", "output": "boom\n",
                              "kind": "command"})
        assert r.status_code == 200

        evt = ws.receive_json()
        assert evt["event"] == "request.executed"
        assert evt["request"]["id"] == rid
        assert evt["request"]["exec_exit_code"] == 3
        assert evt["request"]["exec_kind"] == "command"


def test_exec_report_does_not_refire_decided_callback(client, agent_headers, app_headers,
                                                       monkeypatch):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200)

    _patch_async_client(monkeypatch, handler)

    warden_headers = _warden_headers(client)
    rid = client.post("/v1/requests", headers=agent_headers,
                      json={"title": "t", "callback_url": "http://agent.local/cb"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers=app_headers,
                    json={"decision": "approve"})
    assert d.status_code == 200
    assert _wait_until(lambda: calls.count("http://agent.local/cb") == 1)

    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                    json={"mode": "exec_result", "exit_code": 0,
                          "ran": "x", "output": "y", "kind": "command"})
    assert r.status_code == 200

    # Prove absence within a bound, not by sleeping-and-hoping: give a wrongly
    # routed second callback a generous window to show up, then confirm it never did.
    assert not _wait_until(lambda: calls.count("http://agent.local/cb") >= 2, timeout=0.5)
    assert calls.count("http://agent.local/cb") == 1


def test_exec_report_delivers_executed_webhook(client, cfg, agent_headers, app_headers,
                                               monkeypatch):
    events = []

    def handler(request):
        events.append(json.loads(request.content)["event"])
        return httpx.Response(200)

    _patch_async_client(monkeypatch, handler)
    cfg.webhook.url = "http://hook.local/x"     # same WebhookCfg object the default cell reads

    warden_headers = _warden_headers(client)
    rid = _approved_request(client, agent_headers, app_headers)
    assert _wait_until(lambda: "request.decided" in events)

    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                    json={"mode": "exec_result", "exit_code": 0,
                          "ran": "x", "output": "y", "kind": "command"})
    assert r.status_code == 200
    assert _wait_until(lambda: "request.executed" in events)


def test_agent_role_still_cannot_subscribe_stream(client):
    """Pinned next to request.executed (R6): the stream stays app-role only, so
    its unredacted payload (exec_* included) never reaches an agent credential.
    Deliberately mirrors test_stream.py::test_stream_db_agent_token_rejected --
    that test proves the general guarantee; this one names it next to the new
    event so the suite documents the two together."""
    tok = client.env.mint("default", "worker", "agent")
    with pytest.raises(Exception):
        with client.websocket_connect("/v1/stream",
                                      headers={"Authorization": f"Bearer {tok}"}):
            pass

import json
import time

import httpx
import pytest
from starlette.websockets import WebSocketDisconnect


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
    event so the suite documents the two together. Concrete here (WebSocketDisconnect
    + the 4401 auth/role-failure close code from stream.py's run_stream), rather
    than a bare pytest.raises(Exception), so a future refactor that started
    accepting the connection couldn't silently pass by raising some OTHER
    exception during the session."""
    tok = client.env.mint("default", "worker", "agent")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/v1/stream",
                                      headers={"Authorization": f"Bearer {tok}"}):
            pass
    assert exc_info.value.code == 4401


class _BoomLoop:
    """Stands in for app.state.loop when the hop itself must fail (e.g. the
    real loop closed mid-shutdown)."""
    def call_soon_threadsafe(self, *a, **kw):
        raise RuntimeError("event loop is closed")


def test_exec_report_survives_publish_hop_failure(client, agent_headers, app_headers,
                                                   monkeypatch):
    """The exec_* write already committed by the time the notify hop runs -- a
    best-effort publish failure (no loop, loop closed) must never turn a landed
    write into a 500: the warden would treat 5xx as retryable, retry, and hit the
    write-once 409 for a report that in fact succeeded. Same guarded philosophy
    as outbox.py's own dispatch."""
    warden_headers = _warden_headers(client)
    rid = _approved_request(client, agent_headers, app_headers)
    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    monkeypatch.setattr(client.app_ref.state, "loop", _BoomLoop())

    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                    json={"mode": "exec_result", "exit_code": 0,
                          "ran": "x", "output": "y", "kind": "command"})
    assert r.status_code == 200

    row = client.db.get_request(rid)
    assert row["exec_exit_code"] == 0
    assert row["exec_ran"] == "x"


def test_publish_hop_failure_records_a_notify_failed_audit_row(client, agent_headers,
                                                                app_headers, monkeypatch):
    """0.7 S4 — parity with the notifier path (Dispatcher._guard): a dropped
    request.executed publish is visible in the audit log, not only in stderr."""
    warden_headers = _warden_headers(client)
    rid = _approved_request(client, agent_headers, app_headers)
    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    monkeypatch.setattr(client.app_ref.state, "loop", _BoomLoop())

    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                    json={"mode": "exec_result", "exit_code": 0,
                          "ran": "x", "output": "y", "kind": "command"})
    assert r.status_code == 200

    rows = [a for a in client.db.get_audit(rid) if a["event"] == "notify_failed"]
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["notifier"] == "stream"
    assert "event loop is closed" in detail["error"]
    assert len(detail["error"]) <= 200


def test_notify_failed_audit_write_failure_still_returns_200(client, agent_headers,
                                                              app_headers, monkeypatch):
    """The nested guard: even if the audit write itself explodes, the already
    committed exec_* write must not become a 500 — the warden treats 5xx as
    retryable and would hit the write-once 409 for a report that succeeded."""
    from arbiter.db import Database

    real_add_audit = Database.add_audit

    def _boom_on_notify_failed(self, request_id, event, detail=None):
        if event == "notify_failed":
            raise RuntimeError("audit down")
        return real_add_audit(self, request_id, event, detail)

    warden_headers = _warden_headers(client)
    rid = _approved_request(client, agent_headers, app_headers)
    assert client.post(f"/v1/requests/{rid}/consume",
                       headers=warden_headers).status_code == 200
    monkeypatch.setattr(client.app_ref.state, "loop", _BoomLoop())
    monkeypatch.setattr(Database, "add_audit", _boom_on_notify_failed)

    r = client.post(f"/v1/requests/{rid}/consume", headers=warden_headers,
                    json={"mode": "exec_result", "exit_code": 0,
                          "ran": "x", "output": "y", "kind": "command"})
    assert r.status_code == 200
    assert client.db.get_request(rid)["exec_exit_code"] == 0

"""ASGI app tests - the app object is driven directly; no server, no sockets,
no sleeps. The asgi_call helper below is the entire test transport."""
from __future__ import annotations

import asyncio
import json

import pytest

from hold_warden import api as api_module
from hold_warden.api import create_asgi_app
from hold_warden.arbiter import ArbiterUnavailable
from hold_warden.config import ParamValidationError, WardenConfig
from hold_warden.db import WardenDB
from hold_warden.service import UnknownActionError


def asgi_call(app, method, path, *, body=None, token=None):
    """Drive an ASGI 3 app with one request; returns (status, decoded JSON body)."""

    async def _run():
        raw = b"" if body is None else json.dumps(body).encode()
        headers = [(b"content-type", b"application/json")]
        if token is not None:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 8646),
        }
        state = {"body_sent": False}

        async def receive():
            if state["body_sent"]:
                return {"type": "http.disconnect"}
            state["body_sent"] = True
            return {"type": "http.request", "body": raw, "more_body": False}

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        status = next(m["status"] for m in sent
                      if m["type"] == "http.response.start")
        payload = b"".join(m.get("body", b"") for m in sent
                           if m["type"] == "http.response.body")
        return status, (json.loads(payload) if payload else None)

    return asyncio.run(_run())


class FakeOrch:
    """Duck-typed Orchestrator: real WardenDB, scripted propose()."""

    def __init__(self, db):
        self.db = db
        self.propose_calls: list[tuple] = []
        self.propose_result: dict | None = None
        self.propose_error: Exception | None = None

    def propose(self, agent, action, params, idempotency_key):
        self.propose_calls.append((agent, action, params, idempotency_key))
        if self.propose_error is not None:
            raise self.propose_error
        return self.propose_result


def make_cfg() -> WardenConfig:
    return WardenConfig(
        arbiter_url="http://127.0.0.1:9",
        arbiter_token_ref="env:HMA_WARDEN_TOKEN",
        arbiter_pubkey="deadbeef:QUFBQQ",
        warden_name="test-warden",
        bind="127.0.0.1", port=8646, retention_days=7,
        agents={"hermes": "env:WARDEN_TEST_HERMES",
                "other": "env:WARDEN_TEST_OTHER"},
        actions={}, secrets={})


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_TEST_HERMES", "hermes-token")
    monkeypatch.setenv("WARDEN_TEST_OTHER", "other-token")
    db = WardenDB(tmp_path / "warden.sqlite3")
    orch = FakeOrch(db)
    app = create_asgi_app(orch, make_cfg())
    return app, orch


# -------------------------------------------------------- health + auth

def test_health_ok_when_arbiter_reachable(app_env, monkeypatch):
    app, _ = app_env
    monkeypatch.setattr(api_module, "_arbiter_reachable", lambda url: True)
    assert asgi_call(app, "GET", "/health") == (200, {"ok": True})


def test_health_503_when_arbiter_unreachable(app_env, monkeypatch):
    app, _ = app_env
    monkeypatch.setattr(api_module, "_arbiter_reachable", lambda url: False)
    assert asgi_call(app, "GET", "/health") == (503, {"ok": False})


def test_health_probe_is_cached_for_60s(app_env, monkeypatch):
    app, _ = app_env
    probes = {"n": 0}

    def probe(url):
        probes["n"] += 1
        return True

    clock = {"now": 1000.0}
    monkeypatch.setattr(api_module, "_arbiter_reachable", probe)
    monkeypatch.setattr(api_module, "_now_monotonic", lambda: clock["now"])
    asgi_call(app, "GET", "/health")
    clock["now"] = 1030.0                       # 30s later: served from cache
    asgi_call(app, "GET", "/health")
    assert probes["n"] == 1
    clock["now"] = 1100.0                       # >60s since the probe: re-probed
    asgi_call(app, "GET", "/health")
    assert probes["n"] == 2


def test_missing_token_401(app_env):
    app, _ = app_env
    status, payload = asgi_call(app, "POST", "/v1/propose",
                                body={"action": "echo", "params": {}})
    assert status == 401
    assert payload == {"detail": "invalid or missing bearer token"}


def test_wrong_token_401(app_env):
    app, _ = app_env
    status, _ = asgi_call(app, "POST", "/v1/propose",
                          body={"action": "echo", "params": {}}, token="nope")
    assert status == 401


def test_unknown_route_404(app_env):
    app, _ = app_env
    status, payload = asgi_call(app, "GET", "/v1/nope", token="hermes-token")
    assert status == 404 and payload == {"detail": "not found"}


# ------------------------------------------------------------- propose

def _pending_row(pid="p-1", rid="req-1"):
    return {"id": pid, "request_id": rid, "status": "pending",
            "expires_at": "2026-07-06T00:05:00+00:00"}


def test_propose_201_shape(app_env):
    app, orch = app_env
    orch.propose_result = _pending_row()
    status, payload = asgi_call(app, "POST", "/v1/propose", token="hermes-token",
                                body={"action": "echo", "params": {},
                                      "idempotency_key": "k1"})
    assert status == 201
    assert payload == {"proposal_id": "p-1", "request_id": "req-1",
                       "status": "pending",
                       "expires_at": "2026-07-06T00:05:00+00:00"}
    assert orch.propose_calls == [("hermes", "echo", {}, "k1")]


def test_propose_unknown_action_404(app_env):
    app, orch = app_env
    orch.propose_error = UnknownActionError("unknown action: nope")
    status, payload = asgi_call(app, "POST", "/v1/propose", token="hermes-token",
                                body={"action": "nope", "params": {}})
    assert status == 404 and "unknown action" in payload["detail"]


def test_propose_param_validation_422(app_env):
    app, orch = app_env
    orch.propose_error = ParamValidationError("param 'word': not in enum")
    status, payload = asgi_call(app, "POST", "/v1/propose", token="hermes-token",
                                body={"action": "greet", "params": {"word": "zzz"}})
    assert status == 422 and "word" in payload["detail"]


def test_propose_arbiter_unavailable_502(app_env):
    app, orch = app_env
    orch.propose_error = ArbiterUnavailable("connect refused")
    status, payload = asgi_call(app, "POST", "/v1/propose", token="hermes-token",
                                body={"action": "echo", "params": {}})
    assert status == 502 and payload == {"detail": "arbiter unreachable"}


def test_propose_malformed_body_422(app_env):
    app, orch = app_env
    orch.propose_result = _pending_row()
    for bad in [None, {"params": {}}, {"action": "", "params": {}},
                {"action": "echo", "params": {"k": 1}},
                {"action": "echo", "params": {}, "idempotency_key": "x" * 129}]:
        status, _ = asgi_call(app, "POST", "/v1/propose",
                              token="hermes-token", body=bad)
        assert status == 422, bad

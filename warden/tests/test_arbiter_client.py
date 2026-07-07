"""hold_warden.arbiter — warden->arbiter HTTP client, tested against a local
threaded http.server stub (loopback only; no real arbiter, no FastAPI)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hold_warden.arbiter import (
    ArbiterAuthError,
    ArbiterClient,
    ArbiterConflict,
    ArbiterStale,
    ArbiterUnavailable,
)


class _Stub(BaseHTTPRequestHandler):
    """Scriptable arbiter. Tests set routes[(method, path)] = (status, body_dict)
    and inspect captured requests in seen."""

    routes: dict[tuple[str, str], tuple[int, dict]] = {}
    seen: list[dict] = []

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        _Stub.seen.append({
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": json.loads(raw) if raw else None,
        })
        status, body = _Stub.routes.get((self.command, self.path), (404, {"detail": "not found"}))
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *args) -> None:  # silence per-request stderr noise
        pass


@pytest.fixture()
def stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Stub.routes = {}
    _Stub.seen = []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


CREATE_KWARGS = dict(
    title="Restart nginx",
    description="Restart a systemd unit on hermes",
    action_type="warden.restart_service",
    severity="high",
    ttl_seconds=300,
    payload={"unit": "nginx"},
    canonical_action='{"action":"restart_service","v":1}',
    action_hash="ab" * 32,
    idempotency_key="idem-1",
)


def test_create_request_posts_full_body_with_bearer(stub):
    _Stub.routes[("POST", "/v1/requests")] = (201, {"id": "rid-1", "status": "pending"})
    client = ArbiterClient(stub, "tok-warden-1")
    out = client.create_request(**CREATE_KWARGS)
    assert out == {"id": "rid-1", "status": "pending"}
    sent = _Stub.seen[-1]
    assert sent["headers"]["authorization"] == "Bearer tok-warden-1"
    assert sent["body"] == CREATE_KWARGS


def test_create_request_accepts_200_idempotent_replay(stub):
    # Idempotency replay returns 200 + the existing row (not 201) — still success.
    _Stub.routes[("POST", "/v1/requests")] = (200, {"id": "rid-1", "status": "pending"})
    assert ArbiterClient(stub, "t").create_request(**CREATE_KWARGS)["id"] == "rid-1"


def test_get_request(stub):
    _Stub.routes[("GET", "/v1/requests/rid-1")] = (200, {"id": "rid-1", "status": "approved"})
    assert ArbiterClient(stub, "t").get_request("rid-1")["status"] == "approved"


def test_get_verdict_returns_jws_string(stub):
    _Stub.routes[("GET", "/v1/requests/rid-1/verdict")] = (
        200, {"verdict": "eyJ.header.sig", "kid": "abcd1234"})
    assert ArbiterClient(stub, "t").get_verdict("rid-1") == "eyJ.header.sig"


def test_consume_returns_none_on_200(stub):
    _Stub.routes[("POST", "/v1/requests/rid-1/consume")] = (
        200, {"consumed_at": "2026-07-06T00:00:00+00:00"})
    assert ArbiterClient(stub, "t").consume("rid-1") is None
    assert _Stub.seen[-1]["path"] == "/v1/requests/rid-1/consume"


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_raise_arbiter_auth_error(stub, status):
    _Stub.routes[("GET", "/v1/requests/rid-1")] = (status, {"detail": "bad token"})
    with pytest.raises(ArbiterAuthError):
        ArbiterClient(stub, "t").get_request("rid-1")


@pytest.mark.parametrize("status", [500, 502, 503])
def test_5xx_raises_arbiter_unavailable(stub, status):
    _Stub.routes[("POST", "/v1/requests")] = (status, {"detail": "boom"})
    with pytest.raises(ArbiterUnavailable):
        ArbiterClient(stub, "t").create_request(**CREATE_KWARGS)


def test_connection_refused_raises_arbiter_unavailable():
    client = ArbiterClient("http://127.0.0.1:1", "t")  # nothing listens on port 1
    with pytest.raises(ArbiterUnavailable):
        client.get_request("rid-1")


def test_consume_409_raises_conflict(stub):
    _Stub.routes[("POST", "/v1/requests/rid-1/consume")] = (409, {"detail": "already consumed"})
    with pytest.raises(ArbiterConflict):
        ArbiterClient(stub, "t").consume("rid-1")


def test_consume_410_raises_stale(stub):
    _Stub.routes[("POST", "/v1/requests/rid-1/consume")] = (410, {"detail": "approval stale"})
    with pytest.raises(ArbiterStale):
        ArbiterClient(stub, "t").consume("rid-1")


def test_get_verdict_404_no_verdict_yet_is_retryable(stub):
    # 404 = "no verdict yet" while pending -> ArbiterUnavailable, which the
    # orchestrator treats as keep-polling-until-expires_at (spec fail-closed table).
    _Stub.routes[("GET", "/v1/requests/rid-1/verdict")] = (404, {"detail": "no verdict yet"})
    with pytest.raises(ArbiterUnavailable):
        ArbiterClient(stub, "t").get_verdict("rid-1")


def test_create_422_raises_unavailable_with_status_in_message(stub):
    _Stub.routes[("POST", "/v1/requests")] = (422, {"detail": "canonical hash mismatch"})
    with pytest.raises(ArbiterUnavailable, match="422"):
        ArbiterClient(stub, "t").create_request(**CREATE_KWARGS)


def test_verdict_response_missing_key_raises_unavailable(stub):
    _Stub.routes[("GET", "/v1/requests/rid-1/verdict")] = (200, {"kid": "abcd1234"})
    with pytest.raises(ArbiterUnavailable):
        ArbiterClient(stub, "t").get_verdict("rid-1")

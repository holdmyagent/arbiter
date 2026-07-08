import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

from arbiter.stream import run_stream
from tests._stream_fakes import FakeCell, FakeRegistry, make_resolve


def _build_app():
    app = FastAPI()
    cell = FakeCell("default")
    app.state.registry = FakeRegistry({"default": cell})
    app.state.control = None
    app.state._cell = cell  # test handle
    resolve = make_resolve({"app-tok": "default"})

    @app.websocket("/v1/stream")
    async def stream(ws: WebSocket):
        await run_stream(ws, ws.app.state.registry, ws.app.state.control,
                         resolve=resolve, heartbeat=1e9, send_timeout=5.0)
    return app


def test_endpoint_delegates_to_run_stream_and_keeps_wire_format():
    app = _build_app()
    with TestClient(app) as c:
        with c.websocket_connect(
                "/v1/stream", headers={"Authorization": "Bearer app-tok"}) as ws:
            app.state._cell.hub.publish(
                {"event": "request.created", "request": {"id": "r1"}})
            evt = ws.receive_json()
            assert evt == {"event": "request.created", "request": {"id": "r1"}}


def test_endpoint_rejects_unknown_bearer_before_accept():
    app = _build_app()
    with TestClient(app) as c:
        with pytest.raises(Exception):
            with c.websocket_connect(
                    "/v1/stream", headers={"Authorization": "Bearer nope"}):
                pass

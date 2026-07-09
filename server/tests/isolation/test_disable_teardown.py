"""§16 gate: disable/revoke tears down live sessions on a hot, busy cell —
the open socket is actively closed (not just left to rot) AND the very next
HTTP request 403s immediately (§15.5/§8).

`control.disable_tenant` only flips the `disabled_at` flag in control.db — it
has no reference to the registry or any live cell's Hub (control.py is a leaf
module, deliberately registry-agnostic). The active-teardown half of the
invariant is wired in `arbiter.stream.run_stream`'s heartbeat loop: each open
/v1/stream session re-checks `control.is_disabled(cell.tenant_id)` (never
cached) on every heartbeat tick and, the first time any session on the cell
notices, calls `cell.hub.close()` — which pushes the CLOSE sentinel to every
subscriber of that hub, tearing down ALL of the tenant's live sessions, not
just the one that happened to notice.

This test builds its own app instance (mirroring the `two_tenant` fixture's
construction exactly) with a short `ws_heartbeat` so the recheck fires well
inside the test's time budget instead of the default 30s.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.isolation.conftest import (ControlPlane, TenantRegistry, create_app,
                                      FakeSender, TwoTenant, _provision)

HEARTBEAT = 0.05  # short recheck interval so disable teardown fires in-test


def _next_event(ws):
    """Return the next real stream frame, skipping heartbeat pings.

    run_stream emits a `{"event": "ping"}` keepalive every heartbeat tick, so
    with a 0.05s heartbeat a ping can land in the socket between real frames.
    A test that reads exactly one frame is racy; drain pings and return the
    first non-ping frame instead."""
    while True:
        frame = ws.receive_json()
        if frame.get("event") != "ping":
            return frame


def _fast_two_tenant(cfg, tmp_path) -> TwoTenant:
    """Same construction as the shared `two_tenant` fixture (conftest.py), but
    with a short ws_heartbeat — the default 30s would make this test hang."""
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    sender = FakeSender()
    registry = TenantRegistry(control, cfg=cfg, sender=sender)
    handles = _provision(control, registry, root)
    app = create_app(cfg, registry, control, sender=sender, ws_heartbeat=HEARTBEAT)
    client = TestClient(app)
    client.__enter__()
    return TwoTenant(root=root, control=control, registry=registry, app=app,
                     client=client, sender=sender, tenants=handles)


def test_disable_closes_live_stream_and_403s_next_request(cfg, tmp_path):
    tt = _fast_two_tenant(cfg, tmp_path)
    try:
        a = tt.tenants["alice"]
        with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws:
            # BASELINE: the socket is live (an event flows)
            rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                                 json={"title": "live"}).json()["id"]
            assert _next_event(ws)["request"]["id"] == rid
            # disable alice on a HOT, busy cell (it is pinned by the open socket)
            tt.control.disable_tenant("alice")
            # The open socket is actively torn down (close sentinel on the hub).
            # Once disabled, the heartbeat stops queueing pings and closes instead,
            # so any pings already queued drain in a bounded number of reads before
            # the disconnect arrives; exhausting the bound means teardown never fired.
            with pytest.raises(WebSocketDisconnect):
                for _ in range(200):
                    frame = ws.receive_json()
                    assert frame.get("event") == "ping", \
                        f"unexpected non-ping frame after disable: {frame}"
        # the very next HTTP request on alice 403s immediately (disabled read on resolve)
        r = tt.client.post("/v1/requests", headers=a.agent_hdr, json={"title": "after"})
        assert r.status_code == 403
        # bob is unaffected — disable is per-tenant
        b = tt.tenants["bob"]
        assert tt.client.post("/v1/requests", headers=b.agent_hdr,
                              json={"title": "ok"}).status_code == 200
    finally:
        tt.client.__exit__(None, None, None)

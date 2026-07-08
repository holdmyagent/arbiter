import pytest
from starlette.websockets import WebSocketDisconnect


def test_ws_bearer_binds_to_own_cell(two_tenant):
    tt = two_tenant
    a = tt.tenants["alice"]
    with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws:
        rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                             json={"title": "hi"}).json()["id"]
        assert ws.receive_json()["request"]["id"] == rid


def test_ws_unrouted_bearer_rejected_before_accept(two_tenant):
    tt = two_tenant
    # a bearer that routes to NO cell: never minted, no control route
    bogus = {"Authorization": "Bearer hma_app_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
    with pytest.raises(WebSocketDisconnect) as ei:
        with tt.client.websocket_connect("/v1/stream", headers=bogus):
            pass
    # generic policy close (not a 1000 normal-close after accept)
    assert ei.value.code == 4401

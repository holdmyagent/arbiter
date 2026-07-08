import pytest
from starlette.websockets import WebSocketDisconnect

from tests.isolation.conftest import (ControlPlane, TenantRegistry, create_app,
                                      mint_into_cell, bearer_hdr)
from fastapi.testclient import TestClient


def _one_tenant_low_cap(cfg, tmp_path, cap=2):
    root = tmp_path / "fleet"; root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, stream_cap=cap, cfg=cfg, sender=None)
    d = root / "alice"; d.mkdir(parents=True)
    epoch = control.create_tenant("alice", d)
    app_b = mint_into_cell(control, registry, "alice", epoch, "alice-app", "app")
    app = create_app(cfg, registry, control, sender=None)
    return TestClient(app), bearer_hdr(app_b)


def test_per_tenant_stream_cap_sheds_the_overflow_socket(cfg, tmp_path):
    client, hdr = _one_tenant_low_cap(cfg, tmp_path, cap=2)
    with client:
        import contextlib
        with contextlib.ExitStack() as stack:
            # cap=2: two sockets accepted
            stack.enter_context(client.websocket_connect("/v1/stream", headers=hdr))
            stack.enter_context(client.websocket_connect("/v1/stream", headers=hdr))
            # the third is shed at handshake (over the per-tenant cap)
            with pytest.raises(WebSocketDisconnect) as ei:
                with client.websocket_connect("/v1/stream", headers=hdr):
                    pass
            assert ei.value.code == 4429  # generic "too many streams" policy close

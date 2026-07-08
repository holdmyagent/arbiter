import asyncio
import logging
import pytest
from pathlib import Path


def test_create_and_list_scoped_to_caller_cell(client):
    env = client.env
    env.provision("b"); env.provision("a")
    atok = env.mint("a", "agentA", "agent")
    btok = env.mint("b", "agentB", "agent")
    aapp = env.mint("a", "appA", "app")
    bapp = env.mint("b", "appB", "app")
    ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                     json={"title": "for-A"})
    rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                     json={"title": "for-B"})
    assert ra.status_code == 200 and rb.status_code == 200
    # A's app sees ONLY A's request; B's app sees ONLY B's
    la = client.get("/v1/requests", headers={"Authorization": f"Bearer {aapp}"}).json()
    lb = client.get("/v1/requests", headers={"Authorization": f"Bearer {bapp}"}).json()
    assert [r["title"] for r in la] == ["for-A"]
    assert [r["title"] for r in lb] == ["for-B"]


def test_create_rate_limit_is_per_cell(client, cfg):
    # B's agent burst must NEVER throttle A's agent (§13 — separate buckets)
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agent", "agent")     # SAME name in both cells
    btok = env.mint("b", "agent", "agent")
    # drive B's 'agent' bucket to the limit
    for _ in range(cfg.policy.rate_limit_per_minute + 2):
        client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                    json={"title": "x", "idempotency_key": None})
    rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"}, json={"title": "y"})
    ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"}, json={"title": "z"})
    assert rb.status_code == 429
    assert ra.status_code == 200            # A untouched


@pytest.mark.asyncio
async def test_spawn_publish_logs_and_swallows_epoch_changed(caplog):
    """Test that _spawn_publish wraps and logs exceptions (e.g., EpochChanged)
    instead of letting them surface as unhandled task exceptions."""
    from arbiter.app import _spawn_publish
    from arbiter.config import Config
    from arbiter.registry import TenantRegistry
    from arbiter.control import ControlPlane
    from arbiter.db import Database
    from arbiter.apns import APNsSender
    from types import SimpleNamespace
    import tempfile
    
    caplog.set_level(logging.WARNING, logger="arbiter.app")
    
    # Create a minimal app for testing
    with tempfile.TemporaryDirectory() as tmp_path:
        tmp_path = Path(tmp_path)
        cfg = Config.load("")  # default config
        cfg.auth.agent_token = "test-agent"
        cfg.auth.app_token = "test-app"
        cfg.auth.admin_password = "test-admin"
        cfg.auth.session_secret = "test-secret"
        cfg.server.db_path = str(tmp_path / "t.sqlite3")
        
        control = ControlPlane.open(str(tmp_path / "control"), str(tmp_path / "cells"))
        registry = TenantRegistry(control, cfg=cfg, sender=APNsSender(cfg))
        
        # Provision a tenant using the same method as conftest
        cell_dir = tmp_path / "cells" / "test"
        cell_dir.mkdir(parents=True, exist_ok=True)
        epoch = control.create_tenant("test", str(cell_dir))
        db = Database(str(cell_dir / "arbiter.sqlite3"))
        
        app = SimpleNamespace()
        app.state = SimpleNamespace(
            registry=registry,
            control=control,
            cfg=cfg,
            notify_tasks=set()
        )
        
        # Get the actual epoch
        actual_epoch = control.epoch_of("test")
        assert actual_epoch is not None, "Tenant should be provisioned"
        
        # Use a bogus epoch (current + 1000) that will cause EpochChanged
        bogus_epoch = actual_epoch + 1000
        
        # Spawn a publish task with the bogus epoch
        req = {"id": "req-123", "title": "test"}
        task = _spawn_publish(app, "test", bogus_epoch, "request.created", req)
        
        # Let the task run by yielding to the event loop
        # The task should complete quickly with an exception that gets logged
        await asyncio.sleep(0.1)
        
        # Verify the task completed
        assert task.done(), f"Task should be done but state is: {task._state}"
        
        # Task should not have raised an exception (it was caught and logged)
        try:
            task.result()
        except Exception as e:
            pytest.fail(f"Task raised unhandled exception: {e}")
        
        # Check that the warning was logged
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any("background publish failed" in r.message for r in warnings), \
            f"Expected 'background publish failed' warning, got warnings: {[r.message for r in warnings]}"

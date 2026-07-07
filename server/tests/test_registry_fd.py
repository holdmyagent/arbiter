import resource

import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry, CapacityExceeded


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    return control, TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)


def test_startup_rejects_impossible_fd_budget(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    with pytest.raises(ValueError):
        # max_hot_cells*3 + headroom always dwarfs the ambient RLIMIT_NOFILE,
        # whatever it is on this machine/CI (some hosts raise it well past 1024).
        TenantRegistry(control, max_hot_cells=soft, cfg=cfg, sender=_DummySender())


def test_default_budget_is_valid(tmp_path):
    control, reg = _reg(tmp_path)   # 64*3 + 150 = 342 < 1024 -> constructs fine
    assert reg.max_hot_cells == 64 and reg.stream_cap == 5


@pytest.mark.asyncio
async def test_runtime_shed_rather_than_open_over_budget(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=64)
    # Force a tiny runtime budget: 1 open cell (3 FDs) + headroom already at the edge
    reg._soft_rlimit = 3
    reg._headroom = 0
    ea = control.create_tenant("a", tmp_path / "a")
    with pytest.raises(CapacityExceeded):     # (0+1)*3 + 0 >= 3 -> shed
        await reg.acquire("a", ea)
    assert "a" not in reg._map                # sentinel cleaned up, nothing half-open


@pytest.mark.asyncio
async def test_stream_slots_capped_per_tenant(tmp_path):
    control, reg = _reg(tmp_path, stream_cap=2)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    try:
        assert reg.acquire_stream_slot("a") is True
        assert reg.acquire_stream_slot("a") is True
        assert reg.acquire_stream_slot("a") is False   # over the per-tenant cap
        reg.release_stream_slot("a")
        assert reg.acquire_stream_slot("a") is True     # slot freed
    finally:
        for _ in range(reg._stream_slots.get("a", 0)):
            reg.release_stream_slot("a")
        reg.release(cell)


@pytest.mark.asyncio
async def test_stream_slot_sheds_when_over_fd_budget(tmp_path):
    control, reg = _reg(tmp_path, stream_cap=5)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    try:
        reg._soft_rlimit = 4     # 1 cell = 3 FDs; one more stream FD hits the edge
        reg._headroom = 0
        assert reg.acquire_stream_slot("a") is False    # 3 + 1 >= 4 -> shed (no cross-tenant DoS)
    finally:
        reg.release(cell)

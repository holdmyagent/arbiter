import asyncio
import sqlite3
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    reg = TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)
    return control, reg


async def _acquire_release(reg, control, tmp_path, name):
    epoch = control.create_tenant(name, tmp_path / name)
    cell = await reg.acquire(name, epoch)
    reg.release(cell)
    return cell


@pytest.mark.asyncio
async def test_lru_evicts_idle_cell_over_cap(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=2, clock=lambda: _acquire_release.t)
    _acquire_release.t = 0
    a = await _acquire_release(reg, control, tmp_path, "a"); _acquire_release.t = 1
    b = await _acquire_release(reg, control, tmp_path, "b"); _acquire_release.t = 2
    # opening c over cap -> LRU (a) evicted; its connection is closed
    c = await _acquire_release(reg, control, tmp_path, "c")
    assert "a" not in reg._map and "b" in reg._map and "c" in reg._map
    with pytest.raises(sqlite3.ProgrammingError):
        a.db.ping()      # a's connection was checkpoint_and_close'd


@pytest.mark.asyncio
async def test_never_evicts_a_pinned_cell(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=1)
    ea = control.create_tenant("a", tmp_path / "a")
    pinned = await reg.acquire("a", ea)          # a stays pinned
    try:
        eb = control.create_tenant("b", tmp_path / "b")
        cb = await reg.acquire("b", eb)          # over cap, but a is pinned -> keep both
        try:
            assert "a" in reg._map and "b" in reg._map   # temporarily over-cap
            pinned.db.ping()                              # a's connection still alive
        finally:
            reg.release(cb)
    finally:
        reg.release(pinned)


@pytest.mark.asyncio
async def test_evict_idle_sweep_returns_count(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=64)
    for n in ("a", "b"):
        await _acquire_release(reg, control, tmp_path, n)
    # everything idle; explicit maintenance sweep down to <= cap is a no-op here
    assert await reg.evict_idle() == 0
    # force it: shrink cap then sweep
    reg.max_hot_cells = 1
    assert await reg.evict_idle() == 1
    assert len([k for k, v in reg._map.items()]) == 1

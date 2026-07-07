import asyncio
import threading
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
    return control, TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)


@pytest.mark.asyncio
async def test_open_does_not_hold_db_rlock_of_another_cell(tmp_path):
    # Hold cell A's DB RLock in a background OS thread (inner lock). Opening cell B
    # must still succeed: the registry never takes a cell's DB RLock across a
    # cell open, so B's open cannot be blocked by A's held inner lock.
    control, reg = _reg(tmp_path)
    ea = control.create_tenant("a", tmp_path / "a")
    a = await reg.acquire("a", ea)
    try:
        held = threading.Event()
        release = threading.Event()

        def hog():
            with a.db._lock:
                held.set()
                release.wait(2.0)

        t = threading.Thread(target=hog); t.start()
        assert held.wait(1.0)
        eb = control.create_tenant("b", tmp_path / "b")
        b = await asyncio.wait_for(reg.acquire("b", eb), timeout=2.0)  # not blocked
        reg.release(b)
        release.set(); t.join()
    finally:
        reg.release(a)


@pytest.mark.asyncio
async def test_map_lock_is_timeout_bounded(tmp_path):
    # A stuck holder of the OUTER map lock degrades ONE call (TimeoutError) rather
    # than hanging the process forever.
    control, reg = _reg(tmp_path, lock_timeout=0.2)
    await reg._map_lock.acquire()          # simulate a stuck holder
    try:
        ea = control.create_tenant("a", tmp_path / "a")
        with pytest.raises(asyncio.TimeoutError):
            await reg.acquire("a", ea)
    finally:
        reg._map_lock.release()


@pytest.mark.asyncio
async def test_release_takes_no_async_lock(tmp_path):
    # release must be safe from a finally even while the map lock is held elsewhere
    # (it is a pure synchronous int decrement, no await, no lock).
    control, reg = _reg(tmp_path)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    await reg._map_lock.acquire()          # map lock held by "someone else"
    try:
        reg.release(cell)                  # still works -> no deadlock
        assert reg._map["a"].refcount == 0
    finally:
        reg._map_lock.release()

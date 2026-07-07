import asyncio
import threading
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.db import Database
from arbiter.registry import TenantRegistry


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane.open(tmp_path / "control", tmp_path)
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
                release.wait(5.0)  # strictly longer than acquire's 2.0s wait_for below

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
async def test_checkpoint_never_runs_under_map_lock(tmp_path, monkeypatch):
    # checkpoint_and_close is a blocking DB call; the registry must run it AFTER
    # releasing the outer map lock, never across it (else one tenant's checkpoint
    # would stall every other tenant's acquire/release). Driven from a single task
    # with no other concurrency, so a True reading of _map_lock.locked() at probe
    # time can only mean the eviction path itself held the lock across the
    # checkpoint call -- not a coincidental concurrent acquirer. Covers both
    # eviction paths: acquire()'s over-cap eviction and the explicit evict_idle()
    # maintenance sweep.
    calls = []
    orig = Database.checkpoint_and_close

    def probe(self):
        calls.append(reg._map_lock.locked())
        return orig(self)

    monkeypatch.setattr(Database, "checkpoint_and_close", probe)

    # Path 1: acquire()-triggered eviction (opening b over cap evicts idle a).
    control, reg = _reg(tmp_path, max_hot_cells=1)
    ea = control.create_tenant("a", tmp_path / "a")
    a = await reg.acquire("a", ea)
    reg.release(a)  # idle: refcount 0, eligible for eviction

    eb = control.create_tenant("b", tmp_path / "b")
    b = await reg.acquire("b", eb)  # over cap -> evicts a -> checkpoint_and_close(a)
    reg.release(b)

    assert len(calls) >= 1
    assert all(held is False for held in calls)

    # Path 2: explicit evict_idle() maintenance sweep.
    calls.clear()
    reg.max_hot_cells = 0
    evicted = await reg.evict_idle()  # evicts idle b -> checkpoint_and_close(b)

    assert evicted >= 1
    assert len(calls) >= 1
    assert all(held is False for held in calls)


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

import asyncio

from tests.isolation.conftest import ControlPlane, TenantRegistry


def _reg(cfg, tmp_path):
    root = tmp_path / "fleet"; root.mkdir()
    control = ControlPlane.open(root / "control", root)
    d = root / "t"; d.mkdir(parents=True)
    epoch = control.create_tenant("t", d)
    return TenantRegistry(control, cfg=cfg, sender=None), "t", epoch


def test_refcount_returns_to_baseline_on_every_exit_path(cfg, tmp_path):
    registry, tid, epoch = _reg(cfg, tmp_path)

    async def run():
        # normal acquire/release round-trip
        cell = await registry.acquire(tid, epoch)
        assert registry.refcount(cell) == 1
        registry.release(cell)
        assert registry.refcount(cell) == 0

        # context manager releases exactly once even on an exception path
        try:
            async with registry.hold(tid, epoch) as c2:
                assert registry.refcount(c2) == 1
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert registry.refcount(c2) == 0

        # a live holder pins across a concurrent eviction attempt: no use-after-free
        held = await registry.acquire(tid, epoch)
        await registry.try_evict_idle()          # must skip: refcount>0
        assert held.db.conn.execute("SELECT 1").fetchone()[0] == 1  # connection still open
        registry.release(held)

    asyncio.run(run())


def test_reopened_twin_never_substituted_under_live_holder(cfg, tmp_path):
    registry, tid, epoch = _reg(cfg, tmp_path)

    async def run():
        held = await registry.acquire(tid, epoch)
        # force churn: an acquire while held must return the SAME object, not a twin
        again = await registry.acquire(tid, epoch)
        assert again is held
        registry.release(again)
        registry.release(held)

    asyncio.run(run())

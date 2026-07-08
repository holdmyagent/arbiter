import asyncio

from tests.isolation.conftest import ControlPlane, TenantRegistry
from arbiter.db import SCHEMA_VERSION


def _build(cfg, tmp_path):
    root = tmp_path / "fleet"; root.mkdir()
    control = ControlPlane.open(root / "control", root)
    d = root / "solo"; d.mkdir(parents=True)
    epoch = control.create_tenant("solo", d)
    return TenantRegistry(control, cfg=cfg, sender=None), "solo", epoch


def test_k_concurrent_acquires_yield_one_database(cfg, tmp_path):
    registry, tid, epoch = _build(cfg, tmp_path)
    K = 32

    async def run():
        cells = await asyncio.gather(*[registry.acquire(tid, epoch) for _ in range(K)])
        try:
            first = cells[0]
            # identical Cell object, identical connection, identical RLock:
            assert all(c is first for c in cells), "single-flight returned twin cells"
            assert all(c.db.conn is first.db.conn for c in cells), "two connections on one dir"
            assert all(c.db._lock is first.db._lock for c in cells), "two RLocks on one dir"
            # fully migrated before it was ever observable:
            v = first.db.conn.execute("PRAGMA user_version").fetchone()[0]
            assert v == SCHEMA_VERSION
        finally:
            for c in cells:
                registry.release(c)

    asyncio.run(run())

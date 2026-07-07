import asyncio
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry, EpochChanged
from arbiter.db import Database


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    reg = TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)
    return control, reg


@pytest.mark.asyncio
async def test_single_flight_one_database_under_k_concurrency(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    # Serialize open_cell entry so K coroutines genuinely race the sentinel.
    import arbiter.registry as R
    opens = []
    real = R.open_cell

    def counting_open(*a, **k):
        opens.append(1)
        return real(*a, **k)

    R.open_cell = counting_open
    try:
        cells = await asyncio.gather(*[reg.acquire("acme", epoch) for _ in range(16)])
    finally:
        R.open_cell = real
    # exactly ONE open_cell -> one Database/connection/RLock; every caller got the SAME object
    assert len(opens) == 1
    first = cells[0]
    assert all(c is first for c in cells)
    assert isinstance(first.db, Database)
    # 16 pins outstanding
    assert reg._map["acme"].refcount == 16
    for _ in cells:
        reg.release(first)
    assert reg._map["acme"].refcount == 0


@pytest.mark.asyncio
async def test_never_observes_half_migrated_cell(tmp_path):
    from arbiter.db import SCHEMA_VERSION
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    cell = await reg.acquire("acme", epoch)
    try:
        assert cell.db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        reg.release(cell)


@pytest.mark.asyncio
async def test_release_is_by_object(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    cell = await reg.acquire("acme", epoch)

    class Twin:
        tenant_id = "acme"
    with pytest.raises(RuntimeError):
        reg.release(Twin())        # not the pinned object -> refuse
    reg.release(cell)
    with pytest.raises(RuntimeError):
        reg.release(cell)          # underflow -> refuse (exactly-once)


@pytest.mark.asyncio
async def test_hold_releases_on_normal_and_exception(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    async with reg.hold("acme", epoch) as cell:
        assert reg._map["acme"].refcount == 1
    assert reg._map["acme"].refcount == 0
    with pytest.raises(ValueError):
        async with reg.hold("acme", epoch):
            assert reg._map["acme"].refcount == 1
            raise ValueError("boom")
    assert reg._map["acme"].refcount == 0     # released despite the exception


@pytest.mark.asyncio
async def test_background_task_keeps_cell_pinned(tmp_path):
    # A spawned background task pins the cell for its whole lifetime; the pin is
    # not released until the task's finally runs.
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    gate = asyncio.Event()

    async def bg():
        async with reg.hold("acme", epoch):
            await gate.wait()

    t = asyncio.create_task(bg())
    await asyncio.sleep(0.05)
    assert reg._map["acme"].refcount == 1     # still pinned by the background task
    gate.set()
    await t
    assert reg._map["acme"].refcount == 0


@pytest.mark.asyncio
async def test_epoch_mismatch_on_live_holder_fails_closed(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    held = await reg.acquire("acme", epoch)     # pin at current epoch
    try:
        with pytest.raises(EpochChanged):
            await reg.acquire("acme", epoch + 1)  # delete+recreate raced a live holder
    finally:
        reg.release(held)

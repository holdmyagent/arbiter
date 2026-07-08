import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from arbiter.db import Database
from arbiter.notify.outbox import drain_all_at_startup


def _iso(dt):
    return dt.isoformat()


class CountingDispatcher:
    def __init__(self):
        self.fires = 0

    async def request_created(self, req):
        self.fires += 1

    async def request_decided(self, req):
        self.fires += 1


class FakeCell:
    def __init__(self, tenant_id, epoch, db, dispatcher):
        self.tenant_id, self.epoch, self.db, self.dispatcher = tenant_id, epoch, db, dispatcher


class FakeRegistry:
    def __init__(self, cells):
        self._cells = cells
        self.holds = 0

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        self.holds += 1
        yield self._cells[tenant_id]


class FakeControl:
    def __init__(self, tenants):
        self._tenants = tenants   # list of (tenant_id, epoch)

    def list_tenants(self):
        # Real ControlPlane.list_tenants() returns dicts keyed by
        # tenant_id/epoch (see arbiter/control.py) — match that shape here.
        return [{"tenant_id": tid, "epoch": epoch} for tid, epoch in self._tenants]


def _cell_with_pending(tid):
    db = Database(":memory:")
    exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=300))
    req = {"id": f"{tid}-r1", "title": "x", "severity": "high",
           "status": "approved", "expires_at": exp, "callback_url": None}
    db.outbox_add(req["id"], "request.decided", req, exp)
    return FakeCell(tid, 1, db, CountingDispatcher())


def test_startup_drain_delivers_each_tenants_pending_once():
    cells = {"a": _cell_with_pending("a"), "b": _cell_with_pending("b")}
    reg = FakeRegistry(cells)
    ctrl = FakeControl([("a", 1), ("b", 1)])
    asyncio.run(drain_all_at_startup(reg, ctrl))
    assert cells["a"].dispatcher.fires == 1
    assert cells["b"].dispatcher.fires == 1
    assert cells["a"].db.outbox_pending() == []
    assert cells["b"].db.outbox_pending() == []


def test_merely_holding_a_cell_does_not_drain():
    # The invariant: acquiring/holding a cell fires NOTHING. Only the explicit
    # process-startup coordinator drains. (No drain hook on cell open.)
    cell = _cell_with_pending("a")
    reg = FakeRegistry({"a": cell})

    async def hold_without_draining():
        async with reg.hold("a", 1):
            pass

    asyncio.run(hold_without_draining())
    assert cell.dispatcher.fires == 0            # cell-open never drains
    assert len(cell.db.outbox_pending()) == 1    # row untouched


class FailingRegistry:
    """Registry that raises on hold for a specific tenant."""
    def __init__(self, cells, fail_on_tenant):
        self._cells = cells
        self._fail_on_tenant = fail_on_tenant

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        if tenant_id == self._fail_on_tenant:
            raise RuntimeError(f"simulated drain failure for tenant {tenant_id}")
        yield self._cells[tenant_id]


def test_startup_drain_isolates_per_tenant_failures(caplog):
    # One tenant's drain failure (or hold failure) must NOT abort the entire
    # startup, per design principle §5/§15.13 "shed one tenant, never the fleet".
    # Assert: (a) exception does NOT propagate, (b) good tenant still drains,
    # (c) warning logged for bad tenant.
    import logging
    caplog.set_level(logging.WARNING, logger="arbiter.outbox")

    cells = {"bad": _cell_with_pending("bad"), "good": _cell_with_pending("good")}
    reg = FailingRegistry(cells, "bad")
    ctrl = FakeControl([("bad", 1), ("good", 1)])

    # Should NOT raise — exception is caught and logged.
    asyncio.run(drain_all_at_startup(reg, ctrl))

    # Good tenant's pending was drained (dispatcher fired once, row deleted).
    assert cells["good"].dispatcher.fires == 1
    assert cells["good"].db.outbox_pending() == []

    # Bad tenant's drain was never attempted (registry.hold raised), so it has
    # no dispatcher fires, but that's OK — the point is the fleet booted.
    assert cells["bad"].dispatcher.fires == 0

    # Warning logged for bad tenant.
    assert any("startup drain failed for tenant bad" in record.message
               for record in caplog.records)

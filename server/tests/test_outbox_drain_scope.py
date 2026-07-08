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

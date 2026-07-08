import asyncio
from datetime import datetime, timedelta, timezone

from arbiter.db import Database
from arbiter.notify.outbox import Outbox


def _iso(dt):
    return dt.isoformat()


REQ = {"id": "r1", "title": "Deploy", "severity": "high", "status": "approved",
       "expires_at": _iso(datetime.now(timezone.utc) + timedelta(seconds=300)),
       "callback_url": None}


class CountingDispatcher:
    def __init__(self):
        self.fires = 0

    async def request_created(self, req):
        self.fires += 1

    async def request_decided(self, req):
        self.fires += 1


def test_crash_between_dispatch_and_delete_then_redrain_fires_once():
    # One cell db shared across the "crash" and the "restart drain" — this is
    # what a cell reopened after churn sees: the persisted notify_sent marker.
    db = Database(":memory:")
    disp = CountingDispatcher()
    ob = Outbox(db, disp, sleeps=())

    # First delivery succeeds (fires once) but we simulate a crash BEFORE the
    # outbox row is deleted: enqueue + dispatch manually, skip the delete.
    oid = db.outbox_add(REQ["id"], "request.decided", REQ, REQ["expires_at"])
    assert db.notify_reserve(REQ["id"], "request.decided") is True
    asyncio.run(disp.request_decided(REQ))   # the one real fire
    assert disp.fires == 1
    # crash: outbox row still present, marker present, cell churns/reopens…

    # Restart drain re-runs the row. It must NOT re-fire.
    asyncio.run(ob.drain_startup())
    assert disp.fires == 1                    # at most once per dedupe key
    assert db.outbox_pending() == []          # row cleaned up


def test_first_publish_reserves_and_fires_exactly_once():
    db = Database(":memory:")
    disp = CountingDispatcher()
    ob = Outbox(db, disp, sleeps=())
    asyncio.run(ob.publish("request.created", REQ))
    assert disp.fires == 1
    assert db.notify_reserve(REQ["id"], "request.created") is False   # was reserved
    assert db.outbox_pending() == []

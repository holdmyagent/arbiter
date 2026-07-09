"""§16 outbox-idempotency gate (I18): crash between dispatch-success and
row-delete, plus cell churn, must fire a deduped delivery at most once — and
re-drain is restart-only (``Outbox.drain_startup``), never triggered by
opening/constructing a cell's Outbox.

Reconciled against the real merged G3 Outbox (server/arbiter/notify/outbox.py):
``Outbox(db, dispatcher, sleeps=RETRY_LADDER)`` — no ``tenant_id`` kwarg. The
dedupe key is ``(request_id, event)`` in the notify_sent table (G2), scoped
per-cell db; the tenant dimension is structural (one db per tenant cell), not
a column. Retry sleeps are disabled via ``sleeps=()``.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from arbiter.db import Database
from arbiter.notify.outbox import Outbox


def _iso(dt):
    return dt.isoformat()


class CountingDispatcher:
    """Matches what Outbox._dispatch actually calls: request_created for
    "request.created", request_decided for everything else."""
    def __init__(self):
        self.fires = []

    async def request_created(self, req):
        self.fires.append(("created", req["id"]))

    async def request_decided(self, req):
        self.fires.append(("decided", req["id"]))


REQ = {"id": "r1", "title": "t", "severity": "high", "status": "pending",
       "expires_at": _iso(datetime.now(timezone.utc) + timedelta(seconds=300)),
       "callback_url": None}


def test_dedupe_key_fires_at_most_once_across_restart_redrain(tmp_path):
    db = Database(str(tmp_path / "cell.sqlite3"))
    d = CountingDispatcher()
    ob = Outbox(db, d, sleeps=())
    # normal publish fires once and reserves the dedupe key
    asyncio.run(ob.publish("request.created", REQ))
    assert d.fires == [("created", "r1")]

    # simulate a crash between dispatch-success and row-delete: re-insert the
    # row (a cell reopened after churn would observe exactly this state).
    db.outbox_add(REQ["id"], "request.created", REQ, REQ["expires_at"])

    # process RESTART re-drain: the notify_sent marker must suppress a second fire.
    ob2 = Outbox(db, d, sleeps=())
    asyncio.run(ob2.drain_startup())
    assert d.fires == [("created", "r1")], "re-drain double-fired a deduped delivery"
    assert db.outbox_pending() == []  # leftover row cleaned up by the dedupe-drop path


def test_cell_open_never_triggers_a_redrain(tmp_path):
    # a leftover outbox row must be ignored by cell-open; only an explicit
    # process-restart drain_startup() call drains.
    db = Database(str(tmp_path / "cell.sqlite3"))
    db.outbox_add("r9", "request.created", {**REQ, "id": "r9"}, REQ["expires_at"])
    d = CountingDispatcher()
    # constructing an Outbox / opening a cell must NOT drain
    Outbox(db, d, sleeps=())
    assert d.fires == [], "cell-open re-drained the outbox (must be restart-only)"
    assert len(db.outbox_pending()) == 1

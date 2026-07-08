import asyncio
from datetime import datetime, timedelta, timezone

from arbiter.db import SCHEMA_VERSION
from arbiter.notify.outbox import Outbox, MAX_ATTEMPTS


def _iso(dt):
    return dt.isoformat()


REQ = {"id": "r1", "title": "Deploy", "severity": "high", "status": "pending",
       "expires_at": _iso(datetime.now(timezone.utc) + timedelta(seconds=300)),
       "callback_url": None}


class GoodDispatcher:
    def __init__(self):
        self.created, self.decided = [], []

    async def request_created(self, req):
        self.created.append(req["id"])

    async def request_decided(self, req):
        self.decided.append(req["id"])


class FailingDispatcher:
    """Raises on the first `fail_times` calls, then succeeds."""

    def __init__(self, fail_times=10**9):
        self.calls = 0
        self.fail_times = fail_times

    async def request_created(self, req):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("boom")

    async def request_decided(self, req):
        await self.request_created(req)


def test_migration_6_creates_outbox_table(db):
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "outbox" in names
    # SCHEMA_VERSION bumped to 7 by G1 (pairings table); this test only asserts
    # migration 6 (outbox) landed, not the exact version.
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_publish_success_deletes_row(db):
    d = GoodDispatcher()
    ob = Outbox(db, d, sleeps=())
    asyncio.run(ob.publish("request.created", REQ))
    assert d.created == ["r1"]
    assert db.outbox_pending() == []


def test_decided_and_expired_route_to_request_decided(db):
    d = GoodDispatcher()
    ob = Outbox(db, d, sleeps=())
    asyncio.run(ob.publish("request.decided", REQ))
    asyncio.run(ob.publish("request.expired", REQ))
    assert d.decided == ["r1", "r1"]
    assert d.created == []


def test_max_attempts_then_row_stays_no_dlq(db):
    d = FailingDispatcher()  # always fails
    ob = Outbox(db, d, sleeps=())
    asyncio.run(ob.publish("request.created", REQ))
    assert d.calls == MAX_ATTEMPTS == 3
    rows = db.outbox_pending()
    assert len(rows) == 1 and rows[0]["attempts"] == 3  # stays put; no DLQ table


def test_retry_recovers_midway(db):
    d = FailingDispatcher(fail_times=2)
    ob = Outbox(db, d, sleeps=())
    asyncio.run(ob.publish("request.created", REQ))
    assert d.calls == 3
    assert db.outbox_pending() == []


def test_drain_redelivers_unexpired(db):
    d = GoodDispatcher()
    ob = Outbox(db, d, sleeps=())
    db.outbox_add("r1", "request.created", REQ, REQ["expires_at"])
    asyncio.run(ob.drain_startup())
    assert d.created == ["r1"]
    assert db.outbox_pending() == []


def test_drain_stale_drops_past_request_ttl(db):
    d = GoodDispatcher()
    ob = Outbox(db, d, sleeps=())
    stale = dict(REQ, expires_at=_iso(datetime.now(timezone.utc) - timedelta(seconds=1)))
    db.outbox_add("r1", "request.created", stale, stale["expires_at"])
    asyncio.run(ob.drain_startup())
    assert d.created == []            # never dispatched
    assert db.outbox_pending() == []  # dropped


def test_drain_skips_exhausted_rows(db):
    d = GoodDispatcher()
    ob = Outbox(db, d, sleeps=())
    oid = db.outbox_add("r1", "request.created", REQ, REQ["expires_at"])
    for _ in range(MAX_ATTEMPTS):
        db.outbox_bump_attempts(oid)
    asyncio.run(ob.drain_startup())
    assert d.created == []                 # not re-attempted (max 3, no DLQ)
    assert len(db.outbox_pending()) == 1   # stays until its stale-drop


def test_startup_drain_wired_into_lifespan(cfg, tmp_path):
    # C1 migration (task-C1-brief): create_app now takes (cfg, registry,
    # control) and drains EVERY provisioned tenant's outbox on startup
    # (drain_all_at_startup, task-G4-brief), not a single passed-in `db`. Provision the
    # "default" tenant cell the same way conftest's `client` fixture does,
    # seed the pending row directly into that cell's on-disk db (the registry
    # opens its OWN connection to the SAME file when it acquires the cell —
    # see conftest.provision_tenant), and assert against that same db object
    # afterwards. This is a genuine re-verification of §9 startup drain, not
    # an xfail: the mechanism demonstrably still works post-refactor.
    from fastapi.testclient import TestClient
    from arbiter.apns import APNsSender
    from arbiter.app import create_app
    from tests.conftest import build_registry_env
    env = build_registry_env(cfg, tmp_path, sender=APNsSender(cfg))
    env.default_db.outbox_add("r1", "request.created", REQ, REQ["expires_at"])
    app = create_app(cfg, env.registry, env.control, sender=APNsSender(cfg))
    with TestClient(app):   # lifespan startup runs the drain
        pass
    assert env.default_db.outbox_pending() == []

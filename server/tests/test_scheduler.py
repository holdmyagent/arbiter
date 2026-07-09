import asyncio
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arbiter.db import Database
from arbiter.models import RequestCreate
from arbiter.scheduler import ExpiryScheduler, _ts

# ── shared fakes for the whole Group F suite ─────────────────────────────
def _now():
    return datetime.now(timezone.utc)

def _iso(dt):
    return dt.isoformat()

class _Signer:
    """Real Ed25519 key + tenant-namespaced kid, matching the Cell.signer contract."""
    def __init__(self, tenant_id):
        self.signing_key = Ed25519PrivateKey.generate()
        raw = self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.kid = f"{tenant_id}:{hashlib.sha256(raw).hexdigest()[:8]}"
    def public_key(self):
        return self.signing_key.public_key()

class _Hub:
    def __init__(self):
        self.events = []
    def publish(self, event):                    # contract: publish(event)->None
        self.events.append(event)

class _Dispatcher:
    def __init__(self):
        self.decided = []
    async def request_created(self, req):
        pass
    async def request_decided(self, req):        # Outbox routes expired->request_decided
        self.decided.append(req)

class _Cell:
    def __init__(self, tenant_id, epoch):
        self.tenant_id = tenant_id
        self.epoch = epoch
        self.db = Database(":memory:")
        self.signer = _Signer(tenant_id)
        self.hub = _Hub()
        self.dispatcher = _Dispatcher()

class _Registry:
    """Fake TenantRegistry.hold: pins by object, tracks refcount + opens so
    tests can assert exactly-once release and FD-budgeted (registry-routed)
    cold opens."""
    def __init__(self, *cells):
        self.cells = {c.tenant_id: c for c in cells}
        self.refcount = {t: 0 for t in self.cells}
        self.peak = {t: 0 for t in self.cells}
        self.opens = 0
    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        cell = self.cells[tenant_id]
        assert cell.epoch == epoch               # snapshot-consistent epoch (§5)
        self.opens += 1
        self.refcount[tenant_id] += 1
        self.peak[tenant_id] = max(self.peak[tenant_id], self.refcount[tenant_id])
        try:
            yield cell
        finally:
            self.refcount[tenant_id] -= 1

class _Control:
    def __init__(self, *cells):
        self._t = [{"tenant_id": c.tenant_id, "epoch": c.epoch} for c in cells]
    def list_tenants(self):
        return list(self._t)

def _add_pending(cell, expires_at):
    """Insert a pending request, then force its expires_at (past = overdue)."""
    req = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
    with cell.db._lock:
        cell.db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?",
                            (expires_at, req["id"]))
        cell.db.conn.commit()
    return cell.db.get_request(req["id"])

def _mk(*cells, **kw):
    reg = _Registry(*cells)
    ctl = _Control(*cells)
    kw.setdefault("approval_ttl_seconds", 900)
    return ExpiryScheduler(reg, ctl, **kw), reg, ctl

# ── F3 ───────────────────────────────────────────────────────────────────
def test_schedule_orders_by_deadline():
    cell = _Cell("default", 1)
    sched, _, _ = _mk(cell)
    soon = _iso(_now() + timedelta(seconds=10))
    later = _iso(_now() + timedelta(seconds=100))
    sched.schedule(later, "default", "r-late")
    sched.schedule(soon, "default", "r-soon")
    assert sched._heap[0][3] == "r-soon"          # earliest deadline at the root
    assert sched._wake.is_set()

def test_time_until_next_empty_is_none():
    cell = _Cell("default", 1)
    sched, _, _ = _mk(cell)
    assert sched._time_until_next() is None
    sched.schedule(_iso(_now() + timedelta(seconds=50)), "default", "r1")
    assert 0 < sched._time_until_next() <= 50

# ── F4 ───────────────────────────────────────────────────────────────────
def _verify(jws, signer, tenant_id):
    return jwt.decode(jws, signer.public_key(), algorithms=["EdDSA"],
                      audience=f"hma-verdict:{tenant_id}")

@pytest.mark.asyncio
async def test_fire_one_signs_with_that_cells_key_and_db():
    cellA = _Cell("acme", 1)
    cellB = _Cell("beta", 1)
    sched, reg, _ = _mk(cellA, cellB)
    overdue = _iso(_now() - timedelta(seconds=5))
    rB = _add_pending(cellB, overdue)                 # B's request only

    await sched._fire_one((_ts(overdue), 0, "beta", rB["id"]))

    row = cellB.db.get_request(rB["id"])
    assert row["status"] == "expired" and row["verdict_jws"]
    # verifies under B's key + audience
    claims = _verify(row["verdict_jws"], cellB.signer, "beta")
    assert claims["hma"]["decision"] == "expired"
    assert claims["hma"]["request_id"] == rB["id"]
    # FAILS under A's key (cross-tenant forgery rejected)
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(row["verdict_jws"], cellA.signer.public_key(),
                   algorithms=["EdDSA"], audience="hma-verdict:beta")
    # hit B's db, never A's; and the cell was cold-opened via the registry
    assert cellA.db.get_request(rB["id"]) is None
    assert reg.opens >= 1
    # emitted on B's hub, and refcount released exactly once (back to 0)
    assert any(e.get("event") == "request.expired" for e in cellB.hub.events)
    # drain the spawned outbox task, then assert the pin was released
    for t in list(sched._bg):
        await t
    assert reg.refcount["beta"] == 0

@pytest.mark.asyncio
async def test_fire_one_skips_tombstoned_tenant():
    cell = _Cell("gone", 1)
    sched, reg, ctl = _mk(cell)
    overdue = _iso(_now() - timedelta(seconds=5))
    r = _add_pending(cell, overdue)
    ctl._t = []                                       # tenant tombstoned: absent from control
    await sched._fire_one((_ts(overdue), 0, "gone", r["id"]))
    assert reg.opens == 0                              # never opened a dead cell
    assert cell.db.get_request(r["id"])["status"] == "pending"

# ── F5 ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_fire_due_round_robin_does_not_starve(monkeypatch):
    cellA = _Cell("acme", 1)
    cellB = _Cell("beta", 1)
    sched, reg, _ = _mk(cellA, cellB, per_tenant_batch=2)
    overdue = _iso(_now() - timedelta(seconds=5))
    a_ids = [_add_pending(cellA, overdue)["id"] for _ in range(5)]   # A floods
    b_ids = [_add_pending(cellB, overdue)["id"] for _ in range(2)]   # B is small
    for rid in a_ids:
        sched.schedule(overdue, "acme", rid)
    for rid in b_ids:
        sched.schedule(overdue, "beta", rid)

    await sched._fire_due()          # one pass: <=2 per tenant, B fully served
    assert all(cellB.db.get_request(r)["status"] == "expired" for r in b_ids)
    expired_a = sum(cellA.db.get_request(r)["status"] == "expired" for r in a_ids)
    assert expired_a == 2            # A capped this pass; overflow deferred, not lost
    assert len(sched._heap) == 3     # 3 of A's re-pushed
    for t in list(sched._bg):
        await t

@pytest.mark.asyncio
async def test_seed_schedules_pending_from_cold_cells():
    cell = _Cell("default", 1)
    overdue = _iso(_now() - timedelta(seconds=5))
    r = _add_pending(cell, overdue)
    sched, reg, _ = _mk(cell)
    await sched.seed()
    assert any(e[3] == r["id"] for e in sched._heap)

@pytest.mark.asyncio
async def test_run_expires_a_scheduled_request():
    cell = _Cell("default", 1)
    sched, reg, _ = _mk(cell, rescan_interval=0.05)
    overdue = _iso(_now() - timedelta(seconds=1))
    r = _add_pending(cell, overdue)
    sched.schedule(overdue, "default", r["id"])
    task = asyncio.create_task(sched.run())
    try:
        for _ in range(50):
            if cell.db.get_request(r["id"])["status"] == "expired":
                break
            await asyncio.sleep(0.02)
    finally:
        sched.stop()
        await task
    assert cell.db.get_request(r["id"])["status"] == "expired"
    for t in list(sched._bg):
        await t

# ── F6 ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_rescan_recovers_dropped_heap_push():
    cell = _Cell("default", 1)
    sched, reg, _ = _mk(cell)
    overdue = _iso(_now() - timedelta(seconds=5))
    r = _add_pending(cell, overdue)               # overdue, but NEVER scheduled (dropped push)
    assert sched._heap == []
    await sched._rescan_tick()                     # level trigger picks it up
    assert any(e[3] == r["id"] for e in sched._heap)
    await sched._fire_due()                         # and it actually expires
    assert cell.db.get_request(r["id"])["status"] == "expired"
    for t in list(sched._bg):
        await t

@pytest.mark.asyncio
async def test_rescan_cursor_rolls_over_tenants():
    cells = [_Cell(f"t{i}", 1) for i in range(5)]
    sched, reg, _ = _mk(*cells, seed_batch=2)
    await sched._rescan_tick()
    assert sched._rescan_cursor == 2               # advanced by seed_batch
    await sched._rescan_tick()
    assert sched._rescan_cursor == 4

# ── F7 ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_cold_cell_stale_approval_flips_and_emits():
    cell = _Cell("default", 1)
    sched, reg, _ = _mk(cell, approval_ttl_seconds=1)
    r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
    cell.db.set_decision(r["id"], "approve", "phone")   # approved, unconsumed
    original_verdict_kid = "kid-before"
    cell.db.set_verdict(r["id"], "ORIGINAL.APPROVE.JWS", original_verdict_kid)
    # force decided_at into the past so decided_at+approval_ttl is overdue
    past = _iso(_now() - timedelta(seconds=10))
    with cell.db._lock:
        cell.db.conn.execute("UPDATE requests SET decided_at=? WHERE id=?", (past, r["id"]))
        cell.db.conn.commit()
    # the staleness deadline (decided_at+1s) fires
    staleness = _iso(datetime.fromisoformat(past) + timedelta(seconds=1))
    await sched._fire_one((_ts(staleness), 0, "default", r["id"]))

    row = cell.db.get_request(r["id"])
    assert row["status"] == "expired"
    assert row["verdict_jws"] == "ORIGINAL.APPROVE.JWS"        # decision verdict KEPT
    assert row["verdict_kid"] == original_verdict_kid
    assert any(e.get("event") == "request.expired" for e in cell.hub.events)
    for t in list(sched._bg):
        await t
    assert reg.refcount["default"] == 0

@pytest.mark.asyncio
async def test_seed_schedules_staleness_deadline_for_unconsumed_approved():
    cell = _Cell("default", 1)
    sched, _, _ = _mk(cell, approval_ttl_seconds=900)
    r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
    cell.db.set_decision(r["id"], "approve", "phone")
    await sched.seed()
    assert any(e[3] == r["id"] for e in sched._heap)           # staleness entry seeded

# ── F8 ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_seed_recovers_expired_without_verdict():
    cell = _Cell("default", 1)
    r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
    # crash simulation: flip committed, verdict never did
    with cell.db._lock:
        cell.db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
        cell.db.conn.commit()
    assert cell.db.get_request(r["id"])["verdict_jws"] is None   # permanent 404 today

    sched, reg, _ = _mk(cell)
    await sched.seed()                                            # recovery re-signs

    row = cell.db.get_request(r["id"])
    assert row["status"] == "expired"
    assert row["verdict_jws"]                                     # no longer a 404
    claims = _verify(row["verdict_jws"], cell.signer, "default")
    assert claims["hma"]["decision"] == "expired"
    assert cell.db.expired_without_verdict() == []               # nothing left stranded
    for t in list(sched._bg):
        await t

# ── F9 ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_two_tenant_scheduler_isolation_and_durability():
    A = _Cell("acme", 1)
    B = _Cell("beta", 1)
    sched, reg, _ = _mk(A, B, per_tenant_batch=3)
    overdue = _iso(_now() - timedelta(seconds=5))

    a_ids = [_add_pending(A, overdue)["id"] for _ in range(5)]      # A floods
    b_id = _add_pending(B, overdue)["id"]                           # B is small
    # a dropped push for one of A's rows (never scheduled) — rescan must catch it
    for rid in a_ids[:-1]:
        sched.schedule(overdue, "acme", rid)
    sched.schedule(overdue, "beta", b_id)

    await sched._fire_due()          # B not starved by A's flood
    assert B.db.get_request(b_id)["status"] == "expired"
    await sched._rescan_tick()        # picks up the dropped one + A's deferred overflow
    await sched._fire_due()
    await sched._fire_due()
    for t in list(sched._bg):
        await t

    # every A row expired, each verified under A's key and NOT B's; and vice-versa
    for rid in a_ids:
        row = A.db.get_request(rid)
        assert row["status"] == "expired" and row["verdict_jws"]
        _verify(row["verdict_jws"], A.signer, "acme")
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(row["verdict_jws"], B.signer.public_key(),
                       algorithms=["EdDSA"], audience="hma-verdict:acme")
    # no cross-tenant db bleed and all pins released (FD budget respected)
    assert all(B.db.get_request(rid) is None for rid in a_ids)
    assert reg.refcount["acme"] == 0 and reg.refcount["beta"] == 0
    # each cell only ever saw its own expiry events on its own hub
    assert all(e["request"]["id"] in a_ids for e in A.hub.events)
    assert all(e["request"]["id"] == b_id for e in B.hub.events)

import hashlib
import time
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
    return ExpiryScheduler(reg, ctl, approval_ttl_seconds=900, **kw), reg, ctl

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

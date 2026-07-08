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
from arbiter.scheduler import ExpiryScheduler

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

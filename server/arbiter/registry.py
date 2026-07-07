import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .control import assert_dir_isolated   # §15.7 shared mint/open non-overlap guard (leaf module)
from .db import Database
from .notify import Dispatcher
from .auth import SlidingWindowLimiter
from .signing import Signer, load_or_create_signer
from .stream import Hub


@dataclass(eq=False)
class Cell:
    """The per-tenant isolation unit. Owns ALL tenant-scoped state; the ONLY path
    to this tenant's db/signer/hub/dispatcher/limiters. Nothing here lives on
    app.state (§3/§15.1). eq=False so binding is by object identity, never value."""
    tenant_id: str
    epoch: int
    dir: Path
    db: Database
    signer: Signer
    hub: Hub
    dispatcher: Dispatcher
    create_limiter: SlidingWindowLimiter
    login_limiter: SlidingWindowLimiter


def open_cell(tenant_id: str, dir, epoch: int, cfg, sender=None, other_open_dirs=()) -> Cell:
    """Build a fully-initialized Cell. Blocking (SQLite migrations + key mint);
    the registry runs it via asyncio.to_thread so it never blocks the event loop,
    and the single-flight future keeps the half-built cell unobservable until this
    returns (§5/§15.3).

    dir is re-validated realpath-canonical + absolute at open, AND re-checked for
    non-overlap against every OTHER currently-open cell's dir (§7/§14/§15.7: a shared
    dir hands two live cells the same key = silent cross-tenant forgery). The mint side
    (`ControlPlane.create_tenant`) enforces the same guard against the persisted roster;
    this is the "isolation AND at open" half — it also catches a control.db that was
    tampered/symlink-swapped AFTER mint so two live tenants now resolve to one dir.
    `other_open_dirs` is supplied by `TenantRegistry.acquire` (the dirs of all live
    `_Entry` cells, captured under the map lock). Dispatcher is built with THIS cell's
    db + the process delivery cfg; the notify group refines per-tenant
    webhook/ntfy/allowlist overrides (§9)."""
    d = Path(dir).expanduser()
    if not d.is_absolute():
        raise ValueError(f"cell dir must be absolute, got {dir!r}")
    resolved = d.resolve()
    if resolved != d:
        raise ValueError(f"cell dir must be realpath-canonical, got {dir!r}")
    # §15.7 at-open isolation: reject a dir overlapping any other LIVE cell's dir.
    # Same guard create_tenant applies at mint (shared arbiter.control.assert_dir_isolated).
    assert_dir_isolated(resolved, other_open_dirs)   # raises ValueError on overlap
    resolved.mkdir(parents=True, exist_ok=True)

    db = Database(str(resolved / "arbiter.sqlite3"))          # runs the full migration ladder
    signer = load_or_create_signer(tenant_id, resolved)        # per-cell key, namespaced kid
    hub = Hub()
    dispatcher = Dispatcher(cfg, db, sender=sender)
    create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)
    login_limiter = SlidingWindowLimiter(5, 60.0)
    return Cell(tenant_id=tenant_id, epoch=epoch, dir=resolved, db=db, signer=signer,
                hub=hub, dispatcher=dispatcher, create_limiter=create_limiter,
                login_limiter=login_limiter)


class EpochChanged(Exception):
    """The hot cell's epoch != the resolved epoch and a live holder blocks reopen
    (a delete+recreate/dir-rebind raced a live resolution). Fail closed (§5)."""


class CapacityExceeded(Exception):
    """Opening this cell would breach the runtime FD budget. Shed THIS open rather
    than fail another tenant's cell (§5/§15.13). (Enforced in Task A8.)"""


@dataclass(eq=False)
class _Entry:
    cell: "Cell"
    refcount: int
    last_used: float


class TenantRegistry:
    """Bounded-LRU registry of open cells (cap max_hot_cells). Process-global; the
    ONLY thing about tenancy that is process-global — the cells it hands out are
    not. Cross-group contract: acquire(tenant_id, epoch)->Cell (single-flight,
    caller MUST release), release(cell) (exactly once), hold() (async ctx mgr)."""

    def __init__(self, control, max_hot_cells: int = 64, stream_cap: int = 5, *,
                 cfg, sender=None, headroom: int = 150, lock_timeout: float = 5.0,
                 clock=time.monotonic):
        self._control = control
        self.max_hot_cells = max_hot_cells
        self.stream_cap = stream_cap
        self._cfg = cfg
        self._sender = sender
        self._headroom = headroom
        self._lock_timeout = lock_timeout
        self._clock = clock
        # slot value is either an asyncio.Future (open in flight) or an _Entry.
        self._map: dict[str, object] = {}
        self._stream_slots: dict[str, int] = {}
        self._map_lock = asyncio.Lock()
        # FD budget startup check is added in Task A8 (reads RLIMIT_NOFILE here).

    @asynccontextmanager
    async def _locked(self):
        # Timeout-bounded so a stuck holder degrades one tenant, never deadlocks
        # the whole process (§5/§15.13). This is the OUTER lock; a cell's DB RLock
        # is INNER and is never held across this acquire.
        await asyncio.wait_for(self._map_lock.acquire(), self._lock_timeout)
        try:
            yield
        finally:
            self._map_lock.release()

    async def acquire(self, tenant_id: str, epoch: int) -> "Cell":
        while True:
            async with self._locked():
                slot = self._map.get(tenant_id)
                if isinstance(slot, _Entry):
                    if slot.cell.epoch != epoch:
                        if slot.refcount == 0:
                            # stale-but-idle: drop it, reopen fresh below
                            self._map.pop(tenant_id, None)
                            slot = None
                        else:
                            raise EpochChanged(tenant_id)
                    else:
                        slot.refcount += 1
                        slot.last_used = self._clock()
                        return slot.cell
                if isinstance(slot, asyncio.Future):
                    fut = slot
                    # await OUTSIDE the map lock, then retry to ++refcount
                else:
                    # become the single-flight opener: install the sentinel BEFORE
                    # any await, capture the dir under the same consistent lock.
                    fut = asyncio.get_running_loop().create_future()
                    self._map[tenant_id] = fut
                    dirpath = self._control.tenant_dir(tenant_id)
                    # Snapshot every OTHER live cell's dir under the same lock so the
                    # open-side §15.7 non-overlap check sees a consistent roster.
                    other_open_dirs = [e.cell.dir for e in self._map.values()
                                       if isinstance(e, _Entry)]
                    break  # leave the lock, run the open
            # Reached only when the async-with block above did NOT break: we are
            # an awaiter of someone else's in-flight open, not the opener.
            try:
                await asyncio.wait_for(asyncio.shield(fut), self._lock_timeout)
            except Exception:
                pass
            continue
        # Reached only via the `break` above (the single-flight opener), with the
        # map lock already released. dirpath/other_open_dirs/fut were captured
        # under the lock just before the break.
        try:
            cell = await asyncio.to_thread(
                open_cell, tenant_id, dirpath, epoch, self._cfg, self._sender,
                other_open_dirs)
        except BaseException as exc:
            async with self._locked():
                if self._map.get(tenant_id) is fut:
                    self._map.pop(tenant_id, None)
            if not fut.done():
                fut.set_exception(exc)
            raise
        async with self._locked():
            entry = _Entry(cell=cell, refcount=1, last_used=self._clock())
            self._map[tenant_id] = entry
            if not fut.done():
                fut.set_result(cell)
            victims = self._collect_evictions_locked()
        for v in victims:
            await asyncio.to_thread(v.db.checkpoint_and_close)
        return cell

    def _collect_evictions_locked(self) -> list["Cell"]:
        """Pop LRU idle (refcount==0) entries until at/under cap. Returns the
        cells whose connections the caller must close AFTER releasing the map lock
        (never checkpoint under the outer lock). If every over-cap cell is pinned,
        return [] and stay temporarily over-cap (an ops signal, logged)."""
        victims: list["Cell"] = []
        while True:
            entries = [(k, v) for k, v in self._map.items() if isinstance(v, _Entry)]
            if len(entries) <= self.max_hot_cells:
                break
            idle = [(k, v) for k, v in entries if v.refcount == 0]
            if not idle:
                break  # all pinned: go over-cap rather than block a live holder
            k, v = min(idle, key=lambda kv: kv[1].last_used)
            self._map.pop(k, None)
            victims.append(v.cell)
        return victims

    async def evict_idle(self) -> int:
        """Maintenance sweep: evict LRU idle cells down to cap. Safe to call
        periodically. Returns the number evicted."""
        async with self._locked():
            victims = self._collect_evictions_locked()
        for cell in victims:
            await asyncio.to_thread(cell.db.checkpoint_and_close)
        return len(victims)

    def release(self, cell: "Cell") -> None:
        # Synchronous + no await => atomic on the event loop, safe to call from a
        # finally even during shutdown. Binds by object; exactly-once.
        entry = self._map.get(cell.tenant_id)
        if not isinstance(entry, _Entry) or entry.cell is not cell:
            raise RuntimeError(f"release of unknown/mismatched cell for {cell.tenant_id}")
        if entry.refcount <= 0:
            raise RuntimeError(f"refcount underflow for {cell.tenant_id}")
        entry.refcount -= 1

    @asynccontextmanager
    async def hold(self, tenant_id: str, epoch: int):
        cell = await self.acquire(tenant_id, epoch)
        try:
            yield cell
        finally:
            self.release(cell)

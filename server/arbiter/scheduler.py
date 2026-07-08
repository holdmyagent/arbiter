"""Process-wide expiry scheduler (spec §6, invariant §15.10).

One min-heap of (deadline, tenant_id, request_id) replaces the shipped
per-cell 1s sweeper. Holds NO cell/db/key reference — every firing acquires
the CURRENT cell via registry.hold(tenant_id, epoch) and uses that cell's own
signer + db, so a request is always expired under its own tenant's key and
against its own tenant's db.
"""
import asyncio
import heapq
import itertools
import logging
import time
from collections import OrderedDict
from datetime import datetime, timezone

from .notify.outbox import Outbox
from .signing import sign_verdict

log = logging.getLogger("arbiter.scheduler")


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ExpiryScheduler:
    def __init__(self, registry, control, *, approval_ttl_seconds: int,
                 rescan_interval: float = 30.0, seed_batch: int = 32,
                 per_tenant_batch: int = 16):
        self.registry = registry
        self.control = control
        self.approval_ttl_seconds = approval_ttl_seconds
        self.rescan_interval = rescan_interval
        self.seed_batch = seed_batch
        self.per_tenant_batch = per_tenant_batch
        self._heap: list[tuple[float, int, str, str]] = []
        self._seq = itertools.count()
        self._wake = asyncio.Event()
        self._bg: set[asyncio.Task] = set()
        self._rescan_cursor = 0
        self._last_rescan = 0.0
        self._stopped = False

    def schedule(self, expires_at: str, tenant_id: str, request_id: str) -> None:
        """Push a deadline. Duplicate entries for the same request are harmless:
        every firing is guarded at the DB layer (F1/expire_stale_approvals), so a
        re-scheduled row is at-most-once in effect."""
        heapq.heappush(self._heap,
                       (_ts(expires_at), next(self._seq), tenant_id, request_id))
        self._wake.set()

    def _time_until_next(self) -> float | None:
        if not self._heap:
            return None
        return max(0.0, self._heap[0][0] - time.time())

    def _current_epoch(self, tenant_id: str) -> int | None:
        """Current monotonic epoch from the control plane; None if the tenant
        is tombstoned/absent (its cell is gone — nothing to expire)."""
        for t in self.control.list_tenants():
            if t["tenant_id"] == tenant_id:
                return t["epoch"]
        return None

    async def _fire_one(self, entry) -> None:
        _, _, tenant_id, request_id = entry
        epoch = self._current_epoch(tenant_id)
        if epoch is None:
            return
        try:
            async with self.registry.hold(tenant_id, epoch) as cell:
                row = cell.db.get_request(request_id)
                if row is not None:
                    await self._process_row(cell, row)
        except Exception as exc:
            log.warning("expiry firing failed tenant=%s rid=%s: %s",
                        tenant_id, request_id, exc)

    async def _process_row(self, cell, row) -> None:
        now = _now()
        if row["status"] == "pending":
            jws = sign_verdict(cell.signer, request_id=row["id"],
                               action_hash=row["action_hash"], decision="expired",
                               decided_at=row["expires_at"],
                               approval_ttl=self.approval_ttl_seconds,
                               tenant_id=cell.tenant_id)
            updated = cell.db.expire_request_with_verdict(
                row["id"], jws, cell.signer.kid, now)
            if updated is not None:                    # None => a decision won the race
                self._emit_expired(cell, updated)
        elif row["status"] == "approved" and row["consumed_at"] is None:
            # staleness deadline: flip approved-unconsumed, KEEP the original
            # decision verdict (shipped expire_stale_approvals). Emit for every
            # row this call flipped (its own heap entry, if any, becomes a no-op).
            for flipped in cell.db.expire_stale_approvals(self.approval_ttl_seconds, now):
                self._emit_expired(cell, flipped)

    def _emit_expired(self, cell, row) -> None:
        cell.hub.publish({"event": "request.expired", "request": row})
        self._spawn_outbox(cell.tenant_id, cell.epoch, "request.expired", row)

    def _spawn_outbox(self, tenant_id: str, epoch: int, event: str, row: dict) -> None:
        """At-least-once delivery on a background task that RE-PINS the cell for
        its whole lifetime (§5: background tasks pin their cell). A strong ref is
        held in self._bg until done (bare create_task results are GC-eligible)."""
        async def _run():
            try:
                async with self.registry.hold(tenant_id, epoch) as cell:
                    await Outbox(cell.db, cell.dispatcher).publish(event, row)
            except Exception as exc:
                log.warning("expiry outbox publish failed tenant=%s rid=%s: %s",
                            tenant_id, row.get("id"), exc)
        t = asyncio.create_task(_run())
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    async def _fire_due(self) -> None:
        now = time.time()
        due = []
        while self._heap and self._heap[0][0] <= now:
            due.append(heapq.heappop(self._heap))
        if not due:
            return
        by_tenant: "OrderedDict[str, list]" = OrderedDict()
        for entry in due:
            by_tenant.setdefault(entry[2], []).append(entry)
        deferred = []
        for entries in by_tenant.values():
            head, tail = entries[:self.per_tenant_batch], entries[self.per_tenant_batch:]
            for entry in head:
                await self._fire_one(entry)
            deferred.extend(tail)               # over-cap this pass -> next pass (fairness)
        for entry in deferred:
            heapq.heappush(self._heap, entry)
        if deferred:
            self._wake.set()                    # loop again promptly to drain fairly

    def _schedule_row(self, tenant_id: str, row: dict) -> None:
        if row["status"] == "pending":
            self.schedule(row["expires_at"], tenant_id, row["id"])
        elif row["status"] == "approved" and row["consumed_at"] is None:
            deadline = datetime.fromisoformat(row["decided_at"]).timestamp() \
                + self.approval_ttl_seconds
            heapq.heappush(self._heap,
                           (deadline, next(self._seq), tenant_id, row["id"]))
            self._wake.set()

    async def _recover(self, cell) -> None:
        """Re-sign rows flipped to 'expired' whose verdict never committed, so a
        crash between an old two-commit flip and its sign is not a permanent
        verdict-404 (spec §6 recovery clause)."""
        for row in cell.db.expired_without_verdict():
            jws = sign_verdict(cell.signer, request_id=row["id"],
                               action_hash=row["action_hash"], decision="expired",
                               decided_at=row["expires_at"],
                               approval_ttl=self.approval_ttl_seconds,
                               tenant_id=cell.tenant_id)
            cell.db.set_verdict(row["id"], jws, cell.signer.kid)
            cell.db.add_audit(row["id"], "verdict_issued",
                              {"decision": "expired", "kid": cell.signer.kid,
                               "recovered": True})
            self._spawn_outbox(cell.tenant_id, cell.epoch, "request.expired",
                               cell.db.get_request(row["id"]))

    async def seed(self) -> None:
        """Bounded startup scan: open each cell (one at a time via hold, so at
        most one transient cell FD beyond the hot set), recover stranded expired
        rows, and schedule every open deadline. Yields between tenants."""
        for t in self.control.list_tenants():
            try:
                async with self.registry.hold(t["tenant_id"], t["epoch"]) as cell:
                    await self._recover(cell)
                    for row in cell.db.open_deadline_rows():
                        self._schedule_row(t["tenant_id"], row)
            except Exception as exc:
                log.warning("seed scan failed tenant=%s: %s", t["tenant_id"], exc)
            await asyncio.sleep(0)

    def stop(self) -> None:
        self._stopped = True
        self._wake.set()

    async def run(self) -> None:
        await self.seed()
        self._last_rescan = time.monotonic()
        while not self._stopped:
            wait = self._time_until_next()
            timeout = self.rescan_interval if wait is None \
                else min(wait, self.rescan_interval)
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            if self._stopped:
                break
            await self._fire_due()
            if time.monotonic() - self._last_rescan >= self.rescan_interval:
                self._last_rescan = time.monotonic()
                await self._rescan_tick()

    async def _rescan_tick(self) -> None:
        """Bounded level-triggered rescan: a rolling slice of tenants per tick,
        round-robin across ticks, re-scheduling every open deadline so a dropped
        heap-push cannot leave a request un-expired forever. Re-scheduling an
        already-queued row is harmless — every firing is DB-guarded."""
        tenants = self.control.list_tenants()
        if not tenants:
            return
        start = self._rescan_cursor % len(tenants)
        slice_ = tenants[start:start + self.seed_batch]
        self._rescan_cursor = start + self.seed_batch
        for t in slice_:
            try:
                async with self.registry.hold(t["tenant_id"], t["epoch"]) as cell:
                    for row in cell.db.open_deadline_rows():
                        self._schedule_row(t["tenant_id"], row)
            except Exception as exc:
                log.warning("rescan failed tenant=%s: %s", t["tenant_id"], exc)
            await asyncio.sleep(0)

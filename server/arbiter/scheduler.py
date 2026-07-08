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

    async def _fire_one(self, entry, now: datetime | None = None) -> list[dict]:
        """Returns the rows this firing actually flipped (usually 0 or 1; the
        approved-unconsumed branch can flip more than its own heap entry) --
        the sync scheduler_tick test/ops seam (§16) collects these across a
        drain pass."""
        _, _, tenant_id, request_id = entry
        epoch = self._current_epoch(tenant_id)
        if epoch is None:
            return []
        try:
            async with self.registry.hold(tenant_id, epoch) as cell:
                row = cell.db.get_request(request_id)
                if row is not None:
                    return await self._process_row(cell, row, now=now)
        except Exception as exc:
            log.warning("expiry firing failed tenant=%s rid=%s: %s",
                        tenant_id, request_id, exc)
        return []

    async def _process_row(self, cell, row, now: datetime | None = None) -> list[dict]:
        now = now or _now()
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
                return [updated]
            return []
        elif row["status"] == "approved" and row["consumed_at"] is None:
            # staleness deadline: flip approved-unconsumed, KEEP the original
            # decision verdict (shipped expire_stale_approvals). Emit for every
            # row this call flipped (its own heap entry, if any, becomes a no-op).
            flipped_rows = cell.db.expire_stale_approvals(self.approval_ttl_seconds, now)
            for flipped in flipped_rows:
                self._emit_expired(cell, flipped)
            return flipped_rows
        return []

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

    async def _fire_due(self, now: float | None = None) -> list[dict]:
        """now: injectable wall-clock (epoch seconds) for the heap-due check AND
        the DB guard passed to every firing in this pass, so a caller (the
        scheduler_tick test/ops seam, §16) can drive a single consistent clock
        through the whole pass. Defaults to the real clock for run()'s own use.
        Returns every row this pass actually flipped."""
        now_ts = time.time() if now is None else now
        due = []
        while self._heap and self._heap[0][0] <= now_ts:
            due.append(heapq.heappop(self._heap))
        if not due:
            return []
        now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
        by_tenant: "OrderedDict[str, list]" = OrderedDict()
        for entry in due:
            by_tenant.setdefault(entry[2], []).append(entry)
        deferred = []
        fired: list[dict] = []
        for entries in by_tenant.values():
            head, tail = entries[:self.per_tenant_batch], entries[self.per_tenant_batch:]
            for entry in head:
                fired.extend(await self._fire_one(entry, now=now_dt))
            deferred.extend(tail)               # over-cap this pass -> next pass (fairness)
        for entry in deferred:
            heapq.heappush(self._heap, entry)
        if deferred:
            self._wake.set()                    # loop again promptly to drain fairly
        return fired

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

    # ── §16 durability-gate seams (I19): additive, clock-injectable, public ──
    # These are test/ops entry points that reuse the exact machinery above
    # (_rescan_tick/_fire_due, _recover) -- they never reimplement firing or
    # signing, and they never alter run()'s/seed()'s own real-clock, bounded,
    # discarded-return production behavior.

    async def rescan(self, now: datetime | float | None = None) -> list[dict]:
        """Level-triggered rescan across EVERY tenant (not just one seed_batch
        slice), at an injectable clock: re-discovers every open_deadline_rows
        entry, ignoring the heap entirely, so a dropped heap-push (the row was
        never scheduled) is still recovered -- then fires whatever is due at
        `now` and returns the fired rows. `now` may be a tz-aware datetime or
        epoch-seconds float; None uses the real clock."""
        n = len(self.control.list_tenants())
        ticks = max(1, -(-n // self.seed_batch)) if n else 1
        for _ in range(ticks):
            await self._rescan_tick()
        now_ts = now.timestamp() if isinstance(now, datetime) else now
        return await self._fire_due(now=now_ts)

    async def tick(self, now: datetime | float | None = None) -> list[dict]:
        """Public §16 gate seam (I20): a bounded ONE-SHOT discover-then-fire
        pass across every tenant, round-robin and per-tenant-batch-bounded so
        one tenant's large due batch cannot starve another's due expiries
        (§15.13/§6). Identical machinery to rescan() (discover via
        open_deadline_rows, fire via _fire_due's per-tenant-grouped, batch-
        capped pass) -- kept as a distinctly-named alias because the
        fairness/FD-budget gate exercises this discover+fire contract
        specifically, not the durability-rescan story rescan() is named for."""
        return await self.rescan(now=now)

    async def recover(self, now: datetime | None = None) -> list[dict]:
        """Crash-recovery pass across every tenant cell: re-signs any row stuck
        at status='expired' with verdict_jws IS NULL (a crash between the flip
        commit and the sign commit) with that cell's OWN signer, via the
        existing _recover. Returns the recovered rows. `now` is accepted for
        seam-shape symmetry with rescan/scheduler_tick; the underlying re-sign
        uses the row's own expires_at as decided_at (spec §6), not the wall
        clock, matching seed()'s real-clock recovery path exactly."""
        recovered: list[dict] = []
        for t in self.control.list_tenants():
            try:
                async with self.registry.hold(t["tenant_id"], t["epoch"]) as cell:
                    pending_ids = [row["id"] for row in cell.db.expired_without_verdict()]
                    if not pending_ids:
                        continue
                    await self._recover(cell)
                    recovered.extend(cell.db.get_request(rid) for rid in pending_ids)
            except Exception as exc:
                log.warning("recover seam failed tenant=%s: %s", t["tenant_id"], exc)
        return recovered

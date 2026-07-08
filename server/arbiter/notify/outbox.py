"""Notification outbox (0.4.0 stretch — deliberately dumb).

Restart-safe for *enqueued* notifications: rows already in the outbox
survive a crash and are re-drained at startup. The enqueue is NOT
co-committed with the triggering state change (create/decide/expire commit
first; ``outbox_add`` commits separately in a spawned task), so a crash in
the instant between the request state change committing and the outbox row
committing can still lose that one notification — accepted v1 scope, no
transactional outbox.

Spec constraints: ONE table, max 3 attempts per row with retry gaps of 1s
then 5s between them (ladder constants 1/5/25s; the third rung is
unreachable at max 3 attempts), stale-drop past the request's TTL, and NO
dead-letter queue. A row exists only while a delivery pass is outstanding:
it is enqueued before dispatch and deleted once the pass completes, so a
crash or restart mid-flight leaves the row for the startup drain to re-run.
Channel-level failures inside the Dispatcher are still swallowed and
audited there (``notify_failed``) — the outbox guards against the process
dying, not against a receiver being down.

Because the `(request,event)` dedupe key is reserved in the cell db BEFORE
dispatch, overall delivery is at most once per dedupe key across process
restart and cell churn: a re-drained row whose key is already reserved is
dropped without re-firing.
"""
import asyncio
import logging
from datetime import datetime, timezone

log = logging.getLogger("arbiter.outbox")

RETRY_LADDER = (1.0, 5.0, 25.0)
MAX_ATTEMPTS = 3


class Outbox:
    def __init__(self, db, dispatcher, sleeps=RETRY_LADDER):
        self.db, self.dispatcher, self.sleeps = db, dispatcher, tuple(sleeps)

    async def publish(self, event: str, req: dict) -> None:
        oid = self.db.outbox_add(req["id"], event, req, req["expires_at"])
        await self._deliver(oid, event, req, attempts_done=0)

    async def drain_startup(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for row in self.db.outbox_pending():
            if row["request_expires_at"] < now:
                self.db.outbox_delete(row["id"])  # stale-drop: request TTL passed
                continue
            if row["attempts"] >= MAX_ATTEMPTS:
                continue  # exhausted: stays until its stale-drop (no DLQ)
            await self._deliver(row["id"], row["event"], row["payload"],
                                attempts_done=row["attempts"])

    async def _deliver(self, oid: str, event: str, req: dict,
                       attempts_done: int) -> None:
        # Dedupe guard (§9,§15.11): if this (request,event) was already claimed
        # by a prior delivery — including one interrupted by a crash before its
        # outbox_delete, or a cell reopened after churn — do NOT re-fire. The
        # marker is persisted in the cell db, so it survives eviction/reopen.
        if not self.db.notify_reserve(req["id"], event):
            self.db.outbox_delete(oid)
            return
        for i in range(attempts_done, MAX_ATTEMPTS):
            try:
                await self._dispatch(event, req)
                self.db.outbox_delete(oid)
                return
            except Exception as exc:
                log.warning("outbox dispatch %s for %s failed (attempt %d): %s",
                            event, req.get("id"), i + 1, exc)
                self.db.outbox_bump_attempts(oid)
                if i + 1 < MAX_ATTEMPTS and i < len(self.sleeps):
                    await asyncio.sleep(self.sleeps[i])
        # attempts exhausted: row stays for the stale-drop; deliberately no DLQ

    async def _dispatch(self, event: str, req: dict) -> None:
        if event == "request.created":
            await self.dispatcher.request_created(req)
        else:  # request.decided | request.expired — Dispatcher derives from req["status"]
            await self.dispatcher.request_decided(req)


async def drain_all_at_startup(registry, control) -> None:
    """Process-restart-only re-drain coordinator (§9/§15.11). Iterates every
    provisioned tenant exactly once at process start, opening each cell just
    long enough to drain its outbox, then releasing it. This is the ONLY place
    a drain is triggered — the per-cell lazy open path (``open_cell`` /
    ``TenantRegistry.acquire``) never drains, so constant hot-cell churn
    cannot re-fire a callback. The caller (the FastAPI ``lifespan`` startup)
    is expected to run this once, before serving traffic."""
    for t in control.list_tenants():
        tenant_id, epoch = t["tenant_id"], t["epoch"]
        try:
            async with registry.hold(tenant_id, epoch) as cell:
                await Outbox(cell.db, cell.dispatcher).drain_startup()
        except Exception as exc:
            log.warning("startup drain failed for tenant %s: %s", tenant_id, exc)

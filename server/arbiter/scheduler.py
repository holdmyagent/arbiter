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

"""Contract-faithful fakes so Group E tests can drive run_stream/Hub without the
registry/auth/cell groups. Mirrors the pinned cross-component contract exactly."""
import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import HTTPException

from arbiter.stream import Hub


class FakeCell:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.hub = Hub()


class FakeRegistry:
    """acquire() pins (refcount++), release() unpins exactly once. Mirrors the real
    registry's refcount discipline and exposes stream_cap, plus real per-tenant
    stream-slot accounting mirroring TenantRegistry.acquire_stream_slot/release_stream_slot."""
    def __init__(self, cells: dict[str, FakeCell], stream_cap: int = 5):
        self._cells = cells
        self.stream_cap = stream_cap
        self.refcounts: dict[str, int] = defaultdict(int)
        self.stream_slots: dict[str, int] = defaultdict(int)

    async def acquire(self, tenant_id: str, epoch: int) -> FakeCell:
        self.refcounts[tenant_id] += 1
        return self._cells[tenant_id]

    def release(self, cell: FakeCell) -> None:
        self.refcounts[cell.tenant_id] -= 1

    def acquire_stream_slot(self, tenant_id: str) -> bool:
        if self.stream_slots[tenant_id] >= self.stream_cap:
            return False
        self.stream_slots[tenant_id] += 1
        return True

    def release_stream_slot(self, tenant_id: str) -> None:
        if self.stream_slots[tenant_id] > 0:
            self.stream_slots[tenant_id] -= 1


class HoldMixin:
    @asynccontextmanager
    async def hold(self, tenant_id: str, epoch: int):
        cell = await self.acquire(tenant_id, epoch)
        try:
            yield cell
        finally:
            self.release(cell)


class FakeRegistryWithHold(HoldMixin, FakeRegistry):
    pass


class FakeIdentity:
    def __init__(self, tenant_id: str, name: str = "app", role: str = "app"):
        self.tenant_id, self.name, self.role = tenant_id, name, role


def make_resolve(token_to_tenant: dict[str, str], disabled: set[str] | None = None):
    """Build a resolve() with the real contract shape: acquire+pin on success,
    raise HTTPException (having released any pin) on failure."""
    if disabled is None:
        disabled = set()

    async def resolve(ws, registry, control):
        bearer = ws.headers.get("authorization", "").removeprefix("Bearer ")
        tid = token_to_tenant.get(bearer)
        if tid is None:
            raise HTTPException(403, "invalid token")   # never acquired → nothing to release
        if tid in disabled:
            raise HTTPException(403, "invalid token")   # disabled_at read on THIS resolution
        cell = await registry.acquire(tid, epoch=1)     # pins
        return FakeIdentity(tid), cell

    return resolve


class FakeWS:
    """Drives run_stream directly (no TestClient), so a blocked send is expressible."""
    def __init__(self, headers: dict | None = None):
        self.headers = headers or {}
        self.cookies: dict = {}
        self.client = None
        self.accepted = False
        self.closed: int | None = None
        self.sent: list = []
        self.block_send = False          # simulate a blackholed peer

    async def accept(self):
        self.accepted = True

    async def close(self, code: int = 1000):
        self.closed = code

    async def send_json(self, data):
        if self.block_send:
            await asyncio.Event().wait()  # never resolves → wait_for times out
        self.sent.append(data)

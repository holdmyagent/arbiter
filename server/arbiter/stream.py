import asyncio

from fastapi import HTTPException
from starlette.websockets import WebSocketDisconnect


class Hub:
    """Cell-owned WebSocket event bus. Exactly one Hub per Cell; NEVER on app.state.

    `publish` takes the fully-built wire message dict (the shape iOS/hold-sdk already
    consume: {"event": ..., "request"|"device"|"data": ...}) so callers own message
    construction and the bus stays a dumb fan-out. `close()` is the disable/revoke
    teardown: it hands every live subscriber a CLOSE sentinel so the stream loop can
    ws.close(), then drops them.
    """

    CLOSE = object()  # identity sentinel; stream loops compare with `is`

    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()
        self._closed = False

    @property
    def active(self) -> int:
        """Live subscriber count == live /v1/stream count for this cell (only
        streams subscribe), used to enforce the per-tenant stream cap."""
        return len(self._subs)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        if self._closed:
            # A disable/revoke already tore this cell down; a socket that raced
            # the teardown must not linger — hand back an already-closed queue.
            q.put_nowait(self.CLOSE)
        else:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, event: dict) -> None:
        if self._closed:
            return
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                self._subs.discard(q)  # slow consumer: drop it (fail-closed visibility)

    def close(self) -> None:
        """Idempotent. Push the CLOSE sentinel to every live subscriber so its
        stream loop ws.close()s, then drop them. Also latches _closed so any
        in-flight subscribe() gets a pre-closed queue and later publishes no-op."""
        self._closed = True
        for q in list(self._subs):
            try:
                q.put_nowait(self.CLOSE)
            except asyncio.QueueFull:
                pass  # a stuck full queue: its stream is already timing out on send
        self._subs.clear()


async def run_stream(ws, registry, control, *, resolve,
                     heartbeat: float = 30.0, send_timeout: float = 10.0) -> None:
    """The full /v1/stream session. Tenant is derived from the credential via the
    injected `resolve` (same router path as HTTP); the cell is pinned (refcount++)
    BEFORE ws.accept() and the socket subscribes to THAT cell's hub by object. The
    pin is released EXACTLY ONCE in the outer finally — a stuck send, a disconnect,
    a cap rejection and a disable sentinel all funnel through it.
    """
    try:
        identity, cell = await resolve(ws, registry, control)
    except HTTPException:
        # Auth/route/disabled failure: resolve released any pin it took. Nothing to
        # release here. Generic close; never leak which check failed.
        await ws.close(code=4401)
        return
    # From here `cell` is pinned; the outer finally is the single release site.
    try:
        # Atomic, FD-budget-aware per-tenant cap: acquire the registry's stream
        # slot BEFORE accept so two racing streams can't both read a stale
        # active count and both squeak in over cap (TOCTOU). False => shed;
        # nothing was acquired, so there is nothing to release on this path.
        if not registry.acquire_stream_slot(cell.tenant_id):
            await ws.close(code=4429)   # per-tenant stream cap
            return
        try:
            await ws.accept()
            q = cell.hub.subscribe()

            async def _heartbeat():
                while True:
                    await asyncio.sleep(heartbeat)
                    try:
                        q.put_nowait({"event": "ping", "data": {}})
                    except asyncio.QueueFull:
                        pass  # peer is already backed up; the send loop will time out

            hb = asyncio.create_task(_heartbeat())
            try:
                while True:
                    item = await q.get()
                    if item is Hub.CLOSE:               # disable/revoke teardown
                        await ws.close(code=4403)
                        break
                    # Bound every send: a blackholed peer's send blocks forever, so
                    # wait_for hard-closes it instead of pinning the cell indefinitely.
                    await asyncio.wait_for(ws.send_json(item), timeout=send_timeout)
            except (WebSocketDisconnect, asyncio.TimeoutError):
                pass
            finally:
                hb.cancel()
                cell.hub.unsubscribe(q)
        finally:
            # Acquired above => always released here, on every exit from the
            # accept/subscribe/heartbeat/send path (normal, disconnect, timeout,
            # sentinel close, or any other exception).
            registry.release_stream_slot(cell.tenant_id)
    finally:
        registry.release(cell)

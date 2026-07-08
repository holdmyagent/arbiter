import asyncio


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

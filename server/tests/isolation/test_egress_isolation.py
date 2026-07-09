import asyncio
import json

import httpx

from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry


class RecordingTransport(httpx.AsyncBaseTransport):
    """Records every outbound webhook POST it receives.

    This matches the REAL hook: `WebhookNotifier.deliver` does
    `httpx.AsyncClient(transport=self.transport)` and calls `.post(...)` on
    that client, which in turn calls `transport.handle_async_request(request)`
    — the httpx.AsyncBaseTransport protocol. The brief's snippet guessed a
    bespoke `async def post(self, url, json=None, **kw)` on the transport
    object itself; that method is never called by httpx.AsyncClient, so that
    RecordingTransport would silently capture nothing. Subclassing
    httpx.AsyncBaseTransport and implementing handle_async_request is what
    actually intercepts the request.
    """

    def __init__(self, tag: str):
        self.tag = tag
        self.seen: list[tuple[str, str | None, str | None]] = []  # (url, event, req_title)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.seen.append(
            (str(request.url), body.get("event"), body.get("request", {}).get("title"))
        )
        return httpx.Response(200, json={})


def _write_notify_toml(cell_dir, url: str) -> None:
    (cell_dir / "notify.toml").write_text(f'[webhook]\nurl = "{url}"\n')


def test_cell_dispatcher_egresses_only_its_own_body(cfg, tmp_path):
    """§16/§15.1/§9: each cell builds its OWN Dispatcher bound to its OWN db
    and its OWN per-cell delivery config (`cell_delivery` reads only
    <cell_dir>/notify.toml for a non-default tenant). A decided request in
    bob's cell must egress ONLY through bob's webhook sink — alice's sink
    must never see bob's body.

    Built as a standalone registry + two cells inside a single asyncio.run()
    coroutine, with NO TestClient/app involved. Reasoning: TenantRegistry's
    internal asyncio.Lock binds to whichever event loop first awaits it; a
    live app's lifespan loop runs inside TestClient's portal thread, so
    driving registry.acquire()/dispatcher.request_decided() from the test's
    own thread would either spin up a second, disconnected loop (the brief's
    `asyncio.get_event_loop().run_until_complete(...)` bug — that loop is not
    the portal's loop, so the locks/futures the registry created on the
    portal loop are foreign to it) or require hopping onto the portal loop
    via run_coroutine_threadsafe (a seam app.py exposes only for evict_tick/
    scheduler_tick, not for raw registry.acquire). Skipping the app/TestClient
    entirely sidesteps both: the registry, and every lock/future it creates,
    lives and dies inside this one asyncio.run() call.
    """
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)

    epochs = {}
    for name, url in (
        ("alice", "http://alice.example.invalid/hook"),
        ("bob", "http://bob.example.invalid/hook"),
    ):
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        _write_notify_toml(d, url)  # BEFORE the cell ever opens — cell_delivery reads it at open
        epochs[name] = control.create_tenant(name, str(d))

    async def scenario():
        ca = await registry.acquire("alice", epochs["alice"])
        cb = await registry.acquire("bob", epochs["bob"])
        try:
            # Each cell has its OWN dispatcher, bound to its OWN db (§15.1).
            # Non-vacuous: a regression that shares one dispatcher across
            # cells fails this immediately.
            assert ca.dispatcher is not cb.dispatcher
            assert ca.dispatcher.db is ca.db and cb.dispatcher.db is cb.db

            # Each cell's dispatcher picked up its OWN notify.toml, never the
            # other tenant's (and never a shared process cfg — §9).
            assert ca.dispatcher.cfg.webhook.url == "http://alice.example.invalid/hook"
            assert cb.dispatcher.cfg.webhook.url == "http://bob.example.invalid/hook"
            assert ca.dispatcher.cfg.webhook.enabled and cb.dispatcher.cfg.webhook.enabled

            ta, tb = RecordingTransport("alice"), RecordingTransport("bob")
            ca.dispatcher.webhook.transport = ta
            cb.dispatcher.webhook.transport = tb

            bob_req = {
                "id": "rb",
                "title": "bob-egress-secret",
                "status": "approved",
                "severity": "high",
                "callback_url": None,
                "expires_at": None,
            }
            await cb.dispatcher.request_decided(bob_req)

            # bob's body reached bob's own sink...
            assert any(t[2] == "bob-egress-secret" for t in tb.seen), (
                "bob's dispatcher never delivered bob's body to bob's own sink "
                "(delivery-capture wiring is broken, not just the isolation gate)"
            )
            # ...and NEVER alice's — this is the load-bearing egress-isolation assertion.
            assert all(t[2] != "bob-egress-secret" for t in ta.seen), (
                "bob's body egressed through alice's dispatcher/sink"
            )
        finally:
            registry.release(ca)
            registry.release(cb)

    asyncio.run(scenario())

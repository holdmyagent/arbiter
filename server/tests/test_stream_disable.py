import asyncio
import pytest

from arbiter.stream import run_stream
from tests._stream_fakes import FakeCell, FakeRegistryWithHold, FakeWS, make_resolve


@pytest.mark.asyncio
async def test_disable_closes_live_socket_and_next_connect_403s():
    cell = FakeCell("A")
    reg = FakeRegistryWithHold({"A": cell})
    disabled: set[str] = set()
    resolve = make_resolve({"tokA": "A"}, disabled=disabled)

    # A live, busy (pinned) session on a hot cell.
    ws = FakeWS({"authorization": "Bearer tokA"})
    live = asyncio.create_task(
        run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
    await asyncio.sleep(0.02)
    assert cell.hub.active == 1 and reg.refcounts["A"] == 1

    # Operator disables the tenant: flip disabled_at (fake) THEN tear down live
    # sessions with the exact one-liner the CLI/revoke path uses.
    disabled.add("A")
    async with reg.hold("A", epoch=1) as held:
        held.hub.close()

    await asyncio.wait_for(live, timeout=1.0)
    assert ws.closed == 4403                 # the pinned session did NOT exempt itself
    assert reg.refcounts["A"] == 0           # hold released; live session released

    # The next connection 403s immediately — disabled_at is read on THIS resolution.
    ws2 = FakeWS({"authorization": "Bearer tokA"})
    await run_stream(ws2, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
    assert ws2.accepted is False and ws2.closed == 4401
    assert reg.refcounts["A"] == 0

import asyncio
import pytest

from arbiter.stream import run_stream
from tests._stream_fakes import FakeCell, FakeRegistry, FakeWS, make_resolve


@pytest.mark.asyncio
async def test_happy_path_pins_delivers_and_releases_exactly_once():
    cell = FakeCell("A")
    reg = FakeRegistry({"A": cell})
    resolve = make_resolve({"tokA": "A"})
    ws = FakeWS({"authorization": "Bearer tokA"})

    task = asyncio.create_task(
        run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
    await asyncio.sleep(0.02)                     # let it resolve+accept+subscribe
    assert ws.accepted is True
    assert reg.refcounts["A"] == 1                # pinned before accept
    assert cell.hub.active == 1                   # subscribed by object

    cell.hub.publish({"event": "request.created", "request": {"id": "r1"}})
    await asyncio.sleep(0.02)
    assert ws.sent[-1] == {"event": "request.created", "request": {"id": "r1"}}

    cell.hub.close()                              # end the session cleanly
    await asyncio.wait_for(task, timeout=1.0)
    assert reg.refcounts["A"] == 0                # released exactly once
    assert cell.hub.active == 0                   # unsubscribed

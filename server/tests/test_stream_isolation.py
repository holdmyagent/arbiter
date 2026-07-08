import asyncio
import pytest

from arbiter.stream import run_stream
from tests._stream_fakes import FakeCell, FakeRegistry, FakeWS, make_resolve


@pytest.mark.asyncio
async def test_event_on_A_never_reaches_a_B_socket():
    cell_a, cell_b = FakeCell("A"), FakeCell("B")
    reg = FakeRegistry({"A": cell_a, "B": cell_b})
    resolve = make_resolve({"tokA": "A", "tokB": "B"})

    ws_a = FakeWS({"authorization": "Bearer tokA"})
    ws_b = FakeWS({"authorization": "Bearer tokB"})
    ta = asyncio.create_task(
        run_stream(ws_a, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
    tb = asyncio.create_task(
        run_stream(ws_b, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
    await asyncio.sleep(0.03)
    assert cell_a.hub.active == 1 and cell_b.hub.active == 1

    # A tenant-A create publishes to A's cell hub ONLY.
    cell_a.hub.publish({"event": "request.created", "request": {"id": "rA", "title": "secret-A"}})
    await asyncio.sleep(0.03)

    assert any(m.get("request", {}).get("id") == "rA" for m in ws_a.sent)
    assert ws_b.sent == []            # B's socket saw nothing — structural isolation

    cell_a.hub.close(); cell_b.hub.close()
    await asyncio.wait_for(asyncio.gather(ta, tb), timeout=1.0)
    assert reg.refcounts["A"] == 0 and reg.refcounts["B"] == 0

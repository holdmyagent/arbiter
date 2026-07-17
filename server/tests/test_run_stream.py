import asyncio
import pytest

from arbiter.registry import CapacityExceeded, EpochChanged
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


@pytest.mark.asyncio
async def test_auth_failure_closes_4401_without_accept_or_pin():
    reg = FakeRegistry({"A": FakeCell("A")})
    resolve = make_resolve({"tokA": "A"})            # tokB is unknown
    ws = FakeWS({"authorization": "Bearer tokB"})

    await run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)

    assert ws.accepted is False
    assert ws.closed == 4401
    assert reg.refcounts["A"] == 0                   # never acquired → never released


@pytest.mark.asyncio
async def test_blackholed_send_times_out_and_releases_refcount():
    cell = FakeCell("A")
    reg = FakeRegistry({"A": cell})
    resolve = make_resolve({"tokA": "A"})
    ws = FakeWS({"authorization": "Bearer tokA"})
    ws.block_send = True                              # peer never drains the socket

    # heartbeat fires fast → enqueues a ping → send blocks → wait_for times out.
    task = asyncio.create_task(
        run_stream(ws, reg, None, resolve=resolve, heartbeat=0.01, send_timeout=0.05))
    await asyncio.wait_for(task, timeout=1.0)         # must return on its own
    assert reg.refcounts["A"] == 0                    # stuck send still released the pin
    assert cell.hub.active == 0
    assert reg.stream_slots["A"] == 0                 # stream slot released too


@pytest.mark.asyncio
async def test_close_sentinel_hard_closes_the_live_socket():
    cell = FakeCell("A")
    reg = FakeRegistry({"A": cell})
    resolve = make_resolve({"tokA": "A"})
    ws = FakeWS({"authorization": "Bearer tokA"})

    task = asyncio.create_task(
        run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
    await asyncio.sleep(0.02)
    assert cell.hub.active == 1

    cell.hub.close()                                  # disable/revoke teardown
    await asyncio.wait_for(task, timeout=1.0)
    assert ws.closed == 4403
    assert reg.refcounts["A"] == 0
    assert reg.stream_slots["A"] == 0                 # stream slot released too


@pytest.mark.asyncio
async def test_per_tenant_stream_cap_rejects_and_still_releases():
    cell = FakeCell("A")
    reg = FakeRegistry({"A": cell}, stream_cap=2)
    resolve = make_resolve({"tokA": "A"})

    held = []
    for _ in range(2):                                # fill the cap
        ws = FakeWS({"authorization": "Bearer tokA"})
        held.append(asyncio.create_task(
            run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)))
    await asyncio.sleep(0.03)
    assert cell.hub.active == 2
    assert reg.refcounts["A"] == 2
    assert reg.stream_slots["A"] == 2                 # both slots held

    over = FakeWS({"authorization": "Bearer tokA"})   # the 3rd, over cap
    await run_stream(over, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
    assert over.accepted is False
    assert over.closed == 4429
    assert reg.refcounts["A"] == 2                    # rejected pin was released (2, not 3)
    assert reg.stream_slots["A"] == 2                 # rejected slot acquire: nothing to release

    cell.hub.close()                                  # tear down the two held sockets
    await asyncio.wait_for(asyncio.gather(*held), timeout=1.0)
    assert reg.refcounts["A"] == 0
    assert reg.stream_slots["A"] == 0                 # slot count back to baseline


@pytest.mark.asyncio
async def test_epoch_changed_during_resolve_closes_4401():
    reg = FakeRegistry({"A": FakeCell("A")})

    async def resolve(ws, registry, control):
        raise EpochChanged("A")                    # e.g. cookie-path acquire raced

    ws = FakeWS({"authorization": "Bearer tokA"})
    await run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
    assert ws.accepted is False and ws.closed == 4401


@pytest.mark.asyncio
async def test_capacity_exceeded_during_resolve_closes_1013():
    reg = FakeRegistry({"A": FakeCell("A")})

    async def resolve(ws, registry, control):
        raise CapacityExceeded("A")

    ws = FakeWS({"authorization": "Bearer tokA"})
    await run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
    assert ws.accepted is False and ws.closed == 1013

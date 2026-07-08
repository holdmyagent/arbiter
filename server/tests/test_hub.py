import asyncio
import pytest
from arbiter.stream import Hub


def test_publish_delivers_built_message_dict():
    hub = Hub()
    q = hub.subscribe()
    hub.publish({"event": "request.created", "request": {"id": "r1"}})
    assert q.get_nowait() == {"event": "request.created", "request": {"id": "r1"}}


def test_two_hubs_are_isolated():
    a, b = Hub(), Hub()
    qa, qb = a.subscribe(), b.subscribe()
    a.publish({"event": "x", "request": {"id": "1"}})
    assert qa.get_nowait()["request"]["id"] == "1"
    assert qb.empty()


def test_active_counts_live_subscribers():
    hub = Hub()
    assert hub.active == 0
    q1, q2 = hub.subscribe(), hub.subscribe()
    assert hub.active == 2
    hub.unsubscribe(q1)
    assert hub.active == 1


def test_close_pushes_sentinel_drops_subs_and_is_idempotent():
    hub = Hub()
    q = hub.subscribe()
    hub.close()
    assert q.get_nowait() is Hub.CLOSE
    assert hub.active == 0
    hub.close()  # idempotent: no raise, no second sentinel needed
    assert q.empty()


def test_subscribe_after_close_hands_back_a_pre_closed_queue():
    hub = Hub()
    hub.close()
    q = hub.subscribe()          # races a disable that already fired
    assert q.get_nowait() is Hub.CLOSE
    assert hub.active == 0        # not added to the live set


def test_publish_after_close_is_a_noop():
    hub = Hub()
    q = hub.subscribe()
    hub.close()
    q.get_nowait()               # drain the sentinel
    hub.publish({"event": "x", "request": {}})
    assert q.empty()


def test_full_slow_consumer_is_dropped_on_publish():
    hub = Hub()
    q = hub.subscribe()
    for _ in range(256):         # fill to maxsize
        q.put_nowait({"event": "fill"})
    hub.publish({"event": "overflow", "request": {}})
    assert hub.active == 0        # QueueFull → dropped from the live set

import asyncio

from arbiter.errors import GENERIC_403_DETAIL, generic_403, EqualizedFloor


def test_generic_403_is_constant_and_carries_no_pii():
    a = generic_403()
    b = generic_403()
    assert a.status_code == b.status_code == 403
    assert a.detail == b.detail == GENERIC_403_DETAIL
    # constant, generic, no tenant identity / payload leakage
    low = GENERIC_403_DETAIL.lower()
    for leaky in ("tenant", "disabled", "route", "no such column", "default", "acme"):
        assert leaky not in low


def test_equalized_floor_pads_to_floor():
    slept = []
    now = [0.0]

    def clock():
        return now[0]

    async def sleep(d):
        slept.append(d)

    ef = EqualizedFloor(0.05, clock=clock, sleep=sleep)
    started = clock()
    now[0] = 0.02                     # 20ms of real work elapsed
    asyncio.run(ef.wait(started))
    assert slept == [0.05 - 0.02]     # padded up to the 50ms floor


def test_equalized_floor_never_sleeps_negative():
    async def sleep(d):
        assert d >= 0

    ef = EqualizedFloor(0.01, clock=lambda: 0.0, sleep=sleep)
    # pretend 100ms already elapsed (clock stays 0 but started is negative)
    asyncio.run(ef.wait(-0.1))

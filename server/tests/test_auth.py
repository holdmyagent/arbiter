import pytest
from fastapi import HTTPException
from arbiter.auth import SlidingWindowLimiter, _check


class FakeClient:
    host = "127.0.0.1"


class FakeRequest:
    client = FakeClient()


def _limiter():
    return SlidingWindowLimiter(10, 60.0)


def test_ok():
    _check(FakeRequest(), "Bearer good", ("good",), _limiter())


def test_missing():
    with pytest.raises(HTTPException) as e:
        _check(FakeRequest(), None, ("good",), _limiter())
    assert e.value.status_code == 401


def test_wrong():
    with pytest.raises(HTTPException) as e:
        _check(FakeRequest(), "Bearer bad", ("good",), _limiter())
    assert e.value.status_code == 403

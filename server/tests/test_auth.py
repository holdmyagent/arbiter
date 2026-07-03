import pytest
from fastapi import HTTPException
from arbiter.auth import check_token


def test_ok():
    check_token("Bearer good", "good")


def test_missing():
    with pytest.raises(HTTPException) as e:
        check_token(None, "good")
    assert e.value.status_code == 401


def test_wrong():
    with pytest.raises(HTTPException) as e:
        check_token("Bearer bad", "good")
    assert e.value.status_code == 403

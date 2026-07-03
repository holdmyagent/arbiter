import pytest
from arbiter.db import Database
from arbiter.models import RequestCreate

@pytest.fixture
def db(): return Database(":memory:")

@pytest.fixture
def make():
    def _m(**kw): return RequestCreate(**{"title":"t", **kw})
    return _m

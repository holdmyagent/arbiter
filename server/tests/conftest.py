import pytest
from arbiter.config import Config
from arbiter.db import Database
from arbiter.models import RequestCreate

@pytest.fixture
def db(): return Database(":memory:")

@pytest.fixture
def make():
    def _m(**kw): return RequestCreate(**{"title":"t", **kw})
    return _m

@pytest.fixture
def cfg(tmp_path):
    c = Config.load(str(tmp_path / "absent.toml"))
    c.auth.agent_token = "test-agent"; c.auth.app_token = "test-app"
    c.auth.admin_password = "test-admin"; c.auth.session_secret = "test-secret"
    c.server.db_path = str(tmp_path / "t.sqlite3")
    return c

import hashlib
import json
import secrets as pysecrets
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from arbiter.apns import APNsSender
from arbiter.app import create_app
from arbiter.config import Config
from arbiter.db import Database
from arbiter.models import RequestCreate
from arbiter.control import ControlPlane          # Group A
from arbiter.registry import TenantRegistry       # Group A


@pytest.fixture
def db():
    """Bare in-memory Database — for tests exercising Database/Outbox/
    resolve_identity logic directly, with no app/registry/tenant involved at
    all. Deliberately kept (the brief calls the old `db` fixture dropped, on
    the premise that "no route reads a bare db after this group" — true for
    HTTP routes, but several pre-existing, functionally-unrelated unit tests
    (test_outbox.py, and a few in test_correctness.py/test_consume.py/
    test_identity.py) use `db` for pure Database-level assertions that never
    touch create_app or app.state; dropping it would gratuitously break those
    currently-green tests, which the task instructions forbid)."""
    return Database(":memory:")


@pytest.fixture
def make():
    def _m(**kw): return RequestCreate(**{"title": "t", **kw})
    return _m


@pytest.fixture
def cfg(tmp_path):
    c = Config.load(str(tmp_path / "absent.toml"))
    c.auth.agent_token = "test-agent"
    c.auth.app_token = "test-app"
    c.auth.admin_password = "test-admin"
    c.auth.session_secret = "test-secret"
    c.server.db_path = str(tmp_path / "t.sqlite3")
    return c


def _cell_dir(tmp_path, tenant_id):
    d = tmp_path / "cells" / tenant_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def provision_tenant(env, tenant_id):
    """Register a tenant + create its (empty) cell DB at the convention path.
    Returns (epoch, cell_db). The registry opens the SAME file lazily."""
    d = _cell_dir(env.tmp_path, tenant_id)
    epoch = env.control.create_tenant(tenant_id, str(d))
    db = Database(str(d / "arbiter.sqlite3"))     # convention: <dir>/arbiter.sqlite3
    env.dbs[tenant_id] = db
    return epoch, db


def mint_cell_token(env, tenant_id, name, role, scopes=None):
    """Mint a bearer into a tenant's cell DB AND add the control route (§12
    mint order: cell row first, then router row). Returns the bearer string."""
    db = env.dbs[tenant_id]
    tok = f"hma_{role}_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    db.conn.execute(
        "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,"
        "expires_at,last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), name, role, th,
         json.dumps(scopes) if scopes is not None else None,
         datetime.now(timezone.utc).isoformat()))
    db.conn.commit()
    env.control.add_route(th, tenant_id)          # router row (+MAC over hash,tenant,epoch)
    return tok


def build_registry_env(cfg, tmp_path, sender=None):
    """Non-fixture form of `registry_env` (below): control-plane + registry +
    a provisioned 'default' tenant cell, with a caller-supplied sender. The
    many legacy per-file `client`/`_client()` helpers (predating the
    registry/control refactor) need a FakeSender they can inspect
    (`client.sender.calls`), which a fixture can't parameterize per-test —
    so they call this directly instead of requesting the `registry_env`
    fixture. `registry_env` is a thin default-sender wrapper over this."""
    control = ControlPlane.open(tmp_path / "control", tmp_path / "cells")
    env = SimpleNamespace(control=control, tmp_path=tmp_path, dbs={})
    epoch, db = provision_tenant(env, "default")  # back-compat single cell
    env.default_epoch, env.default_db = epoch, db
    env.registry = TenantRegistry(control, cfg=cfg, sender=sender)
    env.provision = lambda tid: provision_tenant(env, tid)
    env.mint = lambda tid, name, role, scopes=None: mint_cell_token(env, tid, name, role, scopes)
    return env


@pytest.fixture
def registry_env(cfg, tmp_path):
    return build_registry_env(cfg, tmp_path)


@pytest.fixture
def client(cfg, registry_env):
    app = create_app(cfg, registry_env.registry, registry_env.control, sender=APNsSender(cfg))
    with TestClient(app) as c:
        c.db = registry_env.default_db            # existing tests read client.db
        c.env = registry_env
        c.app_ref = app
        yield c


@pytest.fixture
def agent_headers():
    return {"Authorization": "Bearer test-agent"}


@pytest.fixture
def app_headers():
    return {"Authorization": "Bearer test-app"}


@pytest.fixture(autouse=True)
def _clear_revoked():
    from arbiter import web
    web._REVOKED.clear()
    yield

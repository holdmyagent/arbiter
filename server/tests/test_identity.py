import hashlib
import logging

import pytest
from fastapi.testclient import TestClient

from arbiter import auth as arbiter_auth
from arbiter.app import create_app
from arbiter.models import RequestCreate

from tests.conftest import build_registry_env

def _sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()

# ── route wiring: identity-aware create / scoped reads / decided_by ─────────

class FakeSender:
    async def send(self, token, payload):
        return "sent"

@pytest.fixture
def client(cfg, tmp_path):
    sender = FakeSender()
    env = build_registry_env(cfg, tmp_path, sender=sender)
    app = create_app(cfg, env.registry, env.control, sender=sender)
    c = TestClient(app)
    c.db = env.default_db
    c.env = env
    return c

def _mint(client, name, role):
    """Mint a bearer AND register its control-plane route (mirrors
    conftest.mint_cell_token) — a bare db.create_token() is invisible to
    resolve_identity, which routes through the control plane first."""
    value = f"hma_{role}_{name}"
    client.db.create_token(name, role, _sha(value))
    client.env.control.add_route(_sha(value), "default")
    return {"Authorization": f"Bearer {value}"}

def test_db_agent_create_stamps_requested_by(client):
    hdr = _mint(client, "hermes", "agent")
    r = client.post("/v1/requests", json={"title": "Deploy"}, headers=hdr)
    assert r.status_code == 200 and r.json()["requested_by"] == "hermes"

def test_warden_role_can_create(client):
    hdr = _mint(client, "knossos-warden", "warden")
    r = client.post("/v1/requests", json={"title": "Act"}, headers=hdr)
    assert r.status_code == 200 and r.json()["requested_by"] == "knossos-warden"

def test_app_role_cannot_create(client):
    r = client.post("/v1/requests", json={"title": "x"},
                    headers={"Authorization": "Bearer test-app"})
    assert r.status_code == 403

def test_cross_agent_read_is_404_but_app_sees_all(client):
    a = _mint(client, "a1", "agent")
    b = _mint(client, "b1", "agent")
    rid = client.post("/v1/requests", json={"title": "mine"}, headers=a).json()["id"]
    assert client.get(f"/v1/requests/{rid}", headers=a).status_code == 200
    assert client.get(f"/v1/requests/{rid}", headers=b).status_code == 404
    assert client.get(f"/v1/requests/{rid}",
                      headers={"Authorization": "Bearer test-app"}).status_code == 200

def test_legacy_agent_sees_legacy_rows_and_own_but_not_db_agents(client):
    legacy = {"Authorization": "Bearer test-agent"}
    # legacy config-token creates stamp requested_by NULL (pre-0.4.0 convention)...
    own = client.post("/v1/requests", json={"title": "own"}, headers=legacy).json()
    assert own["requested_by"] is None
    # ...and the legacy token sees exactly the requested_by-IS-NULL rows
    assert client.get(f"/v1/requests/{own['id']}", headers=legacy).status_code == 200
    # a pre-0.4.0 row (requested_by NULL) stays visible to the legacy token
    old = client.db.create_request(RequestCreate(title="pre-existing"))
    assert old["requested_by"] is None
    assert client.get(f"/v1/requests/{old['id']}", headers=legacy).status_code == 200
    # ...but another (DB-token) agent's request is not
    other = _mint(client, "hermes", "agent")
    rid = client.post("/v1/requests", json={"title": "hers"}, headers=other).json()["id"]
    assert client.get(f"/v1/requests/{rid}", headers=legacy).status_code == 404

def test_legacy_token_warns_deprecation_exactly_once(client, caplog, monkeypatch):
    monkeypatch.setattr(arbiter_auth, "_LEGACY_WARNED", False)
    legacy = {"Authorization": "Bearer test-agent"}
    msg = ("legacy config token in use - static [auth] tokens are deprecated; "
           "mint scoped tokens with hma token create")
    with caplog.at_level(logging.WARNING, logger="arbiter.auth"):
        assert client.post("/v1/requests", json={"title": "one"},
                           headers=legacy).status_code == 200
        assert client.post("/v1/requests", json={"title": "two"},
                           headers=legacy).status_code == 200
    assert sum(msg in r.getMessage() for r in caplog.records) == 1

def test_db_app_token_stamps_decided_by_with_identity_name(client):
    client.db.register_device("tokX", "Kevins-iPhone")  # would win the legacy heuristic
    approver = _mint(client, "kevin-phone", "app")
    rid = client.post("/v1/requests", json={"title": "t"},
                      headers={"Authorization": "Bearer test-agent"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", json={"decision": "approve"},
                    headers=approver)
    assert d.status_code == 200 and d.json()["decided_by"] == "kevin-phone"

def test_legacy_app_token_keeps_device_heuristic(client):
    client.db.register_device("tokX", "Kevins-iPhone")
    rid = client.post("/v1/requests", json={"title": "t"},
                      headers={"Authorization": "Bearer test-agent"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", json={"decision": "approve"},
                    headers={"Authorization": "Bearer test-app"})
    assert d.status_code == 200 and d.json()["decided_by"] == "Kevins-iPhone"

def test_revoked_db_token_gets_403_on_routes(client):
    hdr = _mint(client, "temp", "agent")
    assert client.post("/v1/requests", json={"title": "a"}, headers=hdr).status_code == 200
    client.db.revoke_token("temp")
    assert client.post("/v1/requests", json={"title": "b"}, headers=hdr).status_code == 403

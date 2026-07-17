import hashlib
import json
import secrets as pysecrets
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.auth import Identity
from arbiter.models import RequestCreate
from arbiter.policy import PolicyResult, evaluate_create

from tests.conftest import build_registry_env

AGENT = {"Authorization": "Bearer test-agent"}

class FakeSender:
    async def send(self, token, payload):
        return "sent"


def mint_token(client, name, role, scopes=None):
    """Insert a DB token row AND register its control-plane route (mirrors
    conftest.mint_cell_token) — a bare token-row insert is invisible to
    resolve_identity, which routes through the control plane first."""
    tok = f"hma_{role}_{pysecrets.token_hex(24)}"
    th = hashlib.sha256(tok.encode()).hexdigest()
    client.db.conn.execute(
        "INSERT INTO tokens(id, name, role, token_hash, scopes, created_at,"
        " expires_at, last_used_at, revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
        (str(uuid.uuid4()), name, role, th,
         json.dumps(scopes) if scopes is not None else None,
         datetime.now(timezone.utc).isoformat()))
    client.db.conn.commit()
    client.env.control.add_route(th, "default")
    return tok


def _client(cfg, tmp_path):
    sender = FakeSender()
    env = build_registry_env(cfg, tmp_path, sender=sender)
    app = create_app(cfg, env.registry, env.control, sender=sender)
    c = TestClient(app)
    c.db = env.default_db
    c.env = env
    c.app_ref = app
    return c


# ── unit: evaluate_create ────────────────────────────────────────────────────

def test_evaluate_create_deny_list(cfg):
    cfg.policy.deny_action_types = ["db.drop"]
    res = evaluate_create(cfg, Identity("agent", "agent"),
                          RequestCreate(title="t", action_type="db.drop"))
    assert res == PolicyResult(False, "medium", "denied by policy")


def test_evaluate_create_severity_floor(cfg):
    cfg.policy.severity_floors = {"deploy": "high"}
    res = evaluate_create(cfg, Identity("agent", "agent"),
                          RequestCreate(title="t", action_type="deploy", severity="low"))
    assert res.allowed and res.effective_severity == "high"
    # a claim above the floor is kept
    res2 = evaluate_create(cfg, Identity("agent", "agent"),
                           RequestCreate(title="t", action_type="deploy",
                                         severity="critical"))
    assert res2.effective_severity == "critical"


def test_evaluate_create_scopes(cfg):
    scopes = {"action_types": ["deploy"], "max_severity": "high"}
    ok = evaluate_create(cfg, Identity("bot", "agent"),
                         RequestCreate(title="t", action_type="deploy", severity="high"),
                         scopes=scopes)
    assert ok.allowed
    bad_type = evaluate_create(cfg, Identity("bot", "agent"),
                               RequestCreate(title="t", action_type="db.drop"),
                               scopes=scopes)
    assert not bad_type.allowed and "action_type" in bad_type.reason
    bad_sev = evaluate_create(cfg, Identity("bot", "agent"),
                              RequestCreate(title="t", action_type="deploy",
                                            severity="critical"), scopes=scopes)
    assert not bad_sev.allowed and "max_severity" in bad_sev.reason


# ── HTTP wiring ──────────────────────────────────────────────────────────────

def test_create_policy_denied_403(cfg, tmp_path):
    cfg.policy.deny_action_types = ["db.drop"]
    client = _client(cfg, tmp_path)
    r = client.post("/v1/requests", headers=AGENT,
                    json={"title": "t", "action_type": "db.drop"})
    assert r.status_code == 403
    assert r.json()["detail"] == "policy: denied by policy"


def test_create_floor_raises_stored_severity(cfg, tmp_path):
    cfg.policy.severity_floors = {"deploy": "high"}
    client = _client(cfg, tmp_path)
    r = client.post("/v1/requests", headers=AGENT,
                    json={"title": "t", "action_type": "deploy", "severity": "low"})
    assert r.status_code == 200 and r.json()["severity"] == "high"
    assert client.db.get_request(r.json()["id"])["severity"] == "high"


def test_scoped_token_enforcement_403(cfg, tmp_path):
    client = _client(cfg, tmp_path)
    tok = mint_token(client, "bot", "agent",
                     scopes={"action_types": ["deploy"], "max_severity": "high"})
    h = {"Authorization": f"Bearer {tok}"}
    assert client.post("/v1/requests", headers=h,
                       json={"title": "t", "action_type": "deploy",
                             "severity": "critical"}).status_code == 403
    assert client.post("/v1/requests", headers=h,
                       json={"title": "t", "action_type": "db.drop"}).status_code == 403
    ok = client.post("/v1/requests", headers=h,
                     json={"title": "t", "action_type": "deploy"})
    assert ok.status_code == 200


def test_rate_limit_429_after_n_creates(cfg, tmp_path):
    cfg.policy.rate_limit_per_minute = 3
    client = _client(cfg, tmp_path)
    for _ in range(3):
        assert client.post("/v1/requests", headers=AGENT,
                           json={"title": "t"}).status_code == 200
    r = client.post("/v1/requests", headers=AGENT, json={"title": "t"})
    assert r.status_code == 429
    assert r.json()["detail"] == "rate limited"


def test_config_template_has_policy_section():
    from arbiter.cli import CONFIG_TEMPLATE
    assert "[policy]" in CONFIG_TEMPLATE
    assert "deny_action_types" in CONFIG_TEMPLATE


def test_create_race_falls_back_to_db_duplicate_index(cfg, tmp_path, monkeypatch):
    # Simulate the read-then-insert race the in-route duplicate check can
    # lose: force the route's dup lookups to miss, so the INSERT hits
    # migration 10's partial unique index. The route must return the
    # surviving row (collapse semantics), not 500.
    from arbiter.db import Database
    client = _client(cfg, tmp_path)
    tok = mint_token(client, "racer", "agent")
    h = {"Authorization": f"Bearer {tok}"}
    orig = Database.find_duplicate_pending
    calls = {"n": 0}

    def flaky(self, *a, **kw):
        calls["n"] += 1
        return None if calls["n"] <= 2 else orig(self, *a, **kw)  # both creates "miss"

    monkeypatch.setattr(Database, "find_duplicate_pending", flaky)
    r1 = client.post("/v1/requests", headers=h, json={"title": "same"})
    r2 = client.post("/v1/requests", headers=h, json={"title": "same"})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["id"] == r1.json()["id"]        # collapsed to the survivor

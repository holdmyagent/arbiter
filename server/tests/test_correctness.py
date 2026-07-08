import hashlib
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from arbiter.app import create_app

from tests.conftest import build_registry_env

AGENT = {"Authorization": "Bearer test-agent"}
APP = {"Authorization": "Bearer test-app"}

# C1 migration (task-C1-brief): create_app now takes (cfg, registry, control);
# require_role reads request.app.state.db, removed per §15.1 — so every route
# behind it 500s/errors until ported per-cell (Groups C4-C8). Assertions below
# are unchanged; xfail(strict=False) documents the expected breakage.
_API_XFAIL = pytest.mark.xfail(
    reason="require_role reads app.state.db, removed per C1 §15.1; ported per-cell in C4-C8",
    strict=False)


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
    c.app_ref = app
    return c


def test_concurrent_approve_deny_exactly_one_wins(db, make):
    r = db.create_request(make())
    barrier = threading.Barrier(2)
    results = {}
    def decide(word):
        barrier.wait()
        results[word] = db.set_decision(r["id"], word, "tester")
    threads = [threading.Thread(target=decide, args=(w,)) for w in ("approve", "deny")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [v for v in results.values() if v is not None]
    assert len(winners) == 1
    assert db.get_request(r["id"])["status"] == winners[0]["status"]


def test_db_decision_refuses_clock_expired(db, make):
    r = db.create_request(make(ttl_seconds=-5))    # already past deadline
    assert db.set_decision(r["id"], "approve", "tester") is None
    assert db.get_request(r["id"])["status"] == "pending"   # sweeper's job to flip it


def test_decide_expired_by_clock_409(client):
    rid = client.post("/v1/requests", headers=AGENT, json={"title": "t"}).json()["id"]
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    client.db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?", (past, rid))
    client.db.conn.commit()
    r = client.post(f"/v1/requests/{rid}/decision", headers=APP,
                    json={"decision": "approve"})
    assert r.status_code == 409
    assert "expired" in r.json()["detail"]


def test_ttl_clamped_low_and_high(client):
    # distinct titles: identical unbound titles would duplicate-collapse
    lo = client.post("/v1/requests", headers=AGENT,
                     json={"title": "t-lo", "ttl_seconds": 1}).json()
    assert lo["ttl_seconds"] == 30
    created = datetime.fromisoformat(lo["created_at"])
    expires = datetime.fromisoformat(lo["expires_at"])
    assert (expires - created).total_seconds() == 30
    hi = client.post("/v1/requests", headers=AGENT,
                     json={"title": "t-hi", "ttl_seconds": 999999}).json()
    assert hi["ttl_seconds"] == 86400


def test_idempotent_create_returns_same_row(client):
    body = {"title": "t", "idempotency_key": "k-1"}
    a = client.post("/v1/requests", headers=AGENT, json=body)
    b = client.post("/v1/requests", headers=AGENT, json=body)
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["id"] == b.json()["id"]
    assert len(client.db.list_requests()) == 1


def test_idempotency_key_max_length_422(client):
    r = client.post("/v1/requests", headers=AGENT,
                    json={"title": "t", "idempotency_key": "x" * 129})
    assert r.status_code == 422


def test_duplicate_pending_collapses_on_action_hash(client):
    canonical = '{"a":1}'
    ah = hashlib.sha256(canonical.encode()).hexdigest()
    body = {"title": "t", "canonical_action": canonical, "action_hash": ah}
    a = client.post("/v1/requests", headers=AGENT, json=body)
    b = client.post("/v1/requests", headers=AGENT, json=body)
    assert a.json()["id"] == b.json()["id"]
    assert len(client.db.list_requests()) == 1
    # once decided, an identical create makes a NEW request
    client.post(f"/v1/requests/{a.json()['id']}/decision", headers=APP,
                json={"decision": "deny"})
    c2 = client.post("/v1/requests", headers=AGENT, json=body)
    assert c2.json()["id"] != a.json()["id"]


def test_duplicate_pending_collapses_unbound_on_title(client):
    # unbound requests (no action_hash) collapse on (requested_by, title)
    a = client.post("/v1/requests", headers=AGENT, json={"title": "restart api"})
    b = client.post("/v1/requests", headers=AGENT, json={"title": "restart api"})
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["id"] == b.json()["id"]
    assert len(client.db.list_requests()) == 1
    # a different title is a different action -> new row
    c = client.post("/v1/requests", headers=AGENT, json={"title": "restart db"})
    assert c.status_code == 200 and c.json()["id"] != a.json()["id"]
    assert len(client.db.list_requests()) == 2

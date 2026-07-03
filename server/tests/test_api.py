import pytest
from fastapi.testclient import TestClient
from arbiter.app import create_app
from arbiter.db import Database

class FakeSender:
    def __init__(self): self.calls=[]
    async def send(self, token, payload): self.calls.append((token,payload)); return "sent"

@pytest.fixture
def client(cfg):
    db = Database(":memory:"); sender = FakeSender()
    app = create_app(cfg, db, sender)
    c = TestClient(app); c.sender = sender; c.db = db; return c

def _create(c, tok="test-agent"):
    return c.post("/v1/requests", headers={"Authorization": f"Bearer {tok}"},
                  json={"title":"Deploy","severity":"high","ttl_seconds":300})

def test_create_requires_agent_token(client):
    assert _create(client, tok="test-app").status_code == 403

def test_create_and_push(client):
    client.db.register_device("tok1","iPhone")
    r = _create(client); assert r.status_code==200 and r.json()["status"]=="pending"
    assert len(client.sender.calls)==1

def test_list_and_decide(client):
    rid=_create(client).json()["id"]
    lst=client.get("/v1/requests?status=pending", headers={"Authorization":"Bearer test-app"})
    assert lst.status_code==200 and len(lst.json())==1
    d=client.post(f"/v1/requests/{rid}/decision", headers={"Authorization":"Bearer test-app"},
                  json={"decision":"approve"})
    assert d.status_code==200 and d.json()["status"]=="approved"
    d2=client.post(f"/v1/requests/{rid}/decision", headers={"Authorization":"Bearer test-app"},
                   json={"decision":"deny"})
    assert d2.status_code==409

def test_unknown_404(client):
    assert client.get("/v1/requests/nope", headers={"Authorization":"Bearer test-agent"}).status_code==404

def test_device_register(client):
    r = client.post("/v1/devices", headers={"Authorization": "Bearer test-app"},
                    json={"apns_token": "abc123", "name": "My iPhone"})
    assert r.status_code == 200
    assert r.json()["apns_token"] == "abc123"
    devices = client.db.list_devices()
    assert len(devices) == 1 and devices[0]["apns_token"] == "abc123"

def test_decision_records_device_name(client):
    client.db.register_device("tokX", "Kevins-iPhone")
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision",
                    headers={"Authorization": "Bearer test-app"}, json={"decision": "approve"})
    assert d.status_code == 200 and d.json()["decided_by"] == "Kevins-iPhone"

def test_create_invalid_severity_returns_422(client):
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "T", "severity": "extreme", "ttl_seconds": 300})
    assert r.status_code == 422

def test_decide_invalid_decision_value_returns_422(client):
    rid = _create(client).json()["id"]
    r = client.post(f"/v1/requests/{rid}/decision",
                    headers={"Authorization": "Bearer test-app"},
                    json={"decision": "maybe"})
    assert r.status_code == 422

def test_severity_filter_medium(client):
    """Device with min_severity=low receives medium push; device with min_severity=high does not."""
    client.db.register_device("tokA", "iPhone A", min_severity="low")
    client.db.register_device("tokB", "iPhone B", min_severity="high")
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "Deploy", "severity": "medium", "ttl_seconds": 300})
    assert r.status_code == 200
    tokens_called = [token for token, _ in client.sender.calls]
    assert "tokA" in tokens_called
    assert "tokB" not in tokens_called

def test_severity_filter_critical(client):
    """Both devices receive critical push regardless of their threshold."""
    client.db.register_device("tokA", "iPhone A", min_severity="low")
    client.db.register_device("tokB", "iPhone B", min_severity="high")
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "Escalation", "severity": "critical", "ttl_seconds": 300})
    assert r.status_code == 200
    tokens_called = [token for token, _ in client.sender.calls]
    assert "tokA" in tokens_called
    assert "tokB" in tokens_called

def test_notifications_enabled_filter(client):
    """Push only sent to device with notifications_enabled=True, not to disabled device."""
    client.db.register_device("tokA", "iPhone A", min_severity="low", notifications_enabled=True)
    client.db.register_device("tokB", "iPhone B", min_severity="low", notifications_enabled=False)
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "Alert", "severity": "high", "ttl_seconds": 300})
    assert r.status_code == 200
    tokens_called = [token for token, _ in client.sender.calls]
    assert "tokA" in tokens_called
    assert "tokB" not in tokens_called

def test_sound_flag_false_omits_sound_key(client):
    """Device with sound=False receives a payload with no 'sound' key in aps."""
    client.db.register_device("tokC", "iPhone C", min_severity="low", sound=False)
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "Silent Alert", "severity": "high", "ttl_seconds": 300})
    assert r.status_code == 200
    assert len(client.sender.calls) == 1
    _, payload = client.sender.calls[0]
    assert "sound" not in payload["aps"]

def test_sound_flag_true_includes_default_sound(client):
    """Device with sound=True receives a payload with 'sound': 'default' in aps."""
    client.db.register_device("tokD", "iPhone D", min_severity="low", sound=True)
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "Noisy Alert", "severity": "high", "ttl_seconds": 300})
    assert r.status_code == 200
    assert len(client.sender.calls) == 1
    _, payload = client.sender.calls[0]
    assert payload["aps"].get("sound") == "default"


# ── S2: /health + /pair ──────────────────────────────────────────────────────

def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_pair_requires_token(client):
    """Unauthenticated /pair must NOT leak the app token, QR, or deep-link payload."""
    r = client.get("/pair")
    assert r.status_code == 401
    assert "holdmyagent://pair" not in r.text  # payload (contains token) not rendered
    assert "<svg" not in r.text                # QR (encodes token) not rendered


def test_pair_wrong_token_rejected(client):
    r = client.get("/pair?token=not-the-token")
    assert r.status_code == 401
    assert "holdmyagent://pair" not in r.text


def test_pair_page_returns_html(client):
    r = client.get("/pair?token=test-app")  # 'test-app' is the app token in the fixture
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_pair_page_contains_payload(client):
    """The authorized /pair page renders the pairing deep-link (which carries the token)."""
    r = client.get("/pair?token=test-app")
    assert "holdmyagent://pair" in r.text
    assert "token=test-app" in r.text


def test_pair_page_contains_svg_qr(client):
    """The authorized /pair page embeds an inline SVG QR code."""
    r = client.get("/pair?token=test-app")
    assert "<svg" in r.text


def test_pair_page_contains_run_command(client):
    """The authorized /pair page shows the `python -m arbiter.pair` run command."""
    r = client.get("/pair?token=test-app")
    assert "python -m arbiter.pair" in r.text


def test_pair_page_contains_trust_note(client):
    """The authorized /pair page displays the trusted-network security notice."""
    r = client.get("/pair?token=test-app")
    assert "trusted" in r.text.lower()


def test_root_links_to_pair(client):
    """GET / returns HTML with a link to /pair."""
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "/pair" in r.text

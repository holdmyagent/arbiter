import asyncio, hashlib, hmac, json
import httpx, pytest
from arbiter.notify.ntfy import NtfyNotifier, PRIORITY
from arbiter.notify.webhook import WebhookNotifier, sign
from arbiter.notify import Dispatcher
from arbiter.config import Config

REQ = {"id": "r1", "title": "Deploy", "description": "", "severity": "critical",
       "status": "pending", "target": "prod", "callback_url": None}

def _cfg(tmp_path):
    c = Config.load(str(tmp_path / "absent.toml"))
    c.auth.agent_token = "a"; c.auth.app_token = "b"
    return c

def test_ntfy_payload_and_priority(tmp_path):
    seen = {}
    def handler(request):
        seen["url"] = str(request.url); seen["headers"] = dict(request.headers)
        seen["body"] = request.read().decode()
        return httpx.Response(200)
    c = _cfg(tmp_path); c.ntfy.topic = "hma-test"
    n = NtfyNotifier(c.ntfy, transport=httpx.MockTransport(handler))
    asyncio.run(n.send(REQ))
    assert seen["url"] == "https://ntfy.sh/hma-test"
    assert seen["headers"]["priority"] == PRIORITY["critical"] == "5"
    assert seen["headers"]["click"] == "holdmyagent://request/r1"
    assert "Deploy" in seen["headers"]["title"]

def test_webhook_signature_and_shape(tmp_path):
    seen = {}
    def handler(request):
        seen["sig"] = request.headers.get("x-hma-signature")
        seen["body"] = request.read()
        return httpx.Response(200)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/x"; c.webhook.secret = "sec"
    w = WebhookNotifier(c.webhook, transport=httpx.MockTransport(handler), sleeps=())
    ok = asyncio.run(w.deliver(c.webhook.url, "request.created", REQ))
    assert ok
    expected = "sha256=" + hmac.new(b"sec", seen["body"], hashlib.sha256).hexdigest()
    assert seen["sig"] == expected == sign("sec", seen["body"])
    assert json.loads(seen["body"]) == {"event": "request.created", "request": REQ}

def test_webhook_unsigned_without_secret(tmp_path):
    seen = {}
    def handler(request):
        seen["sig"] = request.headers.get("x-hma-signature"); return httpx.Response(200)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/x"
    w = WebhookNotifier(c.webhook, transport=httpx.MockTransport(handler), sleeps=())
    asyncio.run(w.deliver(c.webhook.url, "request.created", REQ))
    assert seen["sig"] is None

def test_webhook_retries_then_succeeds(tmp_path):
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        return httpx.Response(500 if calls["n"] < 3 else 200)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/x"
    w = WebhookNotifier(c.webhook, transport=httpx.MockTransport(handler), sleeps=(0, 0, 0))
    assert asyncio.run(w.deliver(c.webhook.url, "e", REQ)) and calls["n"] == 3

def test_dispatcher_failure_is_not_fatal_and_audited(tmp_path, db):
    def handler(request): raise httpx.ConnectError("boom")
    c = _cfg(tmp_path); c.ntfy.topic = "t"
    req = dict(REQ)
    d = Dispatcher(c, db, transport=httpx.MockTransport(handler))
    asyncio.run(d.request_created(req))     # must not raise
    events = [a["event"] for a in db.get_audit("r1")]
    assert "notify_failed" in events

def test_dispatcher_decided_hits_callback_url(tmp_path, db):
    seen = []
    def handler(request):
        seen.append(str(request.url)); return httpx.Response(200)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/global"; c.webhook.secret = "s"
    req = dict(REQ); req["callback_url"] = "http://agent.local/cb"; req["status"] = "approved"
    d = Dispatcher(c, db, transport=httpx.MockTransport(handler))
    asyncio.run(d.request_decided(req))
    assert set(seen) == {"http://hook.local/global", "http://agent.local/cb"}

def test_guard_survives_audit_failure(tmp_path):
    class BoomDB:
        def add_audit(self, *a, **k): raise RuntimeError("db is locked")
        def list_devices(self): return []
    def handler(request): raise httpx.ConnectError("down")
    c = _cfg(tmp_path); c.ntfy.topic = "t"
    d = Dispatcher(c, BoomDB(), transport=httpx.MockTransport(handler))
    asyncio.run(d.request_created(dict(REQ)))   # must not raise

def test_webhook_4xx_is_hard_stop_no_retry(tmp_path):
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1; return httpx.Response(410)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/x"
    w = WebhookNotifier(c.webhook, transport=httpx.MockTransport(handler), sleeps=(0, 0, 0))
    assert asyncio.run(w.deliver(c.webhook.url, "e", REQ)) is False and calls["n"] == 1

def test_dispatcher_expired_status_sends_expired_event(tmp_path, db):
    seen = []
    def handler(request):
        import json as j; seen.append(j.loads(request.read())["event"]); return httpx.Response(200)
    c = _cfg(tmp_path); c.webhook.url = "http://hook.local/g"; c.webhook.secret = "s"
    req = dict(REQ); req["status"] = "expired"
    asyncio.run(Dispatcher(c, db, transport=httpx.MockTransport(handler)).request_decided(req))
    assert seen == ["request.expired"]

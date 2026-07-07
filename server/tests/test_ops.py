import asyncio
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.config import WebhookCfg
from arbiter.db import Database
from arbiter.models import RequestCreate
from arbiter.notify import Dispatcher, callback_allowed
from arbiter.notify.webhook import WebhookNotifier

AGENT = {"Authorization": "Bearer test-agent"}


class FakeSender:
    async def send(self, token, payload):
        return "sent"


def _client(cfg):
    db = Database(":memory:")
    app = create_app(cfg, db, FakeSender())
    c = TestClient(app)
    c.db = db
    return c


# ── callback_allowed unit ────────────────────────────────────────────────────

def test_empty_allowlist_allows_everything():
    assert callback_allowed([], "http://anything.example/x")


def test_cidr_entry_matches_ip_literal_hosts_only():
    al = ["10.0.0.0/8"]
    assert callback_allowed(al, "http://10.1.2.3:9/cb")
    assert not callback_allowed(al, "http://192.168.1.5/cb")
    assert not callback_allowed(al, "http://internal.example/cb")  # hostnames never match a CIDR


def test_url_pattern_entry():
    al = ["https://hooks.example/*"]
    assert callback_allowed(al, "https://hooks.example/agent-1")
    assert not callback_allowed(al, "https://evil.example/agent-1")
    assert not callback_allowed(al, "not a url")


# ── create-time enforcement ──────────────────────────────────────────────────

def test_create_rejects_disallowed_callback(cfg):
    cfg.callback_allowlist = ["10.0.0.0/8"]
    client = _client(cfg)
    r = client.post("/v1/requests", headers=AGENT,
                    json={"title": "t", "callback_url": "http://192.168.1.5/cb"})
    assert r.status_code == 422
    assert r.json()["detail"] == "callback_url not in allowlist"
    ok = client.post("/v1/requests", headers=AGENT,
                     json={"title": "t", "callback_url": "http://10.0.0.9/cb"})
    assert ok.status_code == 200


# ── dispatch-time enforcement ────────────────────────────────────────────────

def _decided_request(db, url):
    req = db.create_request(RequestCreate(title="t", callback_url=url))
    return db.set_decision(req["id"], "approve", "tester")


def test_dispatch_skips_disallowed_callback_and_audits(cfg):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200)
    cfg.callback_allowlist = ["10.0.0.0/8"]
    db = Database(":memory:")
    disp = Dispatcher(cfg, db, sender=FakeSender(),
                      transport=httpx.MockTransport(handler))
    req = _decided_request(db, "http://192.168.1.5/cb")
    asyncio.run(disp.request_decided(req))
    assert calls == []
    rows = [a for a in db.get_audit(req["id"]) if a["event"] == "notify_failed"]
    assert rows and "allowlist" in rows[0]["detail"]


def test_legacy_open_callback_warns_once_and_delivers(cfg, caplog):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200)
    cfg.callback_allowlist = []
    db = Database(":memory:")
    disp = Dispatcher(cfg, db, sender=FakeSender(),
                      transport=httpx.MockTransport(handler))
    with caplog.at_level(logging.WARNING, logger="arbiter.notify"):
        asyncio.run(disp.request_decided(_decided_request(db, "http://192.168.1.5/cb")))
        asyncio.run(disp.request_decided(_decided_request(db, "http://192.168.1.5/cb")))
    warnings = [r for r in caplog.records if "callback_allowlist" in r.getMessage()]
    assert len(warnings) == 1          # one-time warning
    assert len(calls) == 2             # legacy behavior: still delivered


def test_callback_redirects_not_followed():
    def handler(request):
        if request.url.path == "/redir":
            return httpx.Response(302, headers={"location": "http://10.0.0.9/elsewhere"})
        raise AssertionError("redirect was followed")
    n = WebhookNotifier(WebhookCfg(url="", secret=""),
                        transport=httpx.MockTransport(handler), sleeps=())
    ok = asyncio.run(n.deliver("http://10.0.0.9/redir", "request.decided", {"id": "x"}))
    assert ok is False                 # 3xx is a delivery failure, never followed


# ── /health readiness ────────────────────────────────────────────────────────

def test_health_pings_db(cfg):
    client = _client(cfg)
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True, "db": True}


def test_health_503_when_db_closed(cfg):
    client = _client(cfg)
    client.db.conn.close()
    r = client.get("/health")
    assert r.status_code == 503 and r.json() == {"ok": False, "db": False}

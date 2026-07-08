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

from tests.conftest import build_registry_env

AGENT = {"Authorization": "Bearer test-agent"}

# C1 migration (task-C1-brief): create_app now takes (cfg, registry, control);
# require_role reads request.app.state.db, removed per §15.1 — so every route
# behind it 500s/errors until ported per-cell (Groups C4-C8). Assertions below
# are unchanged; xfail(strict=False) documents the expected breakage. /health
# is rewritten in C1 to resolve the default cell directly, so it keeps
# passing genuinely (no xfail needed on the two health tests below).
_API_XFAIL = pytest.mark.xfail(
    reason="require_role reads app.state.db, removed per C1 §15.1; ported per-cell in C4-C8",
    strict=False)


class FakeSender:
    async def send(self, token, payload):
        return "sent"


def _client(cfg, tmp_path):
    sender = FakeSender()
    env = build_registry_env(cfg, tmp_path, sender=sender)
    app = create_app(cfg, env.registry, env.control, sender=sender)
    c = TestClient(app)
    c.db = env.default_db
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


def test_url_pattern_host_literal_and_scheme_must_match():
    al = ["https://hooks.example.com/*"]
    assert callback_allowed(al, "https://hooks.example.com/webhook")
    # a whole-string glob would let "*" cross "/" onto a path segment that
    # merely *contains* the literal host string — must not match.
    assert not callback_allowed(al, "https://evil.com/hooks.example.com/x")
    assert not callback_allowed(al, "http://hooks.example.com/x")  # scheme differs


def test_cidr_entry_ignores_userinfo_trick():
    al = ["10.0.0.0/8"]
    assert callback_allowed(al, "http://10.1.2.3:8080/path")
    # "10.0.0.9@evil.com" is userinfo, not host — urlparse().hostname is
    # "evil.com", which is not an IP literal and must not match the CIDR.
    assert not callback_allowed(al, "http://10.0.0.9@evil.com/cb")
    assert not callback_allowed(al, "http://internal.example/cb")  # never DNS-resolved


def test_subdomain_wildcard_matches_parsed_hostname_only():
    # "*." matches subdomains of the literal host, taken from the PARSED
    # hostname — which can never contain a "/", closing the bypass below.
    # This implementation accepts any number of subdomain labels (e.g.
    # "deep.a.hooks.example.com"), not just a single label.
    al = ["https://*.hooks.example.com/*"]
    assert callback_allowed(al, "https://a.hooks.example.com/y")
    assert callback_allowed(al, "https://deep.a.hooks.example.com/y")
    # THE BYPASS: fnmatch-over-the-whole-URL let "*" cross "/" so this used
    # to match. The evil.com host must never satisfy a host-wildcard rule.
    assert not callback_allowed(al, "https://evil.com/.hooks.example.com/x")
    # suffix-append attack: this hostname merely ends with the literal
    # string, it is not a subdomain of hooks.example.com.
    assert not callback_allowed(al, "https://hooks.example.com.evil.com/x")


def test_url_pattern_path_glob_scoped_to_matched_authority():
    al = ["https://hooks.example.com/hooks/*"]
    assert callback_allowed(al, "https://hooks.example.com/hooks/abc")
    assert not callback_allowed(al, "https://hooks.example.com/other")


def test_malformed_port_fails_closed_not_uncaught():
    # urlparse().port raises ValueError (not caught by urlparse() itself) for
    # a non-numeric port — must fail closed, never propagate an exception.
    al = ["https://hooks.example.com/*"]
    assert not callback_allowed(al, "https://hooks.example.com:notaport/x")


def test_url_pattern_entry_ignores_userinfo_trick():
    # userinfo against a URL-PATTERN entry (not just CIDR): the parsed
    # hostname is evil.com, so the trusted-host rule must not match.
    al = ["https://hooks.example.com/*"]
    assert not callback_allowed(al, "https://a.hooks.example.com@evil.com/x")


def test_url_pattern_scheme_and_host_case_insensitive():
    al = ["https://hooks.example.com/*"]
    assert callback_allowed(al, "HTTPS://Hooks.Example.COM/x")


def test_url_pattern_port_matching_both_directions():
    al = ["https://hooks.example.com:8443/*"]
    assert callback_allowed(al, "https://hooks.example.com:8443/x")       # exact port matches
    assert not callback_allowed(al, "https://hooks.example.com:9999/x")   # wrong port rejected
    # an entry with NO port matches the trusted host on ANY port
    assert callback_allowed(["https://hooks.example.com/*"],
                            "https://hooks.example.com:8443/x")


# ── create-time enforcement ──────────────────────────────────────────────────

@_API_XFAIL
def test_create_rejects_disallowed_callback(cfg, tmp_path):
    cfg.callback_allowlist = ["10.0.0.0/8"]
    client = _client(cfg, tmp_path)
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

def test_health_pings_db(cfg, tmp_path):
    client = _client(cfg, tmp_path)
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True, "db": True}


def test_health_503_when_db_closed(cfg, tmp_path):
    # Multi-tenant note (C1): /health now resolves the DEFAULT CELL through
    # the registry, which opens its OWN Database connection onto the cell's
    # sqlite file — a different connection object than `client.db` (the
    # test's own handle onto the same file). Closing `client.db.conn` alone
    # no longer breaks a LATER connection to the same file (SQLite doesn't
    # care that some other handle closed), so the original "close the db"
    # failure simulation needs the per-cell equivalent: corrupt the file the
    # registry will open on its first (lazy) acquire. This preserves the
    # test's original intent — an unreachable/broken db -> 503 — rather than
    # xfailing a test that no longer represents a real breakage.
    client = _client(cfg, tmp_path)
    client.db.conn.close()
    (tmp_path / "cells" / "default" / "arbiter.sqlite3").write_bytes(b"not a sqlite file")
    r = client.get("/health")
    assert r.status_code == 503 and r.json() == {"ok": False, "db": False}

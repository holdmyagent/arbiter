import os
import threading
import time

import pytest
from click.testing import CliRunner
from arbiter.cli import main, _ask

def test_init_writes_config_and_refuses_overwrite(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.toml"
    monkeypatch.setenv("HMA_CONFIG", str(cfg_path))
    r = CliRunner().invoke(main, ["init"])
    assert r.exit_code == 0 and cfg_path.exists()
    assert oct(os.stat(cfg_path).st_mode & 0o777) == "0o600"
    text = cfg_path.read_text()
    assert "agent_token" in text and "dev-agent-token" not in text
    r2 = CliRunner().invoke(main, ["init"])
    assert r2.exit_code != 0
    assert CliRunner().invoke(main, ["init", "--force"]).exit_code == 0
    assert oct(os.stat(cfg_path).st_mode & 0o777) == "0o600"

def test_json_formatter_emits_parseable_lines():
    import json
    import logging
    from arbiter.cli import _JsonFormatter
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                            '%s - "%s %s" %d', ("127.0.0.1", "GET", "/health", 200), None)
    out = json.loads(_JsonFormatter().format(rec))
    assert out["logger"] == "uvicorn.access" and "GET /health" in out["msg"] and out["level"] == "INFO"

def test_gather_status_raises_on_bad_token(client):
    import httpx
    from arbiter.cli import _gather_status
    with pytest.raises(httpx.HTTPStatusError):
        _gather_status(client, "wrong-token")

def test_gather_status_happy(client, cfg, app_headers):
    from arbiter.cli import _gather_status
    out = _gather_status(client, cfg.auth.app_token)
    assert out["ok"] is True and out["devices"] == [] and out["pending"] == []

def test_ask_approved(client, cfg, app_headers):
    def approve_soon():
        time.sleep(0.3)
        rid = client.get("/v1/requests", headers=app_headers).json()[0]["id"]
        client.post(f"/v1/requests/{rid}/decision", headers=app_headers, json={"decision": "approve"})
    threading.Thread(target=approve_soon).start()
    code, decision = _ask(client, cfg.auth.agent_token, title="Deploy?",
                          severity="high", target="prod", ttl=30, description="")
    assert code == 0 and decision["status"] == "approved" and decision["target"] == "prod"

def test_ask_expired_is_exit_1(client, cfg):
    code, decision = _ask(client, cfg.auth.agent_token, title="x",
                          severity="low", target=None, ttl=1, description="")
    assert code == 1 and decision["status"] == "expired"

def test_ask_error_is_exit_2(cfg):
    import httpx
    dead = httpx.Client(base_url="http://127.0.0.1:1", timeout=0.2)
    code, decision = _ask(dead, cfg.auth.agent_token, title="x",
                          severity="low", target=None, ttl=5, description="")
    assert code == 2


def test_base_url_default_env_and_flag_precedence(cfg, monkeypatch):
    from arbiter.cli import _base_url
    monkeypatch.delenv("HMA_URL", raising=False)
    assert _base_url(None, cfg) == f"http://127.0.0.1:{cfg.server.port}"
    monkeypatch.setenv("HMA_URL", "http://env.example:9")
    assert _base_url(None, cfg) == "http://env.example:9"
    assert _base_url("http://flag.example:8", cfg) == "http://flag.example:8"


def test_ask_url_flag_reaches_http_client(monkeypatch, tmp_path):
    import httpx as _httpx
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.delenv("HMA_URL", raising=False)
    captured = {}
    real = _httpx.Client
    class Cap(real):
        def __init__(self, *a, **kw):
            captured["base_url"] = str(kw.get("base_url"))
            super().__init__(*a, **kw)
    monkeypatch.setattr(_httpx, "Client", Cap)
    r = CliRunner().invoke(main, ["ask", "t", "--url", "http://127.0.0.1:1"])
    assert captured["base_url"].rstrip("/") == "http://127.0.0.1:1"
    assert r.exit_code == 2            # unreachable → fail-closed error exit


def test_status_url_flag_used_in_error(monkeypatch, tmp_path):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.delenv("HMA_URL", raising=False)
    r = CliRunner().invoke(main, ["status", "--url", "http://127.0.0.1:1"])
    assert r.exit_code != 0 and "http://127.0.0.1:1" in r.output


def test_config_template_has_callback_allowlist():
    from arbiter.cli import CONFIG_TEMPLATE
    assert "callback_allowlist" in CONFIG_TEMPLATE


def test_cli_audit_export_writes_jsonl_file(client, cfg, tmp_path, app_headers, agent_headers):
    import json as _json
    from arbiter.cli import _audit_export
    rid = client.post("/v1/requests", headers=agent_headers, json={"title": "t"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers=app_headers, json={"decision": "approve"})
    out = tmp_path / "audit.jsonl"
    n = _audit_export(client, cfg.auth.app_token, "jsonl", str(out))
    lines = [_json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert n == len(lines) and n >= 3
    assert {"created", "approved", "verdict_issued"} <= {line["event"] for line in lines}


def test_cli_audit_export_unreachable_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.delenv("HMA_URL", raising=False)
    r = CliRunner().invoke(main, ["audit", "export", "--url", "http://127.0.0.1:1"])
    assert r.exit_code != 0 and "export failed" in r.output


# ── 0.7 S7: --payload-json ────────────────────────────────────────────────
class _Resp:
    """Minimal httpx.Response stand-in for the wire-body tests."""
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _CapturingClient:
    """Minimal httpx.Client stand-in: records every create body, then reports
    the request as already approved so _ask returns on its first poll."""
    def __init__(self):
        self.bodies = []

    def post(self, url, headers=None, json=None):
        self.bodies.append(json)
        return _Resp({"id": "r-1", "status": "pending"})

    def get(self, url, headers=None, params=None):
        return _Resp({"id": "r-1", "status": "approved"})


def test_ask_omits_payload_from_the_wire_body_when_the_flag_is_absent():
    """The default body must stay byte-for-byte what it has always been."""
    c = _CapturingClient()
    code, _ = _ask(c, "tok", title="t", severity="low", target=None, ttl=5, description="")
    assert code == 0
    assert set(c.bodies[0]) == {"title", "description", "severity", "target", "ttl_seconds"}


def test_ask_includes_payload_in_the_wire_body_when_given():
    c = _CapturingClient()
    payload = {"agent": "hermes", "tool": "skill_manage", "verb": "create"}
    code, _ = _ask(c, "tok", title="t", severity="low", target=None, ttl=5,
                   description="", payload=payload)
    assert code == 0
    assert c.bodies[0]["payload"] == payload


def test_ask_payload_reaches_the_created_request(client, cfg, app_headers):
    """End to end against the real server: the payload lands on the row and
    comes back on the read the caller polls."""
    payload = {"agent": "hermes", "tool": "skill_manage", "verb": "create",
               "args_preview": "{\"name\": \"web-scraper\"}"}

    def approve_soon():
        time.sleep(0.3)
        rid = client.get("/v1/requests", headers=app_headers).json()[0]["id"]
        client.post(f"/v1/requests/{rid}/decision", headers=app_headers,
                    json={"decision": "approve"})

    threading.Thread(target=approve_soon).start()
    code, decision = _ask(client, cfg.auth.agent_token, title="Hermes: skill_manage create",
                          severity="low", target=None, ttl=30, description="creates a skill",
                          payload=payload)
    assert code == 0
    assert decision["payload"] == payload
    assert client.db.get_request(decision["id"])["payload"] == payload


@pytest.mark.parametrize("bad", ["not json", '["list"]', '"a string"', "42", ""])
def test_ask_rejects_a_malformed_payload_before_posting_anything(bad, monkeypatch, tmp_path):
    """Fail-closed: exit 2 (the `ask` error code, not 1 = denied) and NOTHING is
    posted — a gate shelling out here blocks instead of filing a contentless ask."""
    import arbiter.cli as cli_mod

    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.delenv("HMA_URL", raising=False)
    calls = []
    monkeypatch.setattr(cli_mod, "_ask",
                        lambda *a, **kw: calls.append(kw) or (0, {"status": "approved"}))

    r = CliRunner().invoke(main, ["ask", "t", "--payload-json", bad])
    assert r.exit_code == 2, r.output
    assert ("--payload-json is not valid JSON" in r.output
            or "--payload-json must be a JSON object" in r.output)
    assert calls == []

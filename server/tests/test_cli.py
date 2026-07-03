import os
import threading
import time
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
    import pytest
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

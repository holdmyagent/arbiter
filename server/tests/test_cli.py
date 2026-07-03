import threading, time
from click.testing import CliRunner
from arbiter.cli import main, _ask

def test_init_writes_config_and_refuses_overwrite(tmp_path, monkeypatch):
    monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
    r = CliRunner().invoke(main, ["init"])
    assert r.exit_code == 0 and (tmp_path / "config.toml").exists()
    text = (tmp_path / "config.toml").read_text()
    assert "agent_token" in text and "dev-agent-token" not in text
    r2 = CliRunner().invoke(main, ["init"])
    assert r2.exit_code != 0
    assert CliRunner().invoke(main, ["init", "--force"]).exit_code == 0

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

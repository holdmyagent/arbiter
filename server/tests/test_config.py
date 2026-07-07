import pytest
from arbiter.config import Config

TOML = """
[server]
host = "0.0.0.0"
port = 9000
db_path = "/tmp/hma-test.sqlite3"
[auth]
agent_token = "a"
app_token = "b"
admin_password = "pw"
session_secret = "s3"
[notify.ntfy]
topic = "my-topic"
"""

def test_load_file_and_defaults(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(TOML)
    cfg = Config.load(str(p))
    assert cfg.server.port == 9000 and cfg.server.host == "0.0.0.0"
    assert cfg.ntfy.enabled and cfg.ntfy.url == "https://ntfy.sh"
    assert not cfg.webhook.enabled and not cfg.apns.configured

def test_missing_file_gives_defaults(tmp_path):
    cfg = Config.load(str(tmp_path / "nope.toml"))
    assert cfg.server.host == "127.0.0.1" and cfg.auth.agent_token == ""

def test_env_overrides(tmp_path, monkeypatch):
    p = tmp_path / "c.toml"
    p.write_text(TOML)
    monkeypatch.setenv("HMA_PORT", "7777")
    monkeypatch.setenv("HMA_NTFY_TOPIC", "over")
    monkeypatch.setenv("HMA_APNS_SANDBOX", "true")
    cfg = Config.load(str(p))
    assert cfg.server.port == 7777 and cfg.ntfy.topic == "over" and cfg.apns.sandbox is True

@pytest.mark.parametrize("field,val,frag", [
    ("agent_token", "", "agent_token"),
    ("agent_token", "dev-agent-token", "default"),
    ("app_token", "dev-app-token", "default"),
])
def test_validate_for_serve_refuses(tmp_path, field, val, frag):
    cfg = Config.load(str(tmp_path / "nope.toml"))
    cfg.auth.agent_token = "x"
    cfg.auth.app_token = "y"
    cfg.auth.admin_password = "pw"
    cfg.auth.session_secret = "s"
    setattr(cfg.auth, field, val)
    assert any(frag in p for p in cfg.validate_for_serve())

def test_validate_same_tokens(tmp_path):
    cfg = Config.load(str(tmp_path / "nope.toml"))
    cfg.auth.agent_token = cfg.auth.app_token = "same"
    cfg.auth.admin_password = "pw"
    cfg.auth.session_secret = "s"
    assert cfg.validate_for_serve()


def test_notify_severities_default_all_enabled(tmp_path):
    from arbiter.config import Config
    cfg = Config.load(str(tmp_path / "absent.toml"))
    assert cfg.notify_severities == {"low": True, "medium": True, "high": True, "critical": True}


def test_notify_severities_loaded_from_config(tmp_path):
    from arbiter.config import Config
    p = tmp_path / "config.toml"
    p.write_text('[notify.severities]\nlow = false\nmedium = true\n')
    cfg = Config.load(str(p))
    assert cfg.notify_severities == {"low": False, "medium": True, "high": True, "critical": True}


def test_notify_severities_ignores_unknown_keys(tmp_path):
    from arbiter.config import Config
    p = tmp_path / "config.toml"
    p.write_text('[notify.severities]\nbogus = false\nhigh = false\n')
    cfg = Config.load(str(p))
    assert "bogus" not in cfg.notify_severities
    assert cfg.notify_severities["high"] is False


def test_policy_defaults(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    assert cfg.policy.ttl_min_seconds == 30
    assert cfg.policy.ttl_max_seconds == 86400
    assert cfg.policy.approval_ttl_seconds == 600
    assert cfg.policy.rate_limit_per_minute == 30
    assert cfg.policy.deny_action_types == []
    assert cfg.policy.severity_floors == {}


def test_policy_approval_ttl_parsed(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[policy]\napproval_ttl_seconds = 120\n")
    cfg = Config.load(str(p))
    assert cfg.policy.approval_ttl_seconds == 120


def test_policy_ttl_clamps_parsed(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[policy]\nttl_min_seconds = 60\nttl_max_seconds = 3600\n")
    cfg = Config.load(str(p))
    assert cfg.policy.ttl_min_seconds == 60 and cfg.policy.ttl_max_seconds == 3600

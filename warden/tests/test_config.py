"""WardenConfig.load happy path + missing-file error."""
from pathlib import Path

import pytest

from hold_warden.config import ActionSpec, ConfigError, ParamSpec, WardenConfig

SAMPLE = '''
[warden]
name = "knossos-warden"
arbiter_url = "https://arbiter.tailnet.example:8000"
arbiter_token = "env:HMA_WARDEN_TOKEN"
arbiter_pubkey = "kid1:bm90LWEtcmVhbC1rZXk"
arbiter_tenant = "knossos"
bind = "127.0.0.1"
port = 8646
retention_days = 7

[agents.hermes]
token = "env:WARDEN_AGENT_HERMES"

[actions.restart_service]
adapter = "command"
severity = "high"
ttl_seconds = 300
description = "Restart a systemd unit on hermes"
argv = ["ssh", "-o", "BatchMode=yes", "kclear@hermes", "sudo", "systemctl", "restart", "{unit}"]
  [actions.restart_service.params.unit]
  type = "enum"
  values = ["nginx", "caddy", "holdmyagent-server"]

[actions.post_status]
adapter = "http"
severity = "medium"
url = "https://api.example.com/v1/status"
method = "POST"
body_template = '{"text": "{text}"}'
headers = { Authorization = "secret:api_bearer" }
  [actions.post_status.params.text]
  type = "string"
  max_len = 500
  pattern = "^[^\\\\x00-\\\\x08\\\\x0b\\\\x0c\\\\x0e-\\\\x1f]*$"

[actions.release_deploy_key]
adapter = "secret"
severity = "critical"
secret = "secret:deploy_key"

[secrets]
api_bearer = "cmd:rbw get api-bearer"
deploy_key = "file:/etc/warden/deploy_key"
'''


@pytest.fixture
def cfg(tmp_path: Path) -> WardenConfig:
    path = tmp_path / "warden.toml"
    path.write_text(SAMPLE, encoding="utf-8")
    return WardenConfig.load(path)


def test_load_warden_table(cfg: WardenConfig) -> None:
    assert cfg.warden_name == "knossos-warden"
    assert cfg.arbiter_url == "https://arbiter.tailnet.example:8000"
    assert cfg.arbiter_token_ref == "env:HMA_WARDEN_TOKEN"
    assert cfg.arbiter_pubkey == "kid1:bm90LWEtcmVhbC1rZXk"
    assert cfg.arbiter_tenant == "knossos"
    assert cfg.bind == "127.0.0.1"
    assert cfg.port == 8646
    assert cfg.retention_days == 7


def test_load_agents_and_secrets(cfg: WardenConfig) -> None:
    assert cfg.agents == {"hermes": "env:WARDEN_AGENT_HERMES"}
    assert cfg.secrets == {"api_bearer": "cmd:rbw get api-bearer",
                           "deploy_key": "file:/etc/warden/deploy_key"}


def test_load_command_action(cfg: WardenConfig) -> None:
    spec = cfg.actions["restart_service"]
    assert isinstance(spec, ActionSpec)
    assert spec.adapter == "command"
    assert spec.severity == "high"
    assert spec.ttl_seconds == 300
    assert spec.description == "Restart a systemd unit on hermes"
    assert spec.argv == ["ssh", "-o", "BatchMode=yes", "kclear@hermes",
                         "sudo", "systemctl", "restart", "{unit}"]
    unit = spec.params["unit"]
    assert isinstance(unit, ParamSpec)
    assert unit.type == "enum"
    assert unit.values == ["nginx", "caddy", "holdmyagent-server"]


def test_load_http_action(cfg: WardenConfig) -> None:
    spec = cfg.actions["post_status"]
    assert spec.adapter == "http"
    assert spec.url == "https://api.example.com/v1/status"
    assert spec.method == "POST"
    assert spec.body_template == '{"text": "{text}"}'
    assert spec.headers == {"Authorization": "secret:api_bearer"}
    assert spec.ttl_seconds == 300  # default
    text = spec.params["text"]
    assert text.type == "string"
    assert text.max_len == 500
    assert text.pattern is not None


def test_load_secret_action(cfg: WardenConfig) -> None:
    spec = cfg.actions["release_deploy_key"]
    assert spec.adapter == "secret"
    assert spec.severity == "critical"
    assert spec.secret == "secret:deploy_key"
    assert spec.params == {}


def test_load_missing_file_raises_actionable_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="hma-warden init"):
        WardenConfig.load(tmp_path / "nope.toml")


def test_pinned_and_tenant_parse(tmp_path):
    from hold_warden.config import WardenConfig
    import base64
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"acme:{hashlib.sha256(raw).hexdigest()[:8]}"
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    p = tmp_path / "warden.toml"
    p.write_text(f'''
[warden]
arbiter_url = "http://x"
arbiter_token = "env:HMA_WARDEN_TOKEN"
arbiter_pubkey = "{kid}:{x}"
arbiter_tenant = "acme"
name = "w"
[agents.default]
token = "env:A"
''')
    cfg = WardenConfig.load(p)
    assert cfg.arbiter_tenant == "acme"
    pinned = cfg.pinned()
    assert pinned == {kid: raw}


def test_pinned_rejects_malformed_key_bytes(tmp_path):
    """Ed25519 shape validation is eager: a config with garbage key bytes fails
    loudly here (at `pinned()`, called at startup) — never a bare ValueError
    deferred to the first verdict verification."""
    p = tmp_path / "warden.toml"
    p.write_text('''
[warden]
arbiter_url = "http://x"
arbiter_token = "env:HMA_WARDEN_TOKEN"
arbiter_pubkey = "acme:deadbeef:not-a-real-key"
arbiter_tenant = "acme"
name = "w"
[agents.default]
token = "env:A"
''')
    cfg = WardenConfig.load(p)
    with pytest.raises(ConfigError):
        cfg.pinned()


# --- 0.1.1: per-action cwd + env + exec_timeout_s on the command adapter ---

SAMPLE_WITH_ANTHROPIC = SAMPLE.replace(
    'deploy_key = "file:/etc/warden/deploy_key"',
    'deploy_key = "file:/etc/warden/deploy_key"\n'
    'anthropic_key = "env:TEST_ANTHROPIC_KEY"')

DISPATCH_ACTION = '''
[actions.dispatch_claude]
adapter = "command"
severity = "high"
ttl_seconds = 90
exec_timeout_s = 3600
description = "Dispatch claude on a coder-scratch repo"
argv = ["claude", "-p", "{task}"]
cwd = "/srv/agentwork/claude/{repo}"
env = { ANTHROPIC_API_KEY = "secret:anthropic_key" }
  [actions.dispatch_claude.params.repo]
  type = "enum"
  values = ["coder-scratch"]
  [actions.dispatch_claude.params.task]
  type = "string"
  max_len = 4000
'''


def test_load_command_action_with_cwd_and_env(tmp_path: Path) -> None:
    p = tmp_path / "warden.toml"
    p.write_text(SAMPLE_WITH_ANTHROPIC + DISPATCH_ACTION, encoding="utf-8")
    cfg = WardenConfig.load(p)
    spec = cfg.actions["dispatch_claude"]
    assert spec.cwd == "/srv/agentwork/claude/{repo}"
    assert spec.env == {"ANTHROPIC_API_KEY": "secret:anthropic_key"}
    assert spec.exec_timeout_s == 3600


def test_exec_timeout_s_defaults_to_none(tmp_path: Path) -> None:
    """Unset -> None, so service.py falls back to the global 60s EXEC_TIMEOUT_S
    and every pre-0.1.1 action keeps its old behaviour byte for byte."""
    p = tmp_path / "warden.toml"
    p.write_text(SAMPLE, encoding="utf-8")
    cfg = WardenConfig.load(p)
    assert cfg.actions["restart_service"].exec_timeout_s is None
    assert cfg.actions["restart_service"].cwd is None
    assert cfg.actions["restart_service"].env is None


def test_cwd_must_be_absolute(tmp_path: Path) -> None:
    p = tmp_path / "warden.toml"
    p.write_text(SAMPLE + '''
[actions.bad_cwd]
adapter = "command"
argv = ["echo", "hi"]
cwd = "relative/path"
''', encoding="utf-8")
    with pytest.raises(ConfigError, match="cwd must be an absolute path"):
        WardenConfig.load(p)


def test_cwd_param_must_be_enum_typed(tmp_path: Path) -> None:
    """A free-form string/int param used in cwd is a path-traversal vector
    (repo could be '../../etc') -- config load rejects it outright."""
    p = tmp_path / "warden.toml"
    p.write_text(SAMPLE + '''
[actions.bad_cwd_param]
adapter = "command"
argv = ["echo", "{repo}"]
cwd = "/srv/agentwork/{repo}"
  [actions.bad_cwd_param.params.repo]
  type = "string"
  max_len = 50
''', encoding="utf-8")
    with pytest.raises(ConfigError, match='cwd param .* must be type "enum"'):
        WardenConfig.load(p)


def test_env_value_must_reference_declared_secret(tmp_path: Path) -> None:
    p = tmp_path / "warden.toml"
    p.write_text(SAMPLE + '''
[actions.bad_env]
adapter = "command"
argv = ["echo", "hi"]
env = { SOME_KEY = "secret:nonexistent" }
''', encoding="utf-8")
    with pytest.raises(ConfigError, match="nonexistent"):
        WardenConfig.load(p)


def test_resolve_template_command_includes_cwd_and_env_names() -> None:
    spec = ActionSpec(
        name="dispatch_claude", adapter="command", severity="high", ttl_seconds=90,
        description="", argv=["claude", "-p", "{task}"], url=None, method=None,
        body_template=None, headers=None, secret=None,
        cwd="/srv/agentwork/claude/{repo}",
        env={"ANTHROPIC_API_KEY": "secret:anthropic_key"},
        exec_timeout_s=3600,
        params={"repo": ParamSpec(type="enum", values=["coder-scratch"]),
                "task": ParamSpec(type="string", max_len=4000)})
    resolved = spec.resolve_template({"repo": "coder-scratch", "task": "echo hi"})
    assert resolved["argv"] == ["claude", "-p", "echo hi"]
    assert resolved["cwd"] == "/srv/agentwork/claude/coder-scratch"
    assert resolved["env_names"] == ["ANTHROPIC_API_KEY"]
    assert "anthropic_key" not in str(resolved)  # secret VALUES/refs never in the hash doc

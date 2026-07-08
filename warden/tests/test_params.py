"""validate_params + resolve_template + load-time template rules."""
import hashlib
import json
from pathlib import Path

import pytest

from hold_warden.config import (
    ActionSpec,
    ConfigError,
    ParamSpec,
    ParamValidationError,
    WardenConfig,
)


def command_spec() -> ActionSpec:
    return ActionSpec(
        name="restart_service", adapter="command", severity="high", ttl_seconds=300,
        description="", argv=["systemctl", "restart", "{unit}"], url=None, method=None,
        body_template=None, headers=None, secret=None,
        params={"unit": ParamSpec(type="enum", values=["nginx", "caddy"])})


def http_spec() -> ActionSpec:
    return ActionSpec(
        name="post_status", adapter="http", severity="medium", ttl_seconds=300,
        description="", argv=None, url="https://api.example.com/v1/status",
        method="POST", body_template='{"text": "{text}"}',
        headers={"Authorization": "secret:api_bearer", "Content-Type": "application/json"},
        secret=None,
        params={"text": ParamSpec(type="string", max_len=500,
                                  pattern="^[^\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]*$")})


def secret_spec() -> ActionSpec:
    return ActionSpec(
        name="release_deploy_key", adapter="secret", severity="critical", ttl_seconds=300,
        description="", argv=None, url=None, method=None, body_template=None,
        headers=None, secret="secret:deploy_key", params={})


def int_spec() -> ActionSpec:
    return ActionSpec(
        name="scale_workers", adapter="command", severity="medium", ttl_seconds=300,
        description="", argv=["scale-tool", "{count}"], url=None, method=None,
        body_template=None, headers=None, secret=None,
        params={"count": ParamSpec(type="int", min=1, max=10)})


# --- validate_params ---

def test_enum_accepts_listed_value() -> None:
    command_spec().validate_params({"unit": "nginx"})  # no raise


def test_enum_rejects_unlisted_value() -> None:
    with pytest.raises(ParamValidationError, match="unit"):
        command_spec().validate_params({"unit": "rm -rf /"})


def test_unknown_param_rejected() -> None:
    with pytest.raises(ParamValidationError, match="unknown"):
        command_spec().validate_params({"unit": "nginx", "extra": "x"})


def test_missing_param_rejected() -> None:
    with pytest.raises(ParamValidationError, match="missing"):
        command_spec().validate_params({})


def test_string_max_len_enforced() -> None:
    with pytest.raises(ParamValidationError, match="max_len"):
        http_spec().validate_params({"text": "x" * 501})


def test_string_pattern_rejects_control_chars() -> None:
    with pytest.raises(ParamValidationError, match="pattern"):
        http_spec().validate_params({"text": "evil\x00payload"})


def test_string_pattern_accepts_clean_text() -> None:
    http_spec().validate_params({"text": "deploy done"})  # no raise


def test_int_range_enforced() -> None:
    spec = int_spec()
    spec.validate_params({"count": "5"})  # no raise
    with pytest.raises(ParamValidationError, match=">= 1"):
        spec.validate_params({"count": "0"})
    with pytest.raises(ParamValidationError, match="<= 10"):
        spec.validate_params({"count": "11"})
    with pytest.raises(ParamValidationError, match="integer"):
        spec.validate_params({"count": "ten"})


# --- resolve_template ---

def test_command_whole_element_substitution() -> None:
    resolved = command_spec().resolve_template({"unit": "nginx"})
    assert resolved == {"argv": ["systemctl", "restart", "nginx"]}


def test_http_resolved_shape_and_body_sha256() -> None:
    resolved = http_spec().resolve_template({"text": "deploy done"})
    expected_body = '{"text": "deploy done"}'
    assert resolved == {
        "method": "POST",
        "url": "https://api.example.com/v1/status",
        "header_names": ["Authorization", "Content-Type"],
        "body_sha256": hashlib.sha256(expected_body.encode("utf-8")).hexdigest(),
    }
    # cross-check against the http_post golden vector's pinned body hash
    assert resolved["body_sha256"] == (
        "5a435dff38ad22b81a3bd3ab981090a2610df729be73f13c7bfd0d146283e5a6")


def test_http_url_templating() -> None:
    spec = http_spec()
    spec.url = "https://api.example.com/v1/status/{channel}"
    spec.params["channel"] = ParamSpec(type="enum", values=["ops", "dev"])
    resolved = spec.resolve_template({"text": "deploy done", "channel": "ops"})
    assert resolved["url"] == "https://api.example.com/v1/status/ops"


def test_http_header_secret_refs_stay_references() -> None:
    spec = http_spec()
    resolved = spec.resolve_template({"text": "deploy done"})
    dumped = json.dumps(resolved)
    assert "secret:" not in dumped            # no refs in the resolved shape
    assert "api_bearer" not in dumped         # not even the secret's name
    assert resolved["header_names"] == ["Authorization", "Content-Type"]  # sorted names only
    assert spec.headers == {"Authorization": "secret:api_bearer",
                            "Content-Type": "application/json"}  # spec untouched


def test_http_without_body_template_hashes_none() -> None:
    spec = http_spec()
    spec.body_template = None
    spec.params = {}
    assert spec.resolve_template({})["body_sha256"] is None


def test_secret_resolved_is_name_reference_only() -> None:
    assert secret_spec().resolve_template({}) == {"secret": "deploy_key"}


# --- load-time template rules ---

BASE_TOML = '''
[warden]
name = "test-warden"
arbiter_url = "http://127.0.0.1:8000"
arbiter_token = "env:HMA_WARDEN_TOKEN"
arbiter_pubkey = "kid1:bm90LWEtcmVhbC1rZXk"
arbiter_tenant = "test-tenant"

[agents.test]
token = "env:WARDEN_AGENT_TEST"
'''


def load_toml(tmp_path: Path, body: str) -> WardenConfig:
    path = tmp_path / "warden.toml"
    path.write_text(BASE_TOML + body, encoding="utf-8")
    return WardenConfig.load(path)


def test_load_rejects_embedded_flag_interpolation(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="entire argv element"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "command"
argv = ["tool", "--unit={unit}"]
  [actions.bad.params.unit]
  type = "enum"
  values = ["nginx"]
''')


def test_load_rejects_undeclared_argv_param(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="undeclared param"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "command"
argv = ["tool", "{ghost}"]
''')


def test_load_rejects_undeclared_body_param(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="undeclared param"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "http"
url = "https://api.example.com/x"
method = "POST"
body_template = '{"text": "{ghost}"}'
''')


def test_load_rejects_command_without_argv(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="requires argv"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "command"
''')


def test_load_rejects_http_without_method(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="url and method"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "http"
url = "https://api.example.com/x"
''')


def test_load_rejects_secret_action_without_declared_secret(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="no 'ghost'"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "secret"
secret = "secret:ghost"
''')


def test_load_rejects_header_ref_to_missing_secret(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ghost"):
        load_toml(tmp_path, '''
[actions.bad]
adapter = "http"
url = "https://api.example.com/x"
method = "POST"
headers = { Authorization = "secret:ghost" }
''')


def test_load_accepts_whole_element_placeholder(tmp_path: Path) -> None:
    cfg = load_toml(tmp_path, '''
[actions.good]
adapter = "command"
argv = ["systemctl", "restart", "{unit}"]
  [actions.good.params.unit]
  type = "enum"
  values = ["nginx"]
''')
    assert cfg.actions["good"].argv == ["systemctl", "restart", "{unit}"]

"""Secret resolver tests. cmd: recipes run against the fake CLIs in tests/fakes/
(PATH-prepended) so no real secret manager is ever touched. Doctor output must
never contain a resolved value."""
import os
import subprocess
from pathlib import Path

import pytest

from hold_warden.secrets import DoctorResult, SecretResolutionError, doctor_check, resolve

FAKES = Path(__file__).parent / "fakes"


@pytest.fixture
def fake_clis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", f"{FAKES}:{os.environ['PATH']}")


# --- env: ---

def test_env_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_TEST_SECRET", "s3cret-value")
    assert resolve("env:WARDEN_TEST_SECRET") == "s3cret-value"


def test_env_unset_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_TEST_SECRET", raising=False)
    with pytest.raises(SecretResolutionError):
        resolve("env:WARDEN_TEST_SECRET")


# --- file: ---

def test_file_resolves_and_strips(tmp_path: Path) -> None:
    secret_file = tmp_path / "deploy_key"
    secret_file.write_text("s3cret-value\n", encoding="utf-8")
    secret_file.chmod(0o600)
    assert resolve(f"file:{secret_file}") == "s3cret-value"


def test_file_loose_mode_warns_but_resolves(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    secret_file = tmp_path / "deploy_key"
    secret_file.write_text("s3cret-value\n", encoding="utf-8")
    secret_file.chmod(0o644)
    with caplog.at_level("WARNING", logger="hold_warden.secrets"):
        assert resolve(f"file:{secret_file}") == "s3cret-value"
    assert any("0600" in rec.getMessage() for rec in caplog.records)
    assert all("s3cret-value" not in rec.getMessage() for rec in caplog.records)


def test_file_missing_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(SecretResolutionError):
        resolve(f"file:{tmp_path / 'nope'}")


# --- cmd: against the fake CLIs ---

@pytest.mark.parametrize("ref,expected", [
    ("cmd:rbw get api-bearer", "fake-rbw-secret-api-bearer"),
    ("cmd:op read op://homelab/api-bearer/credential", "fake-op-secret-api-bearer"),
    ("cmd:pass show homelab/api-bearer", "fake-pass-secret-api-bearer"),
    ("cmd:vault kv get -field=token secret/api-bearer", "fake-vault-secret-api-bearer"),
])
def test_cmd_recipes_resolve(fake_clis: None, ref: str, expected: str) -> None:
    assert resolve(ref) == expected


def test_cmd_bw_requires_session(fake_clis: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BW_SESSION", raising=False)
    with pytest.raises(SecretResolutionError) as excinfo:
        resolve("cmd:bw get password api-bearer")
    assert excinfo.value.reason == "exit 1"
    monkeypatch.setenv("BW_SESSION", "fake-session")
    assert resolve("cmd:bw get password api-bearer") == "fake-bw-secret-api-bearer"


def test_cmd_nonzero_exit_fails_closed(fake_clis: None) -> None:
    with pytest.raises(SecretResolutionError) as excinfo:
        resolve("cmd:rbw get unknown-entry")
    assert excinfo.value.reason == "exit 1"


def test_cmd_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="sleepy", timeout=10)
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SecretResolutionError) as excinfo:
        resolve("cmd:sleepy forever")
    assert excinfo.value.reason == "timeout"


def test_unknown_scheme_fails_closed() -> None:
    with pytest.raises(SecretResolutionError) as excinfo:
        resolve("vault:not-a-scheme")
    assert excinfo.value.reason == "unknown scheme"


# --- doctor_check: never a value, only ok (non-empty) / FAILED (<reason>) ---

def test_doctor_ok_never_contains_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_TEST_SECRET", "s3cret-value")
    result = doctor_check("env:WARDEN_TEST_SECRET")
    assert result == DoctorResult(ref_scheme="env", ok=True, detail="ok (non-empty)")
    assert "s3cret-value" not in result.detail


def test_doctor_cmd_failure_reports_exit_code(fake_clis: None) -> None:
    result = doctor_check("cmd:rbw get unknown-entry")
    assert result.ref_scheme == "cmd"
    assert result.ok is False
    assert result.detail == "FAILED (exit 1)"


def test_doctor_empty_output_reports_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty_secret"
    empty.write_text("\n", encoding="utf-8")
    empty.chmod(0o600)
    result = doctor_check(f"file:{empty}")
    assert result == DoctorResult(ref_scheme="file", ok=False, detail="FAILED (empty output)")

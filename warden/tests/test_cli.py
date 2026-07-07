"""CLI tests - CliRunner for init/doctor/hash against a stub arbiter;
serve gets a subprocess starts-and-binds test with immediate shutdown."""
from __future__ import annotations

import base64
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hold_warden.canonical import canonicalize
from hold_warden.cli import main


def _ed25519_x() -> str:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class StubArbiter:
    """Minimal HTTP arbiter: canned /v1/keys + /health on an ephemeral port."""

    def __init__(self):
        self.kid = "abcd1234"
        self.x = _ed25519_x()
        jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519",
                          "kid": self.kid, "x": self.x}]}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner):
                if inner.path == "/v1/keys":
                    body = json.dumps(jwks).encode()
                elif inner.path == "/health":
                    body = json.dumps({"ok": True, "db": True}).encode()
                else:
                    inner.send_response(404)
                    inner.end_headers()
                    return
                inner.send_response(200)
                inner.send_header("Content-Type", "application/json")
                inner.send_header("Content-Length", str(len(body)))
                inner.end_headers()
                inner.wfile.write(body)

            def log_message(inner, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def stub_arbiter():
    stub = StubArbiter()
    yield stub
    stub.close()


def _init(stub, tmp_path) -> Path:
    cfg_path = tmp_path / "warden.toml"
    res = CliRunner().invoke(main, ["init", "--arbiter-url", stub.url,
                                    "--config", str(cfg_path)])
    assert res.exit_code == 0, res.output
    return cfg_path


# ------------------------------------------------------------------ init

def test_init_scaffolds_config_and_prints_token_once(stub_arbiter, tmp_path):
    cfg_path = tmp_path / "warden.toml"
    result = CliRunner().invoke(main, ["init", "--arbiter-url", stub_arbiter.url,
                                       "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert oct(cfg_path.stat().st_mode & 0o777) == "0o600"
    text = cfg_path.read_text()
    assert f'arbiter_pubkey = "{stub_arbiter.kid}:{stub_arbiter.x}"' in text
    assert 'arbiter_token = "env:HMA_WARDEN_TOKEN"' in text
    assert "[actions.echo]" in text
    token_path = tmp_path / "agent.default.token"
    assert oct(token_path.stat().st_mode & 0o777) == "0o600"
    token = token_path.read_text().strip()
    assert len(token) == 64
    assert result.output.count(token) == 1   # printed exactly ONCE


def test_init_refuses_to_overwrite(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    again = CliRunner().invoke(main, ["init", "--arbiter-url", stub_arbiter.url,
                                      "--config", str(cfg_path)])
    assert again.exit_code != 0
    assert "refusing" in again.output


def test_init_fails_cleanly_when_arbiter_down(tmp_path):
    result = CliRunner().invoke(main, ["init", "--arbiter-url", "http://127.0.0.1:9",
                                       "--config", str(tmp_path / "warden.toml")])
    assert result.exit_code != 0
    assert not (tmp_path / "warden.toml").exists()


def test_init_secret_files_are_0600_under_permissive_umask(stub_arbiter, tmp_path):
    """Both secret-bearing files must be CREATED with 0600 (atomic at open),
    not chmod-ed after the fact - even under a permissive umask."""
    old_umask = os.umask(0o022)
    try:
        cfg_path = tmp_path / "warden.toml"
        result = CliRunner().invoke(main, ["init", "--arbiter-url", stub_arbiter.url,
                                           "--config", str(cfg_path)])
        assert result.exit_code == 0, result.output
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600
    token_path = tmp_path / "agent.default.token"
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600


# ------------------------------------------------------------------ hash

GREET_TOML = """
[actions.greet]
adapter = "command"
severity = "low"
ttl_seconds = 300
description = "greet someone"
argv = ["echo", "{word}"]

[actions.greet.params.word]
type = "enum"
values = ["hello", "goodbye"]
"""


def test_hash_echo_empty_params(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    result = CliRunner().invoke(main, ["hash", "echo", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    lines = result.output.strip().splitlines()
    expected_canonical, expected_hash = canonicalize(
        "echo", "command", {}, {"argv": ["echo", "warden-echo-ok"]},
        f"{socket.gethostname()}-warden")
    assert lines[-2] == expected_canonical
    assert lines[-1] == expected_hash
    assert '"params":{}' in lines[-2]   # empty params never key-dropped


def test_hash_with_params(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    cfg_path.write_text(cfg_path.read_text() + GREET_TOML)
    result = CliRunner().invoke(main, ["hash", "greet", "--config", str(cfg_path),
                                       "--param", "word=hello"])
    assert result.exit_code == 0, result.output
    lines = result.output.strip().splitlines()
    expected_canonical, expected_hash = canonicalize(
        "greet", "command", {"word": "hello"}, {"argv": ["echo", "hello"]},
        f"{socket.gethostname()}-warden")
    assert lines[-2] == expected_canonical
    assert lines[-1] == expected_hash


def test_hash_rejects_invalid_param(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    cfg_path.write_text(cfg_path.read_text() + GREET_TOML)
    result = CliRunner().invoke(main, ["hash", "greet", "--config", str(cfg_path),
                                       "--param", "word=nope"])
    assert result.exit_code != 0


def test_hash_unknown_action(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    result = CliRunner().invoke(main, ["hash", "nope", "--config", str(cfg_path)])
    assert result.exit_code != 0
    assert "unknown action" in result.output


# ---------------------------------------------------------------- doctor

def test_doctor_all_green_exits_zero(stub_arbiter, tmp_path, monkeypatch):
    cfg_path = _init(stub_arbiter, tmp_path)
    monkeypatch.setenv("HMA_WARDEN_TOKEN", "warden-token-value")
    result = CliRunner().invoke(main, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "ok (non-empty)" in result.output


def test_doctor_fails_on_unresolvable_ref_and_never_prints_values(
        stub_arbiter, tmp_path, monkeypatch):
    cfg_path = _init(stub_arbiter, tmp_path)
    monkeypatch.setenv("HMA_WARDEN_TOKEN", "sup3r-warden-secret")
    monkeypatch.delenv("DOES_NOT_EXIST_12345", raising=False)
    # [secrets] is the last table in the scaffold, so a plain key append lands there
    cfg_path.write_text(cfg_path.read_text()
                        + 'missing = "env:DOES_NOT_EXIST_12345"\n')
    result = CliRunner().invoke(main, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 1
    assert "FAILED" in result.output
    assert "sup3r-warden-secret" not in result.output   # values never printed


def test_doctor_fails_on_pinned_key_mismatch(stub_arbiter, tmp_path, monkeypatch):
    cfg_path = _init(stub_arbiter, tmp_path)
    monkeypatch.setenv("HMA_WARDEN_TOKEN", "warden-token-value")
    cfg_path.write_text(cfg_path.read_text().replace(
        f'"{stub_arbiter.kid}:', '"wrongkid:'))
    result = CliRunner().invoke(main, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 1
    assert "key mismatch" in result.output


def test_doctor_fails_when_arbiter_unreachable(stub_arbiter, tmp_path, monkeypatch):
    cfg_path = _init(stub_arbiter, tmp_path)
    monkeypatch.setenv("HMA_WARDEN_TOKEN", "warden-token-value")
    stub_arbiter.close()
    result = CliRunner().invoke(main, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 1


# ----------------------------------------------------------------- serve

def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_serve_starts_binds_and_shuts_down(stub_arbiter, tmp_path):
    cfg_path = _init(stub_arbiter, tmp_path)
    port = _free_port()
    cfg_path.write_text(cfg_path.read_text().replace(
        "port = 8646", f"port = {port}"))
    env = {**os.environ,
           "HMA_WARDEN_TOKEN": "warden-token-value",
           "HOLD_WARDEN_DATA_DIR": str(tmp_path / "data")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "hold_warden.cli", "serve",
         "--config", str(cfg_path)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 20
        while True:
            if proc.poll() is not None:
                raise AssertionError(f"serve exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break   # bound and accepting
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError("serve never bound its port")
                time.sleep(0.05)
        assert (tmp_path / "data" / "warden.sqlite3").exists()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

"""CLI tests - CliRunner for init/doctor/hash against a stub arbiter;
serve gets a subprocess starts-and-binds test with immediate shutdown."""
from __future__ import annotations

import base64
import json
import os
import socket
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

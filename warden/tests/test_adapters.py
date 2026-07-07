"""hold_warden.adapters — command + http execution adapters."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hold_warden.adapters import CommandResult, HttpResult, run_command, run_http


def test_echo_captures_stdout():
    r = run_command(["echo", "hello"], timeout_s=10)
    assert isinstance(r, CommandResult)
    assert r.exit_code == 0
    assert r.stdout_tail == "hello\n"
    assert r.stderr_tail == ""
    assert r.duration_ms >= 0


def test_false_reports_exit_code():
    r = run_command(["false"], timeout_s=10)
    assert r.exit_code == 1


def test_env_is_scrubbed_to_path_only(monkeypatch):
    monkeypatch.setenv("HMA_LEAK_CANARY", "if-you-see-this-the-env-leaked")
    r = run_command(["printenv"], timeout_s=10)
    assert "PATH=/usr/bin:/bin:/usr/local/bin" in r.stdout_tail
    assert "HMA_LEAK_CANARY" not in r.stdout_tail
    assert "HOME=" not in r.stdout_tail


def test_extra_env_is_added():
    r = run_command(["printenv"], timeout_s=10, extra_env={"HMA_MARKER": "xyz"})
    assert "HMA_MARKER=xyz" in r.stdout_tail
    assert "PATH=/usr/bin:/bin:/usr/local/bin" in r.stdout_tail


def test_tails_truncate_to_4096_chars_with_marker():
    r = run_command([sys.executable, "-c", "print('x' * 5000)"], timeout_s=30)
    assert r.exit_code == 0
    assert r.stdout_tail.startswith("…[truncated] ")
    assert r.stdout_tail.endswith("x" * 100 + "\n")
    assert len(r.stdout_tail) == len("…[truncated] ") + 4096


def test_stderr_tail_truncates_too():
    r = run_command([sys.executable, "-c", "import sys; sys.stderr.write('e' * 5000)"],
                    timeout_s=30)
    assert r.stderr_tail.startswith("…[truncated] ")
    assert len(r.stderr_tail) == len("…[truncated] ") + 4096


def test_exactly_4096_chars_not_truncated():
    r = run_command([sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
                    timeout_s=30)
    assert r.stdout_tail == "x" * 4096


def test_timeout_expired_propagates_to_caller():
    # Contract: run_command does NOT catch subprocess.TimeoutExpired — service.py
    # catches it and marks the proposal failed. This test costs ~1s of real time
    # because it drives an actual child-process timeout (subprocess has no
    # injectable clock); it is the only elapsed-time test in the warden suite.
    with pytest.raises(subprocess.TimeoutExpired):
        run_command(["sleep", "5"], timeout_s=1)


class _HttpTarget(BaseHTTPRequestHandler):
    """Local target server. /redirect 302s to /never-fetched, which records a hit —
    run_http must never follow it."""

    target_hit = False
    seen: list[dict] = []

    def _respond(self, status: int, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/never-fetched")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/never-fetched":
            _HttpTarget.target_hit = True
            self._respond(200, b"redirect target body")
        elif self.path == "/big":
            self._respond(200, b"y" * 3000)
        else:
            self._respond(200, b"hello body")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        _HttpTarget.seen.append({
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": self.rfile.read(length).decode(),
        })
        self._respond(201, b"created")

    def log_message(self, *args):
        pass


@pytest.fixture()
def http_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HttpTarget)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _HttpTarget.target_hit = False
    _HttpTarget.seen = []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_run_http_get_hashes_full_body(http_target):
    r = run_http("GET", f"{http_target}/ok", {}, None, timeout_s=10)
    assert isinstance(r, HttpResult)
    assert r.status == 200
    assert r.body_sha256 == hashlib.sha256(b"hello body").hexdigest()
    assert r.body_head == "hello body"


def test_run_http_post_sends_body_and_headers(http_target):
    r = run_http("POST", f"{http_target}/post",
                 {"Authorization": "Bearer s3cr3t", "Content-Type": "application/json"},
                 '{"text":"hi"}', timeout_s=10)
    assert r.status == 201
    sent = _HttpTarget.seen[-1]
    assert sent["body"] == '{"text":"hi"}'
    assert sent["headers"]["authorization"] == "Bearer s3cr3t"
    assert sent["headers"]["content-type"] == "application/json"


def test_run_http_never_follows_redirects(http_target):
    r = run_http("GET", f"{http_target}/redirect", {}, None, timeout_s=10)
    assert r.status == 302
    assert _HttpTarget.target_hit is False, "redirect must NOT be followed"
    # The hash covers the (empty) 302 body — never the redirect target's body.
    assert r.body_sha256 == hashlib.sha256(b"").hexdigest()


def test_run_http_body_head_is_first_1024_chars(http_target):
    r = run_http("GET", f"{http_target}/big", {}, None, timeout_s=10)
    assert len(r.body_head) == 1024
    assert r.body_head == "y" * 1024
    assert r.body_sha256 == hashlib.sha256(b"y" * 3000).hexdigest()

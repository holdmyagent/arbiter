"""hold_warden.adapters — command + http execution adapters."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hold_warden.adapters import CommandResult, run_command


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

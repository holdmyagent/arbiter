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

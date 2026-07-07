"""Execution adapters — the only warden code that touches the outside world.

run_command: subprocess.run with shell=False and a scrubbed environment
({"PATH": "/usr/bin:/bin:/usr/local/bin"} plus configured extras). It does NOT
catch subprocess.TimeoutExpired — the orchestrator (service.py) catches it and
marks the proposal failed with a receipt recording the attempt.

run_http: httpx with follow_redirects=False (a redirect is returned as-is,
never chased — the approved URL is the only URL ever fetched) and no retries.
"""
from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass

import httpx

_SCRUBBED_PATH = "/usr/bin:/bin:/usr/local/bin"
_TAIL_CHARS = 4096
_TRUNC_MARKER = "…[truncated] "


def _tail(text: str) -> str:
    if len(text) <= _TAIL_CHARS:
        return text
    return _TRUNC_MARKER + text[-_TAIL_CHARS:]


@dataclass
class CommandResult:
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    duration_ms: int


def run_command(argv: list[str], timeout_s: int,
                extra_env: dict[str, str] | None = None) -> CommandResult:
    env = {"PATH": _SCRUBBED_PATH} | (extra_env or {})
    start = time.monotonic()
    proc = subprocess.run(argv, shell=False, env=env, capture_output=True,
                          text=True, errors="replace", timeout=timeout_s)
    duration_ms = int((time.monotonic() - start) * 1000)
    return CommandResult(exit_code=proc.returncode, stdout_tail=_tail(proc.stdout),
                         stderr_tail=_tail(proc.stderr), duration_ms=duration_ms)


_HEAD_CHARS = 1024


@dataclass
class HttpResult:
    status: int
    body_sha256: str
    body_head: str


def run_http(method: str, url: str, headers: dict[str, str], body: str | None,
             timeout_s: int) -> HttpResult:
    with httpx.Client(follow_redirects=False, timeout=timeout_s) as client:
        resp = client.request(
            method, url, headers=headers,
            content=body.encode("utf-8") if body is not None else None,
        )
    return HttpResult(
        status=resp.status_code,
        body_sha256=hashlib.sha256(resp.content).hexdigest(),
        body_head=resp.text[:_HEAD_CHARS],
    )

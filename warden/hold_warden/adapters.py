"""Execution adapters — the only warden code that touches the outside world.

run_command: subprocess.run with shell=False and a scrubbed environment
({"PATH": "/usr/bin:/bin:/usr/local/bin"} plus configured extras). It does NOT
catch subprocess.TimeoutExpired — the orchestrator (service.py) catches it and
marks the proposal failed with a receipt recording the attempt.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

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

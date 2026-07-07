"""Secret reference resolvers: env:VAR, file:/path, cmd:<argv string>.

Resolution is lazy (at execution time). Resolved values NEVER appear in logs,
exception messages, DoctorResult.detail, canonical documents, or arbiter
payloads. Exception messages carry a short value-free `reason` code so
`hma-warden doctor` can report failures without leaking anything.
"""
from __future__ import annotations

import logging
import os
import shlex
import stat
import subprocess
from pathlib import Path
from typing import NamedTuple

log = logging.getLogger("hold_warden.secrets")


class SecretResolutionError(Exception):
    """A secret reference could not be resolved. `reason` is short and value-free."""

    def __init__(self, message: str, reason: str = "error"):
        super().__init__(message)
        self.reason = reason


class DoctorResult(NamedTuple):
    ref_scheme: str
    ok: bool
    detail: str  # only "ok (non-empty)" or "FAILED (<reason>)" — NEVER a value


def resolve(ref: str, timeout_s: int = 10) -> str:
    """Resolve a secret reference to its value. Raises SecretResolutionError."""
    if ref.startswith("env:"):
        return _resolve_env(ref[4:])
    if ref.startswith("file:"):
        return _resolve_file(ref[5:])
    if ref.startswith("cmd:"):
        return _resolve_cmd(ref[4:], timeout_s)
    raise SecretResolutionError(
        "secret ref must start with env:, file:, or cmd:", reason="unknown scheme")


def doctor_check(ref: str) -> DoctorResult:
    """Dry-run one resolver. detail never contains the resolved value."""
    scheme = ref.split(":", 1)[0] if ":" in ref else "?"
    try:
        resolve(ref)
    except SecretResolutionError as exc:
        return DoctorResult(ref_scheme=scheme, ok=False, detail=f"FAILED ({exc.reason})")
    return DoctorResult(ref_scheme=scheme, ok=True, detail="ok (non-empty)")


def _resolve_env(var: str) -> str:
    value = os.environ.get(var, "")
    if not value:
        raise SecretResolutionError(f"env var {var} is unset or empty", reason="unset or empty")
    return value


def _resolve_file(path_str: str) -> str:
    path = Path(path_str)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecretResolutionError(
            f"cannot read secret file {path}: {exc.strerror}", reason="unreadable") from exc
    if mode & 0o077:
        log.warning("secret file %s has mode %s; expected 0600 (run: chmod 600 %s)",
                    path, oct(mode), path)
    if not value:
        raise SecretResolutionError(f"secret file {path} is empty", reason="empty output")
    return value


def _resolve_cmd(cmdline: str, timeout_s: int) -> str:
    argv = shlex.split(cmdline)
    if not argv:
        raise SecretResolutionError("cmd: ref has an empty command", reason="empty command")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise SecretResolutionError(
            f"cmd {argv[0]} timed out after {timeout_s}s", reason="timeout") from exc
    except OSError as exc:
        raise SecretResolutionError(
            f"cmd {argv[0]} could not run: {exc.strerror}", reason="not runnable") from exc
    if proc.returncode != 0:
        # stderr is deliberately NOT included: vault CLIs may echo sensitive context.
        raise SecretResolutionError(
            f"cmd {argv[0]} exited {proc.returncode}", reason=f"exit {proc.returncode}")
    value = proc.stdout.strip()
    if not value:
        raise SecretResolutionError(
            f"cmd {argv[0]} produced empty output", reason="empty output")
    return value

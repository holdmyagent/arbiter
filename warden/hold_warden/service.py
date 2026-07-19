"""Orchestrator: the warden's propose -> poll -> verify -> consume -> execute machine.

Fail-closed contract (spec section 4.3): every failure path lands on a terminal
proposal status (denied | expired | failed); an adapter runs only after signature
verification, hash re-comparison, and a successful single-use consume. The daemon
never dies on a per-proposal error.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from hold_warden.adapters import run_command, run_http
from hold_warden.arbiter import (
    ArbiterAuthError,
    ArbiterClient,
    ArbiterConflict,
    ArbiterStale,
    ArbiterUnavailable,
)
from hold_warden.canonical import canonicalize
from hold_warden.config import ActionSpec, WardenConfig
from hold_warden.db import WardenDB
from hold_warden.secrets import SecretResolutionError, resolve
from hold_warden.verdict import VerdictError, VerdictVerifier

log = logging.getLogger("hold_warden.service")

EXEC_TIMEOUT_S = 60  # adapter execution timeout (command and http), seconds


class ProposeError(Exception):
    """Base class for propose-time validation failures (API maps these to 4xx)."""


class UnknownAgentError(ProposeError):
    pass


class UnknownActionError(ProposeError):
    pass


def _utcnow() -> datetime:
    """Module-level so tests can monkeypatch time (no sleeps in tests)."""
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime:
    ts = datetime.fromisoformat(str(value))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def _row_params(row: dict) -> dict:
    params = row["params"]
    return json.loads(params) if isinstance(params, str) else params


class Orchestrator:
    def __init__(self, cfg: WardenConfig, db: WardenDB, arbiter: ArbiterClient,
                 verifier: VerdictVerifier):
        self.cfg = cfg
        self.db = db
        self.arbiter = arbiter
        self.verifier = verifier

    # ------------------------------------------------------------- propose
    def propose(self, agent: str, action: str, params: dict[str, str],
                idempotency_key: str | None) -> dict:
        """Validate, canonicalize, create the arbiter request, persist the proposal.

        Returns the proposal row plus an "expires_at" key. Raises UnknownAgentError /
        UnknownActionError / ParamValidationError (API: 4xx) and ArbiterUnavailable /
        ArbiterAuthError (API: 502) - always with zero local side effects.
        """
        if agent not in self.cfg.agents:
            raise UnknownAgentError(f"unknown agent: {agent}")
        if idempotency_key is not None:
            existing = self.db.get_by_idem(agent, idempotency_key)
            if existing is not None:
                return self._with_expiry(existing)
        spec = self.cfg.actions.get(action)
        if spec is None:
            raise UnknownActionError(f"unknown action: {action}")
        spec.validate_params(params)  # raises ParamValidationError
        resolved = spec.resolve_template(params)
        canonical, action_hash = canonicalize(
            action, spec.adapter, params, resolved, self.cfg.warden_name)
        # The arbiter-side key is namespaced per agent and hashed so it always
        # fits the arbiter's 128-char idempotency_key cap (64 hex chars,
        # deterministic); when the agent supplied no key we send a fresh UUID
        # (equivalent to "no dedupe" server-side).
        arbiter_idem = (
            hashlib.sha256((agent + ":" + idempotency_key).encode()).hexdigest()
            if idempotency_key is not None else uuid4().hex)
        try:
            resp = self.arbiter.create_request(
                title=f"{self.cfg.warden_name}: {action}",
                description=spec.description,
                action_type=action,
                severity=spec.severity,
                ttl_seconds=spec.ttl_seconds,
                payload={"action": action, "params": params,
                         "warden": self.cfg.warden_name, "agent": agent},
                canonical_action=canonical,
                action_hash=action_hash,
                idempotency_key=arbiter_idem,
            )
        except ArbiterAuthError as exc:
            log.critical("arbiter rejected the warden token at propose "
                         "(rotate/fix the token, then restart): %s", exc)
            raise
        # ArbiterUnavailable propagates untouched: no side effects, API maps to 502.
        row = self.db.create_proposal(
            agent=agent, action=action, params=params, canonical=canonical,
            action_hash=action_hash, request_id=resp["id"],
            idempotency_key=idempotency_key)
        out = dict(row)
        out["expires_at"] = resp.get("expires_at")
        return out

    def _deadline(self, row: dict) -> datetime | None:
        """Local best-effort request deadline: created_at + configured ttl_seconds."""
        spec = self.cfg.actions.get(row["action"])
        if spec is None:
            return None
        return _parse_ts(row["created_at"]) + timedelta(seconds=spec.ttl_seconds)

    def _with_expiry(self, row: dict) -> dict:
        out = dict(row)
        deadline = self._deadline(row)
        out["expires_at"] = deadline.isoformat() if deadline else None
        return out

    # ---------------------------------------------------------------- tick
    def tick(self) -> None:
        """One poll pass over pending/executing proposals. Never raises."""
        for row in self.db.pending():
            try:
                self._advance(row)
            except Exception:  # noqa: BLE001 - the daemon must survive any row
                log.exception("tick: unexpected error on proposal %s", row["id"])
                self.db.set_status(row["id"], "failed", result={
                    "error": "internal warden error; see warden logs"})

    def _advance(self, row: dict) -> None:
        pid = row["id"]
        if row["status"] == "executing":
            # Crash recovery: the approval was consumed but the adapter outcome
            # is unknown. Never guess that an action ran - fail closed.
            self.db.set_status(pid, "failed", result={
                "error": "warden restarted during execution; outcome unknown"})
            return

        rid = row["request_id"]
        try:
            req = self.arbiter.get_request(rid)
        except ArbiterUnavailable:
            self._expire_if_overdue(row)
            return
        except ArbiterAuthError as exc:
            self._fail_auth(pid, "poll", exc)
            return
        if req["status"] == "pending":
            return  # keep polling; the arbiter's sweeper owns expiry

        try:
            jws = self.arbiter.get_verdict(rid)
        except ArbiterUnavailable:
            self._expire_if_overdue(row)
            return
        except ArbiterAuthError as exc:
            self._fail_auth(pid, "verdict fetch", exc)
            return

        try:
            verdict = self.verifier.verify(jws, rid, row["action_hash"])
        except VerdictError as exc:
            self.db.set_status(pid, "failed", result={
                "error": f"verdict verification failed: {exc}"})
            return

        receipt = {
            "request_id": rid,
            "action_hash": row["action_hash"],
            "decision": verdict.decision,
            "decided_at": verdict.decided_at,
            "verdict_jws": jws,
            "executed_at": None,
        }
        if verdict.decision == "denied":
            self.db.set_status(pid, "denied", receipt=receipt)
            return
        if verdict.decision == "expired":
            self.db.set_status(pid, "expired", receipt=receipt)
            return
        if verdict.decision != "approved":
            self.db.set_status(pid, "failed", result={
                "error": f"unrecognized verdict decision: {verdict.decision}"})
            return

        # Approved: re-canonicalize from the live registry and refuse on drift.
        spec = self.cfg.actions.get(row["action"])
        if spec is None:
            self.db.set_status(pid, "failed", result={
                "error": "action no longer in the warden registry"})
            return
        params = _row_params(row)
        resolved = spec.resolve_template(params)
        canonical, action_hash = canonicalize(
            row["action"], spec.adapter, params, resolved, self.cfg.warden_name)
        if canonical != row["canonical"] or action_hash != row["action_hash"]:
            self.db.set_status(pid, "failed", result={
                "error": "action drifted since approval (canonical/hash mismatch)"})
            return

        # Single-use consume: the point of no return.
        try:
            self.arbiter.consume(rid)
        except ArbiterConflict:
            self.db.set_status(pid, "failed", receipt=receipt, result={
                "error": "approval already consumed (replay refused)"})
            return
        except ArbiterStale:
            self.db.set_status(pid, "expired", receipt=receipt, result={
                "error": "approval exceeded its freshness window"})
            return
        except ArbiterUnavailable:
            return  # stay pending; retry consume next tick
        except ArbiterAuthError as exc:
            self._fail_auth(pid, "consume", exc)
            return

        self.db.set_status(pid, "executing")
        self._execute(pid, spec, params, resolved, receipt)

    def _fail_auth(self, pid: str, stage: str, exc: Exception) -> None:
        log.critical("arbiter rejected the warden token at %s for proposal %s "
                     "(rotate/fix the token, then restart): %s", stage, pid, exc)
        self.db.set_status(pid, "failed", result={
            "error": f"arbiter auth failure at {stage}: {exc}"})

    def _expire_if_overdue(self, row: dict) -> None:
        deadline = self._deadline(row)
        if deadline is None:
            self.db.set_status(row["id"], "failed", result={
                "error": "action no longer in the warden registry"})
            return
        if _utcnow() > deadline:
            self.db.set_status(row["id"], "expired", result={
                "error": "arbiter unreachable past the request deadline"})

    # ------------------------------------------------------------- execute
    def _execute(self, pid: str, spec: ActionSpec, params: dict,
                 resolved: dict, receipt: dict) -> None:
        receipt = dict(receipt)
        receipt["executed_at"] = _utcnow().isoformat()
        try:
            if spec.adapter == "command":
                res = run_command(resolved["argv"],
                                  timeout_s=spec.exec_timeout_s or EXEC_TIMEOUT_S,
                                  extra_env=self._resolve_env(spec.env or {}),
                                  cwd=resolved.get("cwd"))
                result = {"exit_code": res.exit_code,
                          "stdout_tail": res.stdout_tail,
                          "stderr_tail": res.stderr_tail,
                          "duration_ms": res.duration_ms}
            elif spec.adapter == "http":
                headers = self._resolve_headers(spec.headers or {})
                body = self._render_body(spec, params, resolved)
                res = run_http(resolved["method"], resolved["url"], headers,
                               body, timeout_s=EXEC_TIMEOUT_S)
                result = {"http_status": res.status,
                          "body_sha256": res.body_sha256,
                          "body_head": res.body_head}
            elif spec.adapter == "secret":
                result = {"secret": self._resolve_action_secret(spec)}
            else:
                self.db.set_status(pid, "failed", receipt=receipt, result={
                    "error": f"unknown adapter: {spec.adapter}"})
                return
        except SecretResolutionError as exc:
            self.db.set_status(pid, "failed", receipt=receipt, result={
                "error": f"secret resolution failed: {exc}"})
            return
        except Exception as exc:  # noqa: BLE001 - adapter timeout/spawn/etc.
            self.db.set_status(pid, "failed", receipt=receipt, result={
                "error": f"adapter error: {exc}"})
            return
        self.db.set_status(pid, "executed", result=result, receipt=receipt)

    def _resolve_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Header values are literals or 'secret:<name>' refs into [secrets]."""
        out: dict[str, str] = {}
        for name, value in headers.items():
            if value.startswith("secret:"):
                secret_name = value.split(":", 1)[1]
                if secret_name not in self.cfg.secrets:
                    raise SecretResolutionError(f"unknown secret name: {secret_name}")
                out[name] = resolve(self.cfg.secrets[secret_name])
            else:
                out[name] = value
        return out

    def _resolve_env(self, env: dict[str, str]) -> dict[str, str]:
        """Command env values are literals or 'secret:<name>' refs into [secrets].
        Resolved lazily at execution, exactly like header values: the resolved
        VALUE never enters the canonical document, the arbiter payload, the
        receipt, or a log line — only the sorted NAMES (resolve_template's
        env_names) are hash-bound."""
        out: dict[str, str] = {}
        for name, value in env.items():
            if value.startswith("secret:"):
                secret_name = value.split(":", 1)[1]
                if secret_name not in self.cfg.secrets:
                    raise SecretResolutionError(f"unknown secret name: {secret_name}")
                out[name] = resolve(self.cfg.secrets[secret_name])
            else:
                out[name] = value
        return out

    def _render_body(self, spec: ActionSpec, params: dict,
                     resolved: dict) -> str | None:
        """Re-render the body with literal whole-segment substitution (the same
        rule resolve_template's body_sha256 is defined over) and refuse to send
        anything whose hash differs from the approved body_sha256."""
        if spec.body_template is None:
            return None
        body = spec.body_template
        for key, value in params.items():
            body = body.replace("{" + key + "}", value)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if digest != resolved.get("body_sha256"):
            raise RuntimeError("rendered body does not match approved body_sha256")
        return body

    def _resolve_action_secret(self, spec: ActionSpec) -> str:
        ref_name = spec.secret or ""
        name = ref_name.split(":", 1)[1] if ref_name.startswith("secret:") else ref_name
        if name not in self.cfg.secrets:
            raise SecretResolutionError(f"unknown secret name: {name}")
        return resolve(self.cfg.secrets[name])

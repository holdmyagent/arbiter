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

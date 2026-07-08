"""Verdict verification — the warden's trust anchor.

The warden trusts ONLY locally pinned public-key bytes (from `hma-warden init`),
keyed by kid = f"{tenant_id}:{hash8}". A verdict must (a) carry a header kid that
is a LOCAL pin, (b) verify under that pin's bytes, (c) have aud == "hma-verdict:
{paired-tenant}" AND hma.tenant_id == paired-tenant — so a neighbour's verdict is
a loud rejection even if the raw keys ever coincide (§7, §15.8/9).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class VerdictError(Exception):
    """Raised on ANY verification failure. Callers must never execute after this."""


@dataclass
class Verdict:
    request_id: str
    action_hash: str | None
    decision: str
    decided_at: str
    approval_ttl_seconds: int


class VerdictVerifier:
    def __init__(self, pinned: dict[str, bytes], tenant_id: str, *, last_seq: int = 0):
        if not pinned:
            raise VerdictError("no pinned keys — run 'hma-warden init'")
        # Copy so adopt_rotation mutations do not alias the caller's dict.
        self._pinned: dict[str, bytes] = dict(pinned)
        self._tenant_id = tenant_id
        self._last_seq = last_seq
        self._audience = f"hma-verdict:{tenant_id}"

    def _pubkey(self, kid: str) -> Ed25519PublicKey:
        raw = self._pinned.get(kid)
        if raw is None:
            raise VerdictError(f"verdict kid {kid!r} is not a locally pinned key")
        return Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, jws: str, expected_request_id: str,
               expected_action_hash: str | None) -> Verdict:
        try:
            header = jwt.get_unverified_header(jws)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"malformed verdict token: {exc}") from exc
        key = self._pubkey(header.get("kid"))       # LOCAL pin or VerdictError
        try:
            payload = jwt.decode(jws, key, algorithms=["EdDSA"], audience=self._audience)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"verdict signature/claims invalid: {exc}") from exc
        hma = payload.get("hma")
        if not isinstance(hma, dict):
            raise VerdictError("verdict missing 'hma' claim")
        if hma.get("tenant_id") != self._tenant_id:
            raise VerdictError(
                f"verdict tenant_id {hma.get('tenant_id')!r} != paired {self._tenant_id!r}")
        try:
            v = Verdict(
                request_id=hma["request_id"],
                action_hash=hma["action_hash"],
                decision=hma["decision"],
                decided_at=hma["decided_at"],
                approval_ttl_seconds=int(hma["approval_ttl_seconds"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VerdictError(f"verdict 'hma' claim malformed: {exc}") from exc
        if v.request_id != expected_request_id:
            raise VerdictError(
                f"verdict request_id {v.request_id!r} != expected {expected_request_id!r}")
        if v.action_hash != expected_action_hash:
            raise VerdictError(
                f"verdict action_hash {v.action_hash!r} != expected {expected_action_hash!r}")
        try:
            decided = datetime.fromisoformat(v.decided_at)
        except (TypeError, ValueError) as exc:
            raise VerdictError(f"verdict decided_at unparseable: {v.decided_at!r}") from exc
        if decided.tzinfo is None:
            decided = decided.replace(tzinfo=timezone.utc)
        if decided + timedelta(seconds=v.approval_ttl_seconds) < datetime.now(timezone.utc):
            raise VerdictError(
                f"verdict stale: decided_at {v.decided_at} + {v.approval_ttl_seconds}s passed")
        return v

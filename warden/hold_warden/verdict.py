"""Verdict verification — the warden's trust anchor.

The pinned arbiter public key is a "kid:b64url" string (kid = first 8 hex of
sha256(raw public bytes); b64url = unpadded base64url of the 32 raw Ed25519
public bytes — identical to the JWKS `x` value served at GET /v1/keys).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

AUDIENCE = "hma-verdict"


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
    def __init__(self, pubkey: str):
        try:
            kid, b64 = pubkey.split(":", 1)
            raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise VerdictError(
                f"invalid pinned arbiter_pubkey (expected 'kid:b64url'): {exc}") from exc
        self._kid = kid
        self._key = key

    def verify(self, jws: str, expected_request_id: str,
               expected_action_hash: str | None) -> Verdict:
        try:
            header = jwt.get_unverified_header(jws)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"malformed verdict token: {exc}") from exc
        if header.get("kid") != self._kid:
            raise VerdictError(
                f"verdict kid {header.get('kid')!r} does not match pinned kid {self._kid!r}")
        try:
            payload = jwt.decode(jws, self._key, algorithms=["EdDSA"], audience=AUDIENCE)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"verdict signature/claims invalid: {exc}") from exc
        hma = payload.get("hma")
        if not isinstance(hma, dict):
            raise VerdictError("verdict missing 'hma' claim")
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
                f"verdict stale: decided_at {v.decided_at} + {v.approval_ttl_seconds}s has passed")
        return v

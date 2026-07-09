"""Verdict verification — the warden's trust anchor.

The warden trusts ONLY locally pinned public-key bytes (from `hma-warden init`),
keyed by kid = f"{tenant_id}:{hash8}". A verdict must (a) carry a header kid that
is a LOCAL pin, (b) verify under that pin's bytes, (c) have aud == "hma-verdict:
{paired-tenant}" AND hma.tenant_id == paired-tenant — so a neighbour's verdict is
a loud rejection even if the raw keys ever coincide (§7, §15.8/9).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROTATION_AUD_PREFIX = "hma-rotation:"


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

    @property
    def pinned(self) -> dict[str, bytes]:
        """Read-only view of the local trust anchor: kid -> raw public-key
        bytes, including any kids adopted via adopt_rotation (§16)."""
        return dict(self._pinned)

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

    def adopt_rotation(self, record_jws: str, served_jwks: dict) -> str:
        """Adopt the new kid iff the record verifies under a LOCAL pin, carries
        tenant_id == paired, has seq strictly > last adopted, is not past
        expires_at, and its new key bytes appear in the served set (candidate
        material only). The old key stays pinned — retirement is a separate signed
        event, never inferred from a key's absence (§7). Returns the adopted kid."""
        try:
            header = jwt.get_unverified_header(record_jws)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"malformed rotation record: {exc}") from exc
        key = self._pubkey(header.get("kid"))       # must be a LOCAL pin
        try:
            payload = jwt.decode(record_jws, key, algorithms=["EdDSA"],
                                 audience=f"{ROTATION_AUD_PREFIX}{self._tenant_id}")
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"rotation record signature/claims invalid: {exc}") from exc
        hma = payload.get("hma")
        if not isinstance(hma, dict):
            raise VerdictError("rotation record missing 'hma' claim")
        if hma.get("tenant_id") != self._tenant_id:
            raise VerdictError(
                f"rotation tenant_id {hma.get('tenant_id')!r} != paired {self._tenant_id!r}")
        try:
            new_kid = str(hma["new_kid"])
            new_x = str(hma["new_x"])
            seq = int(hma["seq"])
            expires_at = int(hma["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VerdictError(f"rotation 'hma' claim malformed: {exc}") from exc
        if seq <= self._last_seq:
            raise VerdictError(f"rotation seq {seq} <= last adopted {self._last_seq}")
        if expires_at < int(datetime.now(timezone.utc).timestamp()):
            raise VerdictError("rotation record expired")
        served = {k.get("kid"): k.get("x") for k in served_jwks.get("keys", [])}
        if served.get(new_kid) != new_x:
            raise VerdictError(
                "new key not present in served /v1/keys set (candidate material required)")
        # Eager Ed25519 shape validation: fail loudly here, never as a bare
        # ValueError deferred to the first verify() against this new pin.
        try:
            raw = base64.urlsafe_b64decode(new_x + "=" * (-len(new_x) % 4))
            Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise VerdictError(f"rotation record new key bytes invalid: {exc}") from exc
        self._pinned[new_kid] = raw
        self._last_seq = seq
        return new_kid

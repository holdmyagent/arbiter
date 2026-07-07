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
        kid, b64 = pubkey.split(":", 1)
        raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        self._kid = kid
        self._key = Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, jws: str, expected_request_id: str,
               expected_action_hash: str | None) -> Verdict:
        payload = jwt.decode(jws, self._key, algorithms=["EdDSA"], audience=AUDIENCE)
        hma = payload["hma"]
        return Verdict(
            request_id=hma["request_id"],
            action_hash=hma["action_hash"],
            decision=hma["decision"],
            decided_at=hma["decided_at"],
            approval_ttl_seconds=int(hma["approval_ttl_seconds"]),
        )

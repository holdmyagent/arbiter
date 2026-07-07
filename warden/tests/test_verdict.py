"""hold_warden.verdict — the warden's trust anchor.

The signing helpers here mirror the arbiter's signing contract exactly
(Ed25519 / EdDSA JWS, headers={"kid": kid}, payload {"iss":"hma",
"aud":"hma-verdict","jti":request_id,"iat":now,"hma":{...}}), so these tests
stand in for a real arbiter without any network or server code.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import Verdict, VerdictError, VerdictVerifier


def _keypair() -> tuple[Ed25519PrivateKey, str, str]:
    """Returns (private_key, kid, pinned) where pinned = "kid:b64url" exactly as
    `hma-warden init` stores it: kid = first 8 hex chars of sha256(raw public
    bytes); b64url = unpadded base64url of the 32 raw public bytes."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = hashlib.sha256(raw).hexdigest()[:8]
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return key, kid, f"{kid}:{b64}"


def _sign(key: Ed25519PrivateKey, kid: str, *, request_id: str, action_hash: str | None,
          decision: str = "approved", decided_at: str | None = None,
          approval_ttl_seconds: int = 600, aud: str = "hma-verdict") -> str:
    """Mirror of the arbiter's sign_verdict() output (PIN Task 14)."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma",
        "aud": aud,
        "jti": request_id,
        "iat": int(now.timestamp()),
        "hma": {
            "request_id": request_id,
            "action_hash": action_hash,
            "decision": decision,
            "decided_at": decided_at or now.isoformat(),
            "approval_ttl_seconds": approval_ttl_seconds,
        },
    }
    return jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": kid})


def test_valid_bound_verdict_round_trip():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="a1" * 32)
    v = VerdictVerifier(pinned).verify(token, "rid-1", "a1" * 32)
    assert isinstance(v, Verdict)
    assert v.request_id == "rid-1"
    assert v.action_hash == "a1" * 32
    assert v.decision == "approved"
    assert v.approval_ttl_seconds == 600
    datetime.fromisoformat(v.decided_at)  # decided_at is a parseable ISO timestamp


def test_valid_unbound_verdict_action_hash_none():
    # Cooperative-tier requests (plain SDK / hma ask) have action_hash = null;
    # the verdict signs action_hash: null and the warden expects None.
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-2", action_hash=None, decision="denied")
    v = VerdictVerifier(pinned).verify(token, "rid-2", None)
    assert v.action_hash is None
    assert v.decision == "denied"

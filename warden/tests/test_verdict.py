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


def test_wrong_key_rejected():
    key1, kid1, pinned = _keypair()
    key2, _, _ = _keypair()
    # Signed by the WRONG private key but carrying the pinned kid in the header.
    token = _sign(key2, kid1, request_id="rid-1", action_hash="h1")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_kid_header_mismatch_rejected():
    key, _, pinned = _keypair()
    # Signed by the RIGHT key but claiming a foreign kid — must still be refused.
    token = _sign(key, "deadbeef", request_id="rid-1", action_hash="h1")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_tampered_payload_rejected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1", decision="denied")
    header, payload, sig = token.split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["hma"]["decision"] = "approved"  # flip the decision, keep the old signature
    forged = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(f"{header}.{forged}.{sig}", "rid-1", "h1")


def test_alg_confusion_hs256_rejected():
    # Classic key-confusion attack: HMAC-sign the token using the PUBLIC key
    # material as the shared secret. algorithms=["EdDSA"] must refuse it.
    key, kid, pinned = _keypair()
    b64_pub = pinned.split(":", 1)[1]
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma", "aud": "hma-verdict", "jti": "rid-1", "iat": int(now.timestamp()),
        "hma": {"request_id": "rid-1", "action_hash": "h1", "decision": "approved",
                "decided_at": now.isoformat(), "approval_ttl_seconds": 600},
    }
    token = jwt.encode(payload, b64_pub, algorithm="HS256", headers={"kid": kid})
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_wrong_audience_rejected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1", aud="not-hma-verdict")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_garbage_token_rejected():
    _, _, pinned = _keypair()
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify("not-a-jws", "rid-1", "h1")


def test_malformed_pinned_key_rejected():
    with pytest.raises(VerdictError):
        VerdictVerifier("missing-colon-and-not-base64")


def test_wrong_request_id_rejected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-OTHER", action_hash="h1")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_wrong_action_hash_rejected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="h-OTHER")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_bound_verdict_rejected_when_unbound_expected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", None)


def test_unbound_verdict_rejected_when_hash_expected():
    # A verdict signing action_hash: null must never authorize a hash-bound action.
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash=None)
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_stale_verdict_rejected():
    # No sleeping: staleness is driven by signing an already-old decided_at.
    key, kid, pinned = _keypair()
    old = (datetime.now(timezone.utc) - timedelta(seconds=700)).isoformat()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1",
                  decided_at=old, approval_ttl_seconds=600)
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")


def test_old_but_within_ttl_accepted():
    key, kid, pinned = _keypair()
    old = (datetime.now(timezone.utc) - timedelta(seconds=500)).isoformat()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1",
                  decided_at=old, approval_ttl_seconds=600)
    v = VerdictVerifier(pinned).verify(token, "rid-1", "h1")
    assert v.decided_at == old


def test_unparseable_decided_at_rejected():
    key, kid, pinned = _keypair()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1", decided_at="yesterday-ish")
    with pytest.raises(VerdictError):
        VerdictVerifier(pinned).verify(token, "rid-1", "h1")

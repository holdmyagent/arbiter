"""hold_warden.verdict — the warden's trust anchor.

The signing helpers here mirror the arbiter's tenant-bound signing contract
exactly (Ed25519 / EdDSA JWS, headers={"kid": kid}, payload {"iss":"hma",
"aud":"hma-verdict:{tenant}","jti":request_id,"iat":now,
"hma":{"tenant_id":tenant,...}}), so these tests stand in for a real arbiter
without any network or server code.
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

TENANT = "acme"


def _keypair(tenant: str = TENANT):
    """Returns (key, kid, raw_pub_bytes). kid = f"{tenant}:{hash8}"."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"{tenant}:{hashlib.sha256(raw).hexdigest()[:8]}"
    return key, kid, raw


def _sign(key, kid, *, request_id, action_hash, tenant=TENANT, decision="approved",
          decided_at=None, approval_ttl_seconds=600, aud=None):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma",
        "aud": aud if aud is not None else f"hma-verdict:{tenant}",
        "jti": request_id,
        "iat": int(now.timestamp()),
        "hma": {
            "tenant_id": tenant,
            "request_id": request_id,
            "action_hash": action_hash,
            "decision": decision,
            "decided_at": decided_at or now.isoformat(),
            "approval_ttl_seconds": approval_ttl_seconds,
        },
    }
    return jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": kid})


def test_valid_bound_verdict_round_trip():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash="a1" * 32)
    out = v.verify(token, "rid-1", "a1" * 32)
    assert isinstance(out, Verdict)
    assert out.request_id == "rid-1" and out.action_hash == "a1" * 32


def test_unbound_action_hash_none():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-2", action_hash=None, decision="denied")
    assert v.verify(token, "rid-2", None).action_hash is None


def test_wrong_key_rejected_even_with_pinned_kid():
    key1, kid1, raw1 = _keypair()
    key2, _, _ = _keypair()
    v = VerdictVerifier({kid1: raw1}, TENANT)
    token = _sign(key2, kid1, request_id="rid-3", action_hash=None)  # wrong key, pinned kid
    with pytest.raises(VerdictError):
        v.verify(token, "rid-3", None)


def test_unpinned_kid_rejected():
    key, kid, raw = _keypair()
    other_key, other_kid, _ = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(other_key, other_kid, request_id="rid-4", action_hash=None)
    with pytest.raises(VerdictError):
        v.verify(token, "rid-4", None)


def test_cross_tenant_rejected_even_with_forced_identical_key():
    # THE §16 gate: tenant A's verdict, verified by tenant B's warden that has
    # FORCED the identical key bytes under ITS OWN kid namespace, still fails
    # on aud/tenant_id — genuinely at that gate, not at kid lookup (the kid
    # IS a valid local pin for warden B, so _pubkey() succeeds first).
    key, hash8_kid_a, raw = _keypair(tenant="acme")
    # Warden B pins the SAME raw bytes but under a beta-namespaced kid & tenant.
    kid_b = f"beta:{hash8_kid_a.split(':', 1)[1]}"
    vb = VerdictVerifier({kid_b: raw}, "beta")
    token = _sign(key, kid_b, request_id="rid-5", action_hash=None, tenant="acme")
    with pytest.raises(VerdictError):
        vb.verify(token, "rid-5", None)


def test_claim_tenant_mismatch_rejected():
    # kid + key + aud all say acme, but the hma.tenant_id claim is forged to beta.
    key, kid, raw = _keypair(tenant="acme")
    v = VerdictVerifier({kid: raw}, "acme")
    now = datetime.now(timezone.utc)
    payload = {"iss": "hma", "aud": "hma-verdict:acme", "jti": "rid-6",
               "iat": int(now.timestamp()),
               "hma": {"tenant_id": "beta", "request_id": "rid-6", "action_hash": None,
                       "decision": "approved", "decided_at": now.isoformat(),
                       "approval_ttl_seconds": 600}}
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": kid})
    with pytest.raises(VerdictError):
        v.verify(token, "rid-6", None)


def test_no_pinned_keys_rejected():
    with pytest.raises(VerdictError):
        VerdictVerifier({}, TENANT)


def test_tampered_payload_rejected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-7", action_hash="h1", decision="denied")
    header, payload, sig = token.split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["hma"]["decision"] = "approved"  # flip the decision, keep the old signature
    forged = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    with pytest.raises(VerdictError):
        v.verify(f"{header}.{forged}.{sig}", "rid-7", "h1")


def test_alg_confusion_hs256_rejected():
    # Classic key-confusion attack: HMAC-sign the token using the PUBLIC key
    # material as the shared secret. algorithms=["EdDSA"] must refuse it.
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma", "aud": f"hma-verdict:{TENANT}", "jti": "rid-8",
        "iat": int(now.timestamp()),
        "hma": {"tenant_id": TENANT, "request_id": "rid-8", "action_hash": "h1",
                "decision": "approved", "decided_at": now.isoformat(),
                "approval_ttl_seconds": 600},
    }
    token = jwt.encode(payload, raw, algorithm="HS256", headers={"kid": kid})
    with pytest.raises(VerdictError):
        v.verify(token, "rid-8", "h1")


def test_wrong_audience_rejected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-9", action_hash="h1", aud="not-hma-verdict")
    with pytest.raises(VerdictError):
        v.verify(token, "rid-9", "h1")


def test_garbage_token_rejected():
    _, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    with pytest.raises(VerdictError):
        v.verify("not-a-jws", "rid-1", "h1")


def test_wrong_request_id_rejected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-OTHER", action_hash="h1")
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", "h1")


def test_wrong_action_hash_rejected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash="h-OTHER")
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", "h1")


def test_bound_verdict_rejected_when_unbound_expected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash="h1")
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", None)


def test_unbound_verdict_rejected_when_hash_expected():
    # A verdict signing action_hash: null must never authorize a hash-bound action.
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash=None)
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", "h1")


def test_stale_verdict_rejected():
    # No sleeping: staleness is driven by signing an already-old decided_at.
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    old = (datetime.now(timezone.utc) - timedelta(seconds=700)).isoformat()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1",
                  decided_at=old, approval_ttl_seconds=600)
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", "h1")


def test_old_but_within_ttl_accepted():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    old = (datetime.now(timezone.utc) - timedelta(seconds=500)).isoformat()
    token = _sign(key, kid, request_id="rid-1", action_hash="h1",
                  decided_at=old, approval_ttl_seconds=600)
    out = v.verify(token, "rid-1", "h1")
    assert out.decided_at == old


def test_unparseable_decided_at_rejected():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash="h1", decided_at="yesterday-ish")
    with pytest.raises(VerdictError):
        v.verify(token, "rid-1", "h1")

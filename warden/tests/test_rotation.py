from __future__ import annotations

import base64
import hashlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import VerdictVerifier

TENANT = "acme"


def _keypair(tenant: str = TENANT):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"{tenant}:{hashlib.sha256(raw).hexdigest()[:8]}"
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return key, kid, raw, x


def _record(old_key, old_kid, *, new_kid, new_x, seq, expires_at, tenant=TENANT, aud=None):
    payload = {"iss": "hma", "aud": aud if aud is not None else f"hma-rotation:{tenant}",
               "iat": int(time.time()),
               "hma": {"tenant_id": tenant, "new_kid": new_kid, "new_x": new_x,
                       "seq": seq, "expires_at": expires_at}}
    return jwt.encode(payload, old_key, algorithm="EdDSA", headers={"kid": old_kid})


def _served(*jwks_entries):
    return {"keys": list(jwks_entries)}


def _jwk(kid, x):
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x}


def test_adopt_valid_record_adds_new_kid_and_bumps_seq():
    ok, okid, oraw, ox = _keypair()
    nk, nkid, nraw, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    served = _served(_jwk(okid, ox), _jwk(nkid, nx))
    assert v.adopt_rotation(rec, served) == nkid
    # New key is now pinned: a verdict signed by it verifies; the OLD key remains pinned too.
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    payload = {"iss": "hma", "aud": "hma-verdict:acme", "jti": "r", "iat": int(now.timestamp()),
               "hma": {"tenant_id": "acme", "request_id": "r", "action_hash": None,
                       "decision": "approved", "decided_at": now.isoformat(),
                       "approval_ttl_seconds": 600}}
    tok = jwt.encode(payload, nk, algorithm="EdDSA", headers={"kid": nkid})
    assert v.verify(tok, "r", None).decision == "approved"


def test_reject_record_signed_by_unpinned_served_key():
    ok, okid, oraw, ox = _keypair()      # pinned (old)
    rogue, rkid, rraw, rx = _keypair()   # NOT pinned — only present in served set
    nk, nkid, nraw, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(rogue, rkid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    served = _served(_jwk(okid, ox), _jwk(rkid, rx), _jwk(nkid, nx))
    with pytest.raises(Exception):
        v.adopt_rotation(rec, served)


def test_reject_older_or_equal_seq_replay():
    ok, okid, oraw, ox = _keypair()
    _, nkid1, _, nx1 = _keypair()
    _, nkid2, _, nx2 = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT, last_seq=5)
    for seq in (5, 4):
        rec = _record(ok, okid, new_kid=nkid1, new_x=nx1, seq=seq,
                      expires_at=int(time.time()) + 3600)
        with pytest.raises(Exception):
            v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid1, nx1)))


def test_reject_expired_record():
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) - 1)
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, nx)))


def test_reject_tenant_mismatch_record():
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1,
                  expires_at=int(time.time()) + 3600, tenant="beta", aud="hma-rotation:beta")
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, nx)))


def test_reject_new_x_absent_from_served_set():
    # Old-key absence / new-key absence is never a reason to adopt.
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox)))  # new kid not served


def test_reject_wrong_aud_with_correct_tenant_claim():
    # Isolates the aud check from the hma.tenant_id claim check: aud is wrong
    # while hma.tenant_id still says the correct paired tenant. jwt.decode's
    # audience check must reject this on its own, before the tenant_id claim
    # is even inspected (unlike test_reject_tenant_mismatch_record, which
    # corrupts aud AND tenant_id together and so doesn't isolate the gate).
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1,
                  expires_at=int(time.time()) + 3600,
                  tenant=TENANT, aud="hma-rotation:wrong-tenant")
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, nx)))


def test_reject_replay_of_identical_already_adopted_record():
    # Explicit replay: the literal SAME jws that was already adopted once,
    # resubmitted verbatim — not merely "a different record with an equal
    # seq" (that's test_reject_older_or_equal_seq_replay).
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    served = _served(_jwk(okid, ox), _jwk(nkid, nx))
    assert v.adopt_rotation(rec, served) == nkid
    with pytest.raises(Exception):
        v.adopt_rotation(rec, served)


def test_reject_new_key_bytes_invalid_shape():
    # Eager Ed25519 shape validation: a candidate new key that isn't a
    # 32-byte Ed25519 public key is rejected with a VerdictError at
    # adopt-time, never left to surface as a bare ValueError the first time
    # something tries to verify against it.
    from hold_warden.verdict import VerdictError
    ok, okid, oraw, ox = _keypair()
    nkid = f"{TENANT}:deadbeef"
    bad_x = base64.urlsafe_b64encode(b"too-short").rstrip(b"=").decode()
    rec = _record(ok, okid, new_kid=nkid, new_x=bad_x, seq=1,
                  expires_at=int(time.time()) + 3600)
    v = VerdictVerifier({okid: oraw}, TENANT)
    with pytest.raises(VerdictError):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, bad_x)))

"""§16 gate: the warden's rotation trust anchor is its LOCAL pin.

The warden adopts a new kid ONLY iff the rotation record verifies under a
LOCAL pin (never a served key), carries tenant_id == paired, has seq strictly
greater than the last adopted, and is not past expires_at (§15.9/§7). The
served /v1/keys set is candidate material only — it can supply the new key's
bytes for the eager-shape check, but it can never substitute for the local
pin that must sign the record.

Note on adopt_rotation's actual contract (verdict.py, D7): it returns the
adopted kid (str) on success and RAISES VerdictError on any rejection — it
does not return a bool. The reject-case assertions below use
`pytest.raises(VerdictError)` accordingly.
"""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import VerdictError, VerdictVerifier

from tests.isolation.conftest import (
    make_signer, make_rotation_record, served_jwks_for,
)


def _raw(signer):
    return signer.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _future() -> int:
    """Epoch-seconds expiry ~1h out (sign_rotation_record's expires_at is a
    Unix timestamp, not an ISO string — see arbiter/signing.py)."""
    return int(time.time()) + 3600


def _past() -> int:
    return int(time.time()) - 3600


def test_adopt_only_under_local_pin_tenant_and_monotonic_seq(tmp_path):
    old = make_signer("alice", tmp_path / "old")
    new = make_signer("alice", tmp_path / "new")
    verifier = VerdictVerifier(pinned={old.kid: _raw(old)}, tenant_id="alice")

    # BASELINE (adopt): record signed by the OLD (locally pinned) key, right
    # tenant, seq strictly greater than last-adopted (0), not expired.
    rec = make_rotation_record(old, new, tenant_id="alice", seq=1, expires_at=_future())
    served = served_jwks_for(old, new)
    adopted_kid = verifier.adopt_rotation(rec, served)
    assert adopted_kid == new.kid
    assert new.kid in verifier.pinned  # the new kid is now a local anchor

    # REJECT: replay / older-or-equal seq
    with pytest.raises(VerdictError):
        verifier.adopt_rotation(rec, served)  # seq 1 no longer > last (1)

    # REJECT: wrong tenant even if signed by the pinned old key
    newer = make_signer("alice", tmp_path / "newer")
    rec_wrong_tenant = make_rotation_record(old, newer, tenant_id="bob", seq=2,
                                            expires_at=_future())
    with pytest.raises(VerdictError):
        verifier.adopt_rotation(rec_wrong_tenant, served_jwks_for(old, newer))

    # REJECT: expired record
    rec_expired = make_rotation_record(old, newer, tenant_id="alice", seq=2,
                                       expires_at=_past())
    with pytest.raises(VerdictError):
        verifier.adopt_rotation(rec_expired, served_jwks_for(old, newer))

    # REJECT: record signed by a SERVED (not locally pinned) key — served set
    # is candidate material only, never a trust anchor.
    attacker = make_signer("alice", tmp_path / "attacker")
    rec_served_only = make_rotation_record(attacker, newer, tenant_id="alice", seq=2,
                                           expires_at=_future())
    served_with_attacker = served_jwks_for(old, new, attacker, newer)
    with pytest.raises(VerdictError):
        verifier.adopt_rotation(rec_served_only, served_with_attacker)


def test_served_entry_with_pinned_kid_but_wrong_bytes_rejected(tmp_path):
    old = make_signer("alice", tmp_path / "old")
    imposter = make_signer("alice", tmp_path / "imp")
    verifier = VerdictVerifier(pinned={old.kid: _raw(old)}, tenant_id="alice")
    new = make_signer("alice", tmp_path / "new")

    # A served entry claiming old.kid but carrying imposter bytes, alongside a
    # genuine entry for the new key (so the new-key-in-served check passes and
    # adoption proceeds purely on the strength of the LOCAL pin).
    forged_served = {"keys": [
        {"kty": "OKP", "crv": "Ed25519", "kid": old.kid,
         "x": served_jwks_for(imposter)["keys"][0]["x"]},
        served_jwks_for(new)["keys"][0],
    ]}
    rec = make_rotation_record(old, new, tenant_id="alice", seq=1, expires_at=_future())

    # Adoption still succeeds via the LOCAL pin — the forged served entry
    # under old.kid is never consulted to verify the record's signature.
    adopted_kid = verifier.adopt_rotation(rec, forged_served)
    assert adopted_kid == new.kid

    # A verdict with header kid=old.kid (the PINNED kid) but SIGNED by the
    # IMPOSTER's key must still be rejected. sign_verdict always forces the
    # header kid to the signer's own kid, so it cannot produce this shape —
    # the forgery has to be built directly with PyJWT, putting the imposter's
    # signature under old.kid (mirroring sign_verdict's exact claim shape,
    # arbiter/signing.py). The only discriminator left is the signature: the
    # warden looks up old.kid, verifies against its LOCAL pin (old's real
    # bytes, not the forged served entry), and the imposter's signature fails
    # — proving the warden trusts its local pin, never the served bytes.
    forged_payload = {
        "iss": "hma",
        "aud": "hma-verdict:alice",
        "jti": "r",
        "iat": int(time.time()),
        "hma": {
            "request_id": "r",
            "action_hash": None,
            "decision": "approved",
            "decided_at": "2999-01-01T00:00:00+00:00",
            "approval_ttl_seconds": 600,
            "tenant_id": "alice",
        },
    }
    forged = jwt.encode(forged_payload, imposter.signing_key, algorithm="EdDSA",
                        headers={"kid": old.kid})
    with pytest.raises(VerdictError):
        verifier.verify(forged, "r", None)

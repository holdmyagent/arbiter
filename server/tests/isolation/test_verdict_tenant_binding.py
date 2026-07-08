"""§16 gate: cross-tenant verdict rejection with keys FORCED identical.

§15.8 — isolation never rests on key distinctness alone. A verdict signed for
alice's tenant must be rejected by a bob-paired warden even when the warden's
locally pinned key bytes are FORCED equal to alice's (the signature verifies
fine); the rejection must come from the aud/hma.tenant_id binding, not from a
kid/signature mismatch. The baseline (an alice-paired warden with the same pin)
must genuinely ACCEPT, proving the test is non-vacuous.
"""
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import VerdictError, VerdictVerifier

from tests.isolation.conftest import sign_verdict
from arbiter.signing import load_or_create_signer


def _raw(signer):
    return signer.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_identical_keys_still_rejected_across_tenants(tmp_path):
    # One physical key, minted for alice.
    signer = load_or_create_signer("alice", tmp_path / "k")  # kid = "alice:<hash8>"

    # A verdict genuinely signed for ALICE.
    jws = sign_verdict(signer, request_id="r1", action_hash=None, decision="approved",
                       decided_at="2999-01-01T00:00:00+00:00", approval_ttl=600,
                       tenant_id="alice")

    # A BOB-paired warden whose LOCAL pin is FORCED to alice's exact key bytes,
    # under alice's own kid (the strongest form of the coincidence: same kid,
    # same bytes — only the warden's paired tenant_id differs).
    pinned = {signer.kid: _raw(signer)}
    bob_verifier = VerdictVerifier(pinned=pinned, tenant_id="bob")

    # Signature verifies (identical key) but the aud/hma.tenant_id binding must
    # still reject — proving isolation does not rest on key distinctness alone.
    with pytest.raises(VerdictError):
        bob_verifier.verify(jws, "r1", None)

    # BASELINE (non-vacuity): an ALICE-paired warden with the identical pin
    # genuinely accepts the same verdict.
    alice_verifier = VerdictVerifier(pinned=pinned, tenant_id="alice")
    v = alice_verifier.verify(jws, "r1", None)
    assert v.decision == "approved"

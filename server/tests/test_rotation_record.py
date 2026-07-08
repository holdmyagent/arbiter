import time

import jwt
import pytest

from arbiter.signing import load_or_create_signer, sign_rotation_record


def test_rotation_record_signed_by_old_key_carries_new_key_and_seq(tmp_path):
    old = load_or_create_signer("acme", tmp_path / "old")
    new = load_or_create_signer("acme", tmp_path / "new")
    new_x = new.public_jwks()["keys"][0]["x"]
    exp = int(time.time()) + 3600
    rec = sign_rotation_record(old, new_kid=new.kid, new_x=new_x, seq=1,
                               expires_at=exp, tenant_id="acme")
    # Header kid is the OLD kid; the record verifies under the OLD public key only.
    assert jwt.get_unverified_header(rec)["kid"] == old.kid
    decoded = jwt.decode(rec, old.signing_key.public_key(), algorithms=["EdDSA"],
                         audience="hma-rotation:acme")
    assert decoded["hma"] == {"tenant_id": "acme", "new_kid": new.kid,
                              "new_x": new_x, "seq": 1, "expires_at": exp}


def test_rotation_record_does_not_verify_under_new_key(tmp_path):
    old = load_or_create_signer("acme", tmp_path / "old")
    new = load_or_create_signer("acme", tmp_path / "new")
    new_x = new.public_jwks()["keys"][0]["x"]
    rec = sign_rotation_record(old, new_kid=new.kid, new_x=new_x, seq=1,
                               expires_at=int(time.time()) + 3600, tenant_id="acme")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(rec, new.signing_key.public_key(), algorithms=["EdDSA"],
                   audience="hma-rotation:acme")

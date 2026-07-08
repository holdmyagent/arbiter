import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from arbiter.signing import (RETIRED_FILENAME, ROTATION_FILENAME,
                              load_or_create_signer, rotate_signing_key)


def test_rotate_changes_current_key_and_stages_grace_set(tmp_path):
    old = load_or_create_signer("acme", tmp_path)
    new = rotate_signing_key("acme", tmp_path, ttl_seconds=3600, seq=1)
    assert new.kid != old.kid
    assert new.kid.startswith("acme:")
    # A fresh load now returns the NEW key.
    assert load_or_create_signer("acme", tmp_path).kid == new.kid

    jwks = new.public_jwks()
    kids = {k["kid"] for k in jwks["keys"]}
    assert new.kid in kids and old.kid in kids     # both served during grace
    assert "rotation" in jwks
    # The staged record is signed by the OLD key and names the NEW kid.
    rec = jwks["rotation"]
    assert jwt.get_unverified_header(rec)["kid"] == old.kid
    decoded = jwt.decode(rec, old.signing_key.public_key(), algorithms=["EdDSA"],
                         audience="hma-rotation:acme")
    assert decoded["hma"]["new_kid"] == new.kid and decoded["hma"]["seq"] == 1


def test_expired_grace_window_drops_prev_key_and_record(tmp_path):
    old = load_or_create_signer("acme", tmp_path)
    new = rotate_signing_key("acme", tmp_path, ttl_seconds=-1, seq=1)  # already expired
    jwks = new.public_jwks()
    assert [k["kid"] for k in jwks["keys"]] == [new.kid]  # only current
    assert "rotation" not in jwks
    _ = old  # (retired PEM retained on disk; not served past grace)


def test_rotate_archives_old_pem_to_retired_filename(tmp_path):
    """RETIRED_FILENAME (declared alongside KEY_FILENAME/ROTATION_FILENAME) must
    actually be wired: the pre-rotation private key survives on disk under that
    name rather than being silently overwritten."""
    old = load_or_create_signer("acme", tmp_path)
    rotate_signing_key("acme", tmp_path, ttl_seconds=3600, seq=1)
    retired_pem = (tmp_path / RETIRED_FILENAME).read_bytes()
    retired_key = serialization.load_pem_private_key(retired_pem, password=None)
    assert (retired_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)
            == old.signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw))


def test_rotation_file_non_dict_json_degrades_to_no_rotation(tmp_path):
    """A syntactically valid but structurally wrong verdict_rotation.json (e.g. a
    JSON list or scalar) must not crash public_jwks()/GET /v1/keys; it should be
    treated as 'no rotation staged' rather than raising out of rec.get(...)."""
    signer = load_or_create_signer("acme", tmp_path)
    (tmp_path / ROTATION_FILENAME).write_text("[1, 2, 3]")
    jwks = signer.public_jwks()
    assert [k["kid"] for k in jwks["keys"]] == [signer.kid]
    assert "rotation" not in jwks

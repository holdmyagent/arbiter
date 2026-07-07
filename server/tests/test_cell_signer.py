from pathlib import Path
from arbiter.signing import Signer, load_or_create_signer, KEY_FILENAME


def test_kid_is_tenant_namespaced(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    prefix, _, hash8 = s.kid.partition(":")
    assert prefix == "acme"
    assert len(hash8) == 8 and all(c in "0123456789abcdef" for c in hash8)
    assert s.tenant_id == "acme"


def test_key_persisted_in_cell_dir_and_stable(tmp_path):
    s1 = load_or_create_signer("acme", tmp_path)
    assert (tmp_path / KEY_FILENAME).is_file()
    s2 = load_or_create_signer("acme", tmp_path)   # reload, don't regenerate
    assert s1.kid == s2.kid


def test_two_tenants_get_distinct_keys(tmp_path):
    a = load_or_create_signer("a", tmp_path / "a")
    b = load_or_create_signer("b", tmp_path / "b")
    assert a.kid.split(":")[1] != b.kid.split(":")[1]   # different key bytes -> different hash8


def test_public_jwks_advertises_namespaced_kid(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jwks = s.public_jwks()
    assert jwks["keys"][0]["kid"] == s.kid
    assert jwks["keys"][0]["kty"] == "OKP" and jwks["keys"][0]["crv"] == "Ed25519"

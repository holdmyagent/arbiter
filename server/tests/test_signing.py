import base64
import hashlib
import json
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from arbiter.signing import Signer, load_or_create_keypair, public_jwks, sign_verdict


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ── keypair persistence + kid ────────────────────────────────────────────────

def test_creates_pem_0600_and_persists_across_loads(tmp_path):
    kid1, key1 = load_or_create_keypair(tmp_path)
    pem = tmp_path / "verdict_signing_key.pem"
    assert pem.is_file()
    assert oct(pem.stat().st_mode & 0o777) == "0o600"
    kid2, key2 = load_or_create_keypair(tmp_path)
    assert kid1 == kid2
    assert _raw_pub(key1) == _raw_pub(key2)


def test_creates_missing_config_dir(tmp_path):
    kid, _ = load_or_create_keypair(tmp_path / "nested" / "cfg")
    assert (tmp_path / "nested" / "cfg" / "verdict_signing_key.pem").is_file()
    assert len(kid) == 8


def test_kid_is_first_8_hex_of_pubkey_sha256(tmp_path):
    kid, key = load_or_create_keypair(tmp_path)
    assert kid == hashlib.sha256(_raw_pub(key)).hexdigest()[:8]
    int(kid, 16)  # pure hex


def test_distinct_keypairs_get_distinct_kids(tmp_path):
    kid_a, _ = load_or_create_keypair(tmp_path / "a")
    kid_b, _ = load_or_create_keypair(tmp_path / "b")
    assert kid_a != kid_b


def test_race_loser_loads_winners_key(tmp_path, monkeypatch):
    # Simulate losing the O_EXCL first-run race: the winner minted the key
    # after we checked is_file() but before our O_EXCL create. The loser must
    # recover by loading the winner's key, not crash with FileExistsError.
    kid_winner, key_winner = load_or_create_keypair(tmp_path)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    kid, key = load_or_create_keypair(tmp_path)
    assert kid == kid_winner
    assert _raw_pub(key) == _raw_pub(key_winner)


# ── sign_verdict round trip ─────────────────────────────────────────────────

def test_sign_verdict_round_trips_with_pyjwt(tmp_path):
    kid, key = load_or_create_keypair(tmp_path)
    signer = Signer(tenant_id="acme", kid=kid, signing_key=key)
    jws = sign_verdict(signer, request_id="r1", action_hash="ab" * 32,
                       decision="approved", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    assert jwt.get_unverified_header(jws)["kid"] == kid
    decoded = jwt.decode(jws, key.public_key(), algorithms=["EdDSA"], audience="hma-verdict:acme")
    assert set(decoded) == {"iss", "aud", "jti", "iat", "hma"}
    assert decoded["iss"] == "hma" and decoded["aud"] == "hma-verdict:acme"
    assert decoded["jti"] == "r1" and isinstance(decoded["iat"], int)
    assert decoded["hma"] == {"request_id": "r1", "action_hash": "ab" * 32,
                              "decision": "approved",
                              "decided_at": "2026-07-06T00:00:00+00:00",
                              "approval_ttl_seconds": 600,
                              "tenant_id": "acme"}


def test_action_hash_none_signs_verifiably_unbound(tmp_path):
    kid, key = load_or_create_keypair(tmp_path)
    signer = Signer(tenant_id="acme", kid=kid, signing_key=key)
    jws = sign_verdict(signer, request_id="r2", action_hash=None,
                       decision="expired", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    decoded = jwt.decode(jws, key.public_key(), algorithms=["EdDSA"], audience="hma-verdict:acme")
    assert decoded["hma"]["action_hash"] is None


def test_wrong_key_fails_verification(tmp_path):
    kid, key = load_or_create_keypair(tmp_path / "signer")
    _, other = load_or_create_keypair(tmp_path / "other")
    signer = Signer(tenant_id="acme", kid=kid, signing_key=key)
    jws = sign_verdict(signer, request_id="r3", action_hash=None,
                       decision="approved", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(jws, other.public_key(), algorithms=["EdDSA"], audience="hma-verdict:acme")


def test_tampered_payload_fails_verification(tmp_path):
    kid, key = load_or_create_keypair(tmp_path)
    signer = Signer(tenant_id="acme", kid=kid, signing_key=key)
    jws = sign_verdict(signer, request_id="r4", action_hash=None,
                       decision="denied", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    h, p, s = jws.split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    body["hma"]["decision"] = "approved"
    p2 = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(f"{h}.{p2}.{s}", key.public_key(), algorithms=["EdDSA"],
                   audience="hma-verdict:acme")


# ── public_jwks ─────────────────────────────────────────────────────────────

def test_public_jwks_shape(tmp_path):
    kid, key = load_or_create_keypair(tmp_path)
    jwks = public_jwks(kid, key)
    assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1
    k = jwks["keys"][0]
    assert set(k) == {"kty", "crv", "kid", "x"}
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["kid"] == kid
    assert "=" not in k["x"]  # unpadded base64url
    assert base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4)) == _raw_pub(key)

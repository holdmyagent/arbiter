import base64
import hashlib
import json
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from arbiter.signing import Signer, load_or_create_signer, sign_verdict, _write_rotation


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_signer_kid_is_tenant_namespaced_hash8(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    assert isinstance(s, Signer)
    assert s.tenant_id == "acme"
    tenant, _, hash8 = s.kid.partition(":")
    assert tenant == "acme"
    assert hash8 == hashlib.sha256(_raw_pub(s.signing_key)).hexdigest()[:8]
    int(hash8, 16)  # pure hex


def test_pem_is_0600_and_persists_across_loads(tmp_path):
    s1 = load_or_create_signer("acme", tmp_path)
    pem = tmp_path / "verdict_signing_key.pem"
    assert pem.is_file()
    assert oct(pem.stat().st_mode & 0o777) == "0o600"
    s2 = load_or_create_signer("acme", tmp_path)
    assert s1.kid == s2.kid
    assert _raw_pub(s1.signing_key) == _raw_pub(s2.signing_key)


def test_creates_missing_cell_dir(tmp_path):
    s = load_or_create_signer("acme", tmp_path / "nested" / "cfg")
    assert (tmp_path / "nested" / "cfg" / "verdict_signing_key.pem").is_file()
    assert s.dir == tmp_path / "nested" / "cfg"


def test_distinct_dirs_get_distinct_keys_same_tenant_prefix(tmp_path):
    a = load_or_create_signer("acme", tmp_path / "a")
    b = load_or_create_signer("acme", tmp_path / "b")
    assert a.kid.startswith("acme:") and b.kid.startswith("acme:")
    assert a.kid != b.kid  # different key bytes -> different hash8


def test_race_loser_loads_winners_key(tmp_path, monkeypatch):
    winner = load_or_create_signer("acme", tmp_path)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    loser = load_or_create_signer("acme", tmp_path)
    assert loser.kid == winner.kid
    assert _raw_pub(loser.signing_key) == _raw_pub(winner.signing_key)


def test_public_jwks_shape(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jwks = s.public_jwks()
    assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1
    k = jwks["keys"][0]
    assert set(k) == {"kty", "crv", "kid", "x"}
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["kid"] == s.kid
    assert "=" not in k["x"]
    assert base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4)) == _raw_pub(s.signing_key)


# ── rotation-grace-window public_jwks ───────────────────────────────────────

def test_public_jwks_serves_retired_key_during_grace(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    rec = {"prev_kid": "acme:deadbeef", "prev_x": "abc123",
           "record": {"old_kid": "acme:deadbeef", "new_kid": s.kid},
           "expires_at": int(time.time()) + 3600}
    _write_rotation(tmp_path, rec)
    jwks = s.public_jwks()
    assert {k["kid"] for k in jwks["keys"]} == {s.kid, "acme:deadbeef"}
    assert jwks["rotation"] == rec["record"]


def test_public_jwks_ignores_expired_rotation_record(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    rec = {"prev_kid": "acme:deadbeef", "prev_x": "abc123",
           "record": {"old_kid": "acme:deadbeef", "new_kid": s.kid},
           "expires_at": int(time.time()) - 1}
    _write_rotation(tmp_path, rec)
    jwks = s.public_jwks()
    assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1


def test_public_jwks_ignores_malformed_rotation_record(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    (tmp_path / "verdict_rotation.json").write_text("not json")
    jwks = s.public_jwks()
    assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1


# ── sign_verdict round trip ─────────────────────────────────────────────────

def test_sign_verdict_round_trips_with_pyjwt(tmp_path):
    signer = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(signer, request_id="r1", action_hash="ab" * 32,
                       decision="approved", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    assert jwt.get_unverified_header(jws)["kid"] == signer.kid
    decoded = jwt.decode(jws, signer.signing_key.public_key(), algorithms=["EdDSA"],
                        audience="hma-verdict:acme")
    assert set(decoded) == {"iss", "aud", "jti", "iat", "hma"}
    assert decoded["iss"] == "hma" and decoded["aud"] == "hma-verdict:acme"
    assert decoded["jti"] == "r1" and isinstance(decoded["iat"], int)
    assert decoded["hma"] == {"request_id": "r1", "action_hash": "ab" * 32,
                              "decision": "approved",
                              "decided_at": "2026-07-06T00:00:00+00:00",
                              "approval_ttl_seconds": 600,
                              "tenant_id": "acme"}


def test_action_hash_none_signs_verifiably_unbound(tmp_path):
    signer = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(signer, request_id="r2", action_hash=None,
                       decision="expired", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    decoded = jwt.decode(jws, signer.signing_key.public_key(), algorithms=["EdDSA"],
                        audience="hma-verdict:acme")
    assert decoded["hma"]["action_hash"] is None


def test_wrong_key_fails_verification(tmp_path):
    signer = load_or_create_signer("acme", tmp_path / "signer")
    other = load_or_create_signer("acme", tmp_path / "other")
    jws = sign_verdict(signer, request_id="r3", action_hash=None,
                       decision="approved", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(jws, other.signing_key.public_key(), algorithms=["EdDSA"],
                   audience="hma-verdict:acme")


def test_tampered_payload_fails_verification(tmp_path):
    signer = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(signer, request_id="r4", action_hash=None,
                       decision="denied", decided_at="2026-07-06T00:00:00+00:00",
                       approval_ttl=600, tenant_id="acme")
    h, p, s = jws.split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    body["hma"]["decision"] = "approved"
    p2 = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(f"{h}.{p2}.{s}", signer.signing_key.public_key(), algorithms=["EdDSA"],
                   audience="hma-verdict:acme")


# ── D2 round-trip coverage: tenant-binding in aud and hma.tenant_id ──────

def test_sign_verdict_binds_tenant_in_aud_and_claim(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r1", action_hash="ab" * 32, decision="approved",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl=600,
                       tenant_id="acme")
    assert jwt.get_unverified_header(jws)["kid"] == s.kid  # "acme:<hash8>"
    decoded = jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                          audience="hma-verdict:acme")
    assert decoded["iss"] == "hma"
    assert decoded["aud"] == "hma-verdict:acme"
    assert decoded["jti"] == "r1" and isinstance(decoded["iat"], int)
    assert decoded["hma"] == {"tenant_id": "acme", "request_id": "r1",
                              "action_hash": "ab" * 32, "decision": "approved",
                              "decided_at": "2026-07-07T00:00:00+00:00",
                              "approval_ttl_seconds": 600}


def test_verdict_from_tenant_a_fails_audience_for_tenant_b(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r2", action_hash=None, decision="denied",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl=600,
                       tenant_id="acme")
    # Even with the SAME key, decoding as tenant "beta" fails on audience.
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                    audience="hma-verdict:beta")


def test_action_hash_none_still_signs(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r3", action_hash=None, decision="expired",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl=600,
                       tenant_id="acme")
    decoded = jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                          audience="hma-verdict:acme")
    assert decoded["hma"]["action_hash"] is None

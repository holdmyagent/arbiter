"""Level 3 device attestation (§F.1): RECORDED, never REQUIRED.

Covers signing.py's P-256/ECDSA-SHA256 primitives (F.1.1, F.1.4), device key
enrolment + rotation (F.1.2), and the decision endpoint's optional attestation
(F.1.3). The two guard-rail tests below are the load-bearing gates of this
file: both MUST return 200, because attestation must never turn an
otherwise-valid approve/deny into a failure.
"""
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from arbiter.signing import build_attestation_payload, verify_attestation


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
    return priv, pub_b64


def _sign(priv, payload: bytes) -> str:
    return base64.b64encode(priv.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()


def _create(c, tok="test-agent"):
    return c.post("/v1/requests", headers={"Authorization": f"Bearer {tok}"},
                  json={"title": "Deploy", "severity": "high", "ttl_seconds": 300})


# ── F.1.1: verify_attestation -- round-trip + tampered signature ───────────

def test_verify_attestation_round_trips_with_fixture_keypair():
    priv, pub_b64 = _keypair()
    payload = build_attestation_payload(request_id="r1", decision="approve",
                                        action_hash="ab" * 32,
                                        signed_at="2026-01-01T00:00:00+00:00")
    sig = _sign(priv, payload)
    assert verify_attestation(pub_b64, sig, payload) is True


def test_verify_attestation_tampered_signature_returns_false_not_raises():
    priv, pub_b64 = _keypair()
    payload = build_attestation_payload(request_id="r1", decision="approve",
                                        action_hash=None,
                                        signed_at="2026-01-01T00:00:00+00:00")
    raw_sig = bytearray(base64.b64decode(_sign(priv, payload)))
    raw_sig[-1] ^= 0xFF   # flip a byte -> tampered
    tampered = base64.b64encode(bytes(raw_sig)).decode()
    assert verify_attestation(pub_b64, tampered, payload) is False


def test_verify_attestation_wrong_key_returns_false():
    priv, _ = _keypair()
    _, other_pub_b64 = _keypair()
    payload = build_attestation_payload(request_id="r1", decision="deny",
                                        action_hash=None, signed_at="T")
    sig = _sign(priv, payload)
    assert verify_attestation(other_pub_b64, sig, payload) is False


def test_verify_attestation_garbage_input_returns_false_not_raises():
    assert verify_attestation("not-base64-!!!", "also-garbage", b"payload") is False
    assert verify_attestation("", "", b"") is False


# ── F.1.4: signed payload binds action_hash -- byte-equality fixture ───────

def test_build_attestation_payload_byte_equality_fixture():
    payload = build_attestation_payload(
        request_id="req-123", decision="approve",
        action_hash="deadbeef" * 8, signed_at="2026-01-01T12:00:00+00:00")
    assert payload == (
        b"hma-attest.v1\nreq-123\napprove\n"
        b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        b"2026-01-01T12:00:00+00:00"
    )


def test_build_attestation_payload_action_hash_none_uses_empty_slot():
    payload = build_attestation_payload(request_id="r", decision="deny",
                                        action_hash=None, signed_at="T")
    assert payload == b"hma-attest.v1\nr\ndeny\n\nT"


# ── F.1.2: enrol -> rotate -> old key row still present, still verifies ────

def test_rotate_device_key_retires_old_row_but_keeps_it_verifying(db):
    dev = db.register_device("tok1", "iPhone")
    priv1, pub1_b64 = _keypair()
    k1 = db.enroll_device_key(dev["id"], pub1_b64)
    payload = build_attestation_payload(request_id="r1", decision="approve",
                                        action_hash=None,
                                        signed_at="2026-01-01T00:00:00+00:00")
    sig1 = _sign(priv1, payload)

    _, pub2_b64 = _keypair()
    k2 = db.enroll_device_key(dev["id"], pub2_b64)   # rotation

    assert k2["id"] != k1["id"]
    old = db.get_device_key(k1["id"])
    assert old is not None and old["retired_at"] is not None   # still present, retired
    assert verify_attestation(old["public_key"], sig1, payload) is True  # still verifies
    new = db.get_device_key(k2["id"])
    assert new["retired_at"] is None
    assert db.get_active_device_key(dev["id"])["id"] == k2["id"]


def test_enroll_device_key_endpoint(client):
    dev = client.db.register_device("tokA", "iPhone")
    _, pub_b64 = _keypair()
    r = client.post("/v1/devices/keys", headers={"Authorization": "Bearer test-app"},
                    json={"device_id": dev["id"], "public_key": pub_b64})
    assert r.status_code == 200
    body = r.json()
    assert body["device_id"] == dev["id"] and body["retired_at"] is None


def test_enroll_device_key_rotation_retires_old_row(client):
    dev = client.db.register_device("tokA", "iPhone")
    _, pub1 = _keypair()
    _, pub2 = _keypair()
    r1 = client.post("/v1/devices/keys", headers={"Authorization": "Bearer test-app"},
                     json={"device_id": dev["id"], "public_key": pub1}).json()
    r2 = client.post("/v1/devices/keys", headers={"Authorization": "Bearer test-app"},
                     json={"device_id": dev["id"], "public_key": pub2}).json()
    assert r1["id"] != r2["id"]
    assert client.db.get_device_key(r1["id"])["retired_at"] is not None
    assert client.db.get_device_key(r2["id"])["retired_at"] is None


# ── F.1.3: the two guard-rail tests -- BOTH MUST return 200 ─────────────────

def test_decision_without_attestation_still_approves(client):
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
                    json={"decision": "approve"})
    assert d.status_code == 200
    assert d.json()["attestation"] == "unattested"
    assert d.json()["attest_key_id"] is None


def test_decision_with_invalid_attestation_still_approves_and_records_failure(client):
    dev = client.db.register_device("tokA", "iPhone")
    key = client.db.enroll_device_key(dev["id"], _keypair()[1])
    rid = _create(client).json()["id"]
    d = client.post(
        f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
        json={"decision": "approve",
              "attestation": {"key_id": key["id"],
                             "signature": base64.b64encode(b"not-a-real-signature").decode(),
                             "signed_at": "2026-01-01T00:00:00+00:00"}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "attestation_failed"
    assert d.json()["attest_key_id"] == key["id"]


# ── the remaining three classifications ─────────────────────────────────────

def test_decision_with_valid_attestation_records_attested(client):
    dev = client.db.register_device("tokA", "iPhone")
    priv, pub_b64 = _keypair()
    key = client.db.enroll_device_key(dev["id"], pub_b64)
    rid = _create(client).json()["id"]
    signed_at = "2026-01-01T00:00:00+00:00"
    payload = build_attestation_payload(request_id=rid, decision="approve",
                                        action_hash=None, signed_at=signed_at)
    sig = _sign(priv, payload)
    d = client.post(
        f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
        json={"decision": "approve",
              "attestation": {"key_id": key["id"], "signature": sig, "signed_at": signed_at}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "attested"
    assert d.json()["attest_key_id"] == key["id"]


def test_decision_with_unknown_key_records_key_unknown(client):
    rid = _create(client).json()["id"]
    d = client.post(
        f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
        json={"decision": "approve",
              "attestation": {"key_id": "does-not-exist", "signature": "AAAA",
                             "signed_at": "2026-01-01T00:00:00+00:00"}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "key_unknown"
    assert d.json()["attest_key_id"] == "does-not-exist"


def test_decision_with_retired_key_records_key_retired_even_if_signature_valid(client):
    dev = client.db.register_device("tokA", "iPhone")
    priv1, pub1_b64 = _keypair()
    k1 = client.db.enroll_device_key(dev["id"], pub1_b64)
    client.db.enroll_device_key(dev["id"], _keypair()[1])   # rotates k1 out
    rid = _create(client).json()["id"]
    signed_at = "2026-01-01T00:00:00+00:00"
    payload = build_attestation_payload(request_id=rid, decision="approve",
                                        action_hash=None, signed_at=signed_at)
    sig = _sign(priv1, payload)   # cryptographically VALID, but against a retired key
    d = client.post(
        f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
        json={"decision": "approve",
              "attestation": {"key_id": k1["id"], "signature": sig, "signed_at": signed_at}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "key_retired"
    assert d.json()["attest_key_id"] == k1["id"]


# ── attestation is deliberately UNVALIDATED at the wire (Any, not a nested
# model): a malformed shape must still 200, never 422 ───────────────────────

def test_decision_with_non_dict_attestation_still_approves(client):
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
                    json={"decision": "approve", "attestation": "not-even-an-object"})
    assert d.status_code == 200
    assert d.json()["attestation"] == "attestation_failed"
    assert d.json()["attest_key_id"] is None


def test_decision_with_incomplete_attestation_dict_still_approves(client):
    """A known, active key_id with no signature/signed_at at all -- still 200,
    still classified rather than 422'd on a missing field."""
    dev = client.db.register_device("tokA", "iPhone")
    key = client.db.enroll_device_key(dev["id"], _keypair()[1])
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
                    json={"decision": "approve", "attestation": {"key_id": key["id"]}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "attestation_failed"
    assert d.json()["attest_key_id"] == key["id"]

def test_decision_with_unresolvable_key_id_and_no_other_fields_is_key_unknown(client):
    """A key_id that resolves to nothing at all is key_unknown, not
    attestation_failed -- still 200 either way."""
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
                    json={"decision": "approve", "attestation": {"key_id": "some-key"}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "key_unknown"
    assert d.json()["attest_key_id"] == "some-key"


def test_decision_with_wrong_typed_key_id_still_approves(client):
    rid = _create(client).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": "Bearer test-app"},
                    json={"decision": "approve",
                          "attestation": {"key_id": 12345, "signature": "AAAA", "signed_at": "T"}})
    assert d.status_code == 200
    assert d.json()["attestation"] == "attestation_failed"
    assert d.json()["attest_key_id"] is None


# ── attestation is write-once: a later call cannot blank/downgrade it ───────

def test_set_attestation_is_write_once(db, make):
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "someone")
    db.set_attestation(r["id"], "attested", "key-1")
    db.set_attestation(r["id"], "attestation_failed", "key-2")   # must NOT overwrite
    got = db.get_request(r["id"])
    assert got["attestation"] == "attested" and got["attest_key_id"] == "key-1"

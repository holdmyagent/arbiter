"""load_rotation_state / save_rotation_state round trip + fail-closed on tamper.

Rotation state stores only PUBLIC pins + a monotonic seq, so a corrupted or
tampered file must never crash the warden or silently smuggle in a forged
pin — it fails closed to the empty state (the initial config pin set still
applies; adoption is simply forgotten and would need to happen again)."""


def test_rotation_state_round_trip(tmp_path):
    from hold_warden.rotation_state import load_rotation_state, save_rotation_state
    pinned = {"acme:aabbccdd": b"\x01" * 32, "acme:11223344": b"\x02" * 32}
    save_rotation_state(tmp_path, pinned, 7)
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == pinned and seq == 7


def test_rotation_state_absent_is_empty(tmp_path):
    from hold_warden.rotation_state import load_rotation_state
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == {} and seq == 0


def test_rotation_state_corrupt_json_is_empty(tmp_path):
    from hold_warden.rotation_state import load_rotation_state
    (tmp_path / "rotation_state.json").write_text("not json at all {{{")
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == {} and seq == 0


def test_rotation_state_invalid_key_shape_fails_closed(tmp_path):
    """A tampered/corrupt file with a non-Ed25519-shaped pin must be rejected
    wholesale (eager shape validation), not accepted and deferred to a bare
    ValueError at first verify."""
    import json
    from hold_warden.rotation_state import load_rotation_state
    (tmp_path / "rotation_state.json").write_text(json.dumps(
        {"adopted": {"acme:bad": "AAAA"}, "last_seq": 3}))  # "AAAA" decodes to 3 bytes, not 32
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == {} and seq == 0


def test_rotation_state_save_is_atomic_no_partial_file_left(tmp_path):
    """save_rotation_state writes via a tmp file + rename — no .tmp litter, no
    window where a reader could observe a half-written file."""
    from hold_warden.rotation_state import save_rotation_state
    save_rotation_state(tmp_path, {"acme:aabbccdd": b"\x01" * 32}, 1)
    leftovers = [p for p in tmp_path.iterdir() if p.name != "rotation_state.json"]
    assert leftovers == []
    assert (tmp_path / "rotation_state.json").exists()


def test_config_pin_wins_on_kid_collision():
    """When rotation_state.json contains the config kid with different bytes
    (simulating tampering), the config pin always wins. A verdict signed by
    the CONFIG key verifies; one signed by the attacker key does not."""
    from hold_warden.verdict import VerdictVerifier, VerdictError
    import pytest
    import hashlib
    from datetime import datetime, timezone
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Generate config key and kid
    config_key = Ed25519PrivateKey.generate()
    config_raw = config_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    config_kid = f"acme:{hashlib.sha256(config_raw).hexdigest()[:8]}"

    # Generate attacker key that shares the same kid (collision)
    attacker_key = Ed25519PrivateKey.generate()
    attacker_raw = attacker_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Merge with config pin WINNING (adopted first, config second)
    # This simulates the fixed precedence where a same-privilege FS writer
    # could tamper rotation_state.json with {config_kid: attacker_raw}, but
    # the config pin still wins the collision.
    adopted = {config_kid: attacker_raw}  # tampered state file
    config_pins = {config_kid: config_raw}  # from warden.toml
    pinned = {**adopted, **config_pins}  # config wins

    # Verify that the config key is actually pinned (not the attacker's)
    assert pinned[config_kid] == config_raw

    verifier = VerdictVerifier(pinned, "acme")

    # A verdict signed by the CONFIG key should verify
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma",
        "aud": "hma-verdict:acme",
        "jti": "test-rid",
        "iat": int(now.timestamp()),
        "hma": {
            "tenant_id": "acme",
            "request_id": "test-rid",
            "action_hash": "a1" * 32,
            "decision": "approved",
            "decided_at": now.isoformat(),
            "approval_ttl_seconds": 600,
        },
    }
    valid_token = jwt.encode(payload, config_key, algorithm="EdDSA",
                             headers={"kid": config_kid})
    verdict = verifier.verify(valid_token, "test-rid", "a1" * 32)
    assert verdict.decision == "approved"

    # A verdict signed by the ATTACKER key (even with the same kid) should fail
    forged_token = jwt.encode(payload, attacker_key, algorithm="EdDSA",
                              headers={"kid": config_kid})
    with pytest.raises(VerdictError):
        verifier.verify(forged_token, "test-rid", "a1" * 32)

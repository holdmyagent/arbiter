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

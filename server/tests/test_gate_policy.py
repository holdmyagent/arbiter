from arbiter.db import Database
from arbiter import gate_policy as gp


def test_most_restrictive_default_is_fail_closed():
    r = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                          {"version": 0, "epoch": 1})
    assert r["policy_schema_version"] == gp.POLICY_SCHEMA_VERSION
    assert r["default_decision"] == "ask"
    assert r["categorical_ask"]                  # NON-EMPTY floor
    assert set(gp.LOCAL_FLOOR_CATEGORICAL) <= set(r["categorical_ask"])
    assert r["tool_allowlist"] == []             # nothing is affirmatively safe
    assert r["ask_patterns"] == []
    assert r["advisory_allow_patterns"] == []
    assert r["override_allow_patterns"] == []
    assert r["active_preset"] is None
    assert r["etag"]


def test_most_restrictive_default_is_isolated_across_calls():
    # A caller that mutates the returned most-restrictive doc must NOT corrupt
    # the fail-closed default for subsequent independent resolve_policy calls
    # (dict.update is a shallow copy — the returned lists must be fresh, not
    # the same list objects as the module constant MOST_RESTRICTIVE_STATIC).
    r = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                          {"version": 0, "epoch": 1})
    r["tool_allowlist"].append("run_shell")
    r["categorical_ask"].remove("execute_code")

    r2 = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                           {"version": 1, "epoch": 1})
    assert r2["tool_allowlist"] == []
    assert set(gp.LOCAL_FLOOR_CATEGORICAL) <= set(r2["categorical_ask"])
    assert "execute_code" in r2["categorical_ask"]


def test_resolver_unions_local_floor_and_never_lets_overlay_drop_it():
    preset = {"name": "audit-only", "block_patterns": [], "allow_patterns": [],
              "tool_allowlist": ["run_shell"], "default_decision": "allow"}
    # An operator overlay that tries to always_allow a categorical tool name:
    overlay = {"always_ask": [], "always_allow": ["execute_code"]}
    r = gp.resolve_policy(preset, overlay, {"version": 3, "epoch": 1})
    assert "execute_code" in r["categorical_ask"]        # floor survives
    # override_allow is kept as a list but the matcher (Task 3) never lets it
    # suppress a categorical tool; the resolver simply does not strip the floor.


def test_everything_preset_drops_override_allow_and_asks_by_default():
    preset = {"name": "everything", **gp.SEED_PRESETS["everything"]}
    overlay = {"always_ask": [], "always_allow": ["rm -rf /data"]}
    r = gp.resolve_policy(preset, overlay, {"version": 5, "epoch": 1})
    assert r["default_decision"] == "ask"
    assert r["override_allow_patterns"] == []            # H3: holes ignored under everything
    assert r["tool_allowlist"] == []                     # everything = no tool is auto-safe


def test_everything_posture_is_detected_by_shape_not_name():
    # Pins the SHAPE-based detection: ANY preset with default_decision=="ask"
    # and an empty tool_allowlist gets the "everything" H3 treatment (overlay
    # always_allow holes suppressed), regardless of its name. The local floor
    # (categorical_ask) stays intact either way.
    preset = {"name": "totally-custom-name", "block_patterns": [],
              "allow_patterns": [], "tool_allowlist": [], "default_decision": "ask"}
    overlay = {"always_ask": [], "always_allow": ["rm -rf /data"]}
    r = gp.resolve_policy(preset, overlay, {"version": 7, "epoch": 1})
    assert r["override_allow_patterns"] == []            # shape-matched "everything"
    assert set(gp.LOCAL_FLOOR_CATEGORICAL) <= set(r["categorical_ask"])


def test_etag_changes_with_epoch_and_version():
    a = gp._etag(1, 4)
    assert a != gp._etag(2, 4) and a != gp._etag(1, 5)


def test_policy_store_roundtrip():
    db = Database(":memory:")
    assert db.policy_get_active() is None
    assert db.policy_list_presets() == []
    assert db.policy_get_overlay() == {"always_ask": [], "always_allow": []}
    assert db.policy_meta() == {"version": 0, "epoch": 1}

    db.policy_put_preset("dangerous-shell", ["rm -rf", "git push"], ["ls"],
                         ["run_shell"], "allow")
    p = db.policy_get_preset("dangerous-shell")
    assert p == {"name": "dangerous-shell", "block_patterns": ["rm -rf", "git push"],
                 "allow_patterns": ["ls"], "tool_allowlist": ["run_shell"],
                 "default_decision": "allow"}
    db.policy_set_active("dangerous-shell")
    assert db.policy_get_active() == "dangerous-shell"

    db.policy_set_overlay(["curl"], ["ls -la"])
    assert db.policy_get_overlay() == {"always_ask": ["curl"], "always_allow": ["ls -la"]}

    assert db.policy_bump_version() == 1
    assert db.policy_bump_version() == 2
    assert db.policy_meta()["version"] == 2

    assert db.policy_delete_preset("dangerous-shell") is True
    assert db.policy_get_preset("dangerous-shell") is None
    assert db.policy_delete_preset("dangerous-shell") is False

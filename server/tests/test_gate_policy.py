import pytest

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
    # the same list objects any other resolve_policy(None, ...) call handed out).
    r = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                          {"version": 0, "epoch": 1})
    r["tool_allowlist"].append("run_shell")
    r["categorical_ask"].remove("execute_code")

    r2 = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                           {"version": 1, "epoch": 1})
    assert r2["tool_allowlist"] == []
    assert set(gp.LOCAL_FLOOR_CATEGORICAL) <= set(r2["categorical_ask"])
    assert "execute_code" in r2["categorical_ask"]


def test_mutating_exported_most_restrictive_does_not_corrupt_resolver_default():
    # The public symbol gp.MOST_RESTRICTIVE must be a snapshot, NOT an alias of
    # whatever object graph resolve_policy's None-branch rebuilds from. A
    # consumer mutating the exported "constant" in place must never corrupt
    # the fail-closed default returned to subsequent independent callers.
    gp.MOST_RESTRICTIVE["tool_allowlist"].append("run_shell")
    gp.MOST_RESTRICTIVE["categorical_ask"].clear()

    r = gp.resolve_policy(None, {"always_ask": [], "always_allow": []},
                          {"version": 0, "epoch": 1})
    assert r["tool_allowlist"] == []
    assert set(gp.LOCAL_FLOOR_CATEGORICAL) <= set(r["categorical_ask"])
    assert "execute_code" in r["categorical_ask"]
    assert "delegate_task" in r["categorical_ask"]


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


def _resolved(preset_name=None, overlay=None, meta=None):
    overlay = overlay or {"always_ask": [], "always_allow": []}
    meta = meta or {"version": 1, "epoch": 1}
    preset = None
    if preset_name is not None:
        preset = {"name": preset_name, **gp.SEED_PRESETS[preset_name]}
    return gp.resolve_policy(preset, overlay, meta)


def test_matcher_most_restrictive_asks_unmatched_command():
    # THE mutation-check: a no-policy fetch makes whoami ASK. RED if allow-all.
    r = _resolved(None)
    assert gp.evaluate(r, "run_shell", "whoami") == "ask"
    assert gp.evaluate(r, "run_shell", "") == "ask"


def test_matcher_categorical_ask_is_first_and_non_overridable():
    # Even an override_allow whose text matches the payload cannot suppress a
    # categorical-ask tool.
    r = _resolved("dangerous-shell", overlay={"always_ask": [],
                                              "always_allow": ["execute_code"]})
    assert gp.evaluate(r, "execute_code", "execute_code") == "ask"


def test_matcher_ask_wins_ties_over_advisory_allow():
    # A command matching BOTH an ask pattern and an advisory allow -> ask.
    preset = {"name": "p", "block_patterns": ["git push"], "allow_patterns": ["git push --dry-run"],
              "tool_allowlist": ["run_shell"], "default_decision": "allow"}
    r = gp.resolve_policy(preset, {"always_ask": [], "always_allow": []},
                          {"version": 1, "epoch": 1})
    assert gp.evaluate(r, "run_shell", "git push --dry-run origin") == "ask"


def test_matcher_override_allow_cannot_beat_a_block():
    preset = {"name": "p", "block_patterns": ["git push"], "allow_patterns": [],
              "tool_allowlist": ["run_shell"], "default_decision": "allow"}
    r = gp.resolve_policy(preset, {"always_ask": [], "always_allow": ["git push origin main"]},
                          {"version": 1, "epoch": 1})
    assert gp.evaluate(r, "run_shell", "git push origin main") == "ask"


def test_matcher_override_allow_beats_default_ask_escape_hatch():
    preset = {"name": "p", "block_patterns": [], "allow_patterns": [],
              "tool_allowlist": ["run_shell"], "default_decision": "ask"}
    # not "everything" (tool_allowlist non-empty) so override_allow is kept:
    r = gp.resolve_policy(
        preset, {"always_ask": [], "always_allow": ["ls -la /home/hermes"]},
        {"version": 1, "epoch": 1})
    assert gp.evaluate(r, "run_shell", "ls -la /home/hermes") == "allow"
    assert gp.evaluate(r, "run_shell", "cat /etc/passwd") == "ask"   # default ask


def test_matcher_unknown_tool_asks_under_everything():
    # H3: a tool not affirmatively safe ASKS under everything/default.
    r = _resolved("everything")
    assert gp.evaluate(r, "some_new_mcp_tool", "anything") == "ask"


def test_matcher_advisory_allow_beats_default_allow_context():
    r = _resolved("dangerous-shell")            # default_decision "allow"
    assert gp.evaluate(r, "run_shell", "ls -la") == "allow"        # unmatched, default allow
    assert gp.evaluate(r, "run_shell", "rm -rf /data") == "ask"    # block matches


def test_matcher_unknown_tool_asks_even_under_permissive_default_decision():
    # H3: "any tool not affirmatively safe ASKS" is not conditioned on the
    # active preset's default_decision. A preset like "dangerous-shell" sets
    # default_decision "allow" for its KNOWN/vetted tool (run_shell) -- that
    # must never leak into blanket-allowing a tool the preset never vetted at
    # all. Unknown tool asks regardless of posture (do NOT default unknown
    # tools to allow).
    r = _resolved("dangerous-shell")             # default_decision "allow"
    assert gp.evaluate(r, "some_brand_new_tool", "anything") == "ask"


def test_matcher_bare_git_override_allow_does_not_shadow_git_push_block():
    # H4: the earlier fail-open was "anchored always_allow beats ask" --
    # always_allow:["git"] shadowing a "git push" block. A bare, broad
    # override pattern must not punch through a block just because it also
    # substring-matches the blocked command.
    preset = {"name": "p", "block_patterns": ["git push"], "allow_patterns": [],
              "tool_allowlist": ["run_shell"], "default_decision": "allow"}
    r = gp.resolve_policy(preset, {"always_ask": [], "always_allow": ["git"]},
                          {"version": 1, "epoch": 1})
    assert gp.evaluate(r, "run_shell", "git push origin main") == "ask"
    assert gp.evaluate(r, "run_shell", "git status") == "allow"  # override still works elsewhere


def test_validate_preset_rejects_fail_open_shapes():
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("bad name!", [], [], [], "allow")          # name charset
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("p", ["", "ok"], [], ["run_shell"], "allow")  # empty pattern
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("p", [], [], [], "allow")                  # gates nothing
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("p", ["rm"], [], [], "sometimes")          # bad decision
    # a real preset is fine:
    gp.validate_preset("dangerous-shell", ["rm -rf"], [], ["run_shell"], "allow")
    # default_decision "ask" always gates (unmatched -> ask), so empty blocks ok:
    gp.validate_preset("everything", [], [], [], "ask")


def test_validate_overlay_specificity():
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_overlay([], ["rm"])                # too short / no space
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_overlay([""], [])                  # empty always_ask
    gp.validate_overlay(["curl"], ["ls -la /home/hermes"])   # ok


# --- H9 adversarial-review fixups: proven authored fail-open holes -------
#
# The matcher is SUBSTRING (`pattern in command`, only the empty string
# guarded -- see gp._matches). A low-content allow pattern that survives
# validate_preset/validate_overlay therefore becomes a broad allow. Each test
# below pins one proven hole as REJECTED at write time.

def test_h9_rejects_whitespace_only_allow_pattern_preset():
    # Hole 1 (CRITICAL): a whitespace-only preset allow pattern substring-
    # matches almost any real command (the command also contains a space).
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("x", [], [" "], ["run_shell"], "ask")
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("x", [], ["   "], ["run_shell"], "ask")


def test_h9_rejects_whitespace_only_overlay_always_allow():
    # Hole 1 (CRITICAL), overlay surface: 8 spaces still clears the OLD
    # unstripped `len>=8 and " " in p` floor.
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_overlay([], ["        "])


def test_h9_rejects_whitespace_only_on_block_and_ask_surfaces_too():
    # Whitespace-only must be rejected EVERYWHERE patterns are authored, not
    # just on allow surfaces -- block_patterns and overlay always_ask included.
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("x", [" "], [], ["run_shell"], "ask")
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_overlay(["   "], [])


def test_h9_rejects_single_char_or_punctuation_allow_pattern():
    # Hole 2 (CRITICAL): a 1-char/punctuation advisory allow is a substring
    # of almost any real command.
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("x", [], ["a"], ["run_shell"], "ask")
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("x", [], ["/"], ["run_shell"], "ask")


def test_h9_rejects_bare_dangerous_verb_as_preset_advisory_allow():
    # Hole 3 (CRITICAL): a bare dangerous-verb advisory allow (e.g. "rm")
    # substring-matches "rm -rf /" and allows almost everything.
    for verb in ("rm", "curl", "ssh", "kubectl", "sudo", "dd", "wget", "nc",
                 "chmod", "chown"):
        with pytest.raises(gp.PolicyValidationError):
            gp.validate_preset("x", [], [verb], ["run_shell"], "ask")


def test_h9_rejects_bare_dangerous_verb_as_overlay_always_allow():
    # Hole 3 (CRITICAL), overlay surface.
    for verb in ("rm", "curl", "ssh", "kubectl", "sudo", "dd", "wget", "nc",
                 "chmod", "chown"):
        with pytest.raises(gp.PolicyValidationError):
            gp.validate_overlay([], [verb])


def test_h9_rejects_padded_verb_that_bypassed_unstripped_overlay_floor():
    # Hole 4 (HIGH): "kubectl " is 8 raw chars containing a space, so the OLD
    # unstripped floor (len(p) >= 8 and " " in p) passed it. Stripped, it's
    # just the bare verb "kubectl" (7 chars, no interior space) -- reject.
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_overlay([], ["kubectl "])


def test_h9_legit_short_safe_allow_patterns_still_pass():
    # MUST NOT BREAK: short, safe, legitimate advisory allow commands like
    # "ls"/"pwd" must not be swept up by a blanket length floor -- only
    # stripped-length>=2 and "not a bare dangerous verb" is required on
    # preset allow_patterns (no >=8-char floor, that's overlay-only).
    #
    # NOTE: default_decision is "ask" here, not "allow". The literal shape
    # block_patterns=[] + default_decision="allow" + tool_allowlist=
    # ["run_shell"] independently trips the PRE-EXISTING (unrelated to this
    # task's 4 holes) "gates nothing" guard in validate_preset, because it
    # really would leave run_shell completely unrestricted -- a real,
    # separate fail-open shape, not one of the four holes assigned here.
    # default_decision="ask" exercises the identical allow_patterns
    # specificity path this regression guards without colliding with that
    # separate, correct guard.
    gp.validate_preset("ok", [], ["ls", "pwd", "git status"], ["run_shell"], "ask")


def test_h9_all_seed_presets_still_validate():
    # MUST NOT BREAK: every entry in SEED_PRESETS must remain authorable
    # through the write-time validator.
    for name, p in gp.SEED_PRESETS.items():
        gp.validate_preset(name, p["block_patterns"], p["allow_patterns"],
                           p["tool_allowlist"], p["default_decision"])


def test_h9_e2e_critical_whitespace_policy_rejected_before_it_can_reach_evaluate():
    # End-to-end guard for the proven CRITICAL hole: this exact policy shape
    # used to pass validate_preset, after which resolve_policy + evaluate
    # would return "allow" for "rm -rf /home/hermes" (proven below by
    # constructing the resolved doc directly, i.e. bypassing the validator
    # the way the old fail-open path effectively did). The fix must make
    # validate_preset raise so this shape can never be written in the first
    # place -- it can never reach evaluate().
    with pytest.raises(gp.PolicyValidationError):
        gp.validate_preset("critical-hole", [], [" "], ["run_shell"], "ask")

    exploit_preset = {"name": "critical-hole", "block_patterns": [],
                       "allow_patterns": [" "], "tool_allowlist": ["run_shell"],
                       "default_decision": "ask"}
    r = gp.resolve_policy(exploit_preset, {"always_ask": [], "always_allow": []},
                          {"version": 1, "epoch": 1})
    assert gp.evaluate(r, "run_shell", "rm -rf /home/hermes") == "allow"

from arbiter.db import Database


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

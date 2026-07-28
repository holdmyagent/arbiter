from datetime import datetime, timedelta, timezone

import pytest

from arbiter.db import Database
from arbiter.grants import (GRANT_RECENT_SECONDS, GRANT_TTL_MAX_SECONDS,
                            auto_approve_eligible, grant_keys, grant_state)


def _iso(dt):
    return dt.isoformat()


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def gdb(tmp_path):
    return Database(str(tmp_path / "g.sqlite3"))


def _grant(db, agent="hermes", tool="skill_manage", ttl=300, by="kevin-phone"):
    return db.create_grant(agent=agent, tool=tool, granted_by=by,
                           granted_via="app-token", request_id="r1", ttl_seconds=ttl)


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_ttl_ceiling_is_eight_hours():
    assert GRANT_TTL_MAX_SECONDS == 28800
    assert GRANT_RECENT_SECONDS == 86400


def test_grant_keys_requires_two_non_empty_strings():
    assert grant_keys({"agent": "hermes", "tool": "skill_manage"}) == ("hermes", "skill_manage")
    assert grant_keys({"agent": "hermes"}) is None
    assert grant_keys({"tool": "skill_manage"}) is None
    assert grant_keys({"agent": "", "tool": "skill_manage"}) is None
    assert grant_keys({"agent": "hermes", "tool": ""}) is None
    assert grant_keys({"agent": 7, "tool": "skill_manage"}) is None
    assert grant_keys({"agent": "hermes", "tool": ["skill_manage"]}) is None
    assert grant_keys({}) is None
    assert grant_keys(None) is None
    assert grant_keys("hermes") is None


def test_grant_keys_are_matched_exactly_never_normalised():
    """No case folding, no trimming: 'Hermes' is a different agent from
    'hermes' and ' skill_manage' is a different tool. A grant must not widen
    itself by accident."""
    assert grant_keys({"agent": "Hermes", "tool": "skill_manage"}) == ("Hermes", "skill_manage")
    assert grant_keys({"agent": "hermes", "tool": " skill_manage"}) == ("hermes", " skill_manage")


def test_critical_severity_is_never_eligible():
    payload = {"agent": "hermes", "tool": "skill_manage"}
    assert auto_approve_eligible("low", payload) == ("hermes", "skill_manage")
    assert auto_approve_eligible("medium", payload) == ("hermes", "skill_manage")
    assert auto_approve_eligible("high", payload) == ("hermes", "skill_manage")
    assert auto_approve_eligible("critical", payload) is None


def test_grant_state_prefers_revoked_over_expired():
    now = _iso(_now())
    future = _iso(_now() + timedelta(minutes=5))
    past = _iso(_now() - timedelta(minutes=5))
    assert grant_state({"revoked_at": None, "expires_at": future}, now) == "active"
    assert grant_state({"revoked_at": None, "expires_at": past}, now) == "expired"
    assert grant_state({"revoked_at": past, "expires_at": past}, now) == "revoked"
    assert grant_state({"revoked_at": past, "expires_at": future}, now) == "revoked"


# ── database layer ───────────────────────────────────────────────────────────

def test_create_grant_returns_the_full_row_with_state(gdb):
    g = _grant(gdb, ttl=300)
    assert g["agent"] == "hermes" and g["tool"] == "skill_manage"
    assert g["granted_by"] == "kevin-phone" and g["granted_via"] == "app-token"
    assert g["request_id"] == "r1" and g["revoked_at"] is None
    assert g["state"] == "active"
    assert g["expires_at"] > g["created_at"]
    assert gdb.get_grant(g["id"]) == g


def test_get_grant_unknown_id_is_none(gdb):
    assert gdb.get_grant("no-such-grant") is None


def test_find_active_grant_matches_both_keys_exactly(gdb):
    _grant(gdb, agent="hermes", tool="skill_manage")
    assert gdb.find_active_grant("hermes", "skill_manage") is not None
    assert gdb.find_active_grant("iris", "skill_manage") is None       # agent mismatch
    assert gdb.find_active_grant("hermes", "shell") is None            # tool mismatch
    assert gdb.find_active_grant("HERMES", "skill_manage") is None     # no case folding
    assert gdb.find_active_grant("herm", "skill_manage") is None       # no prefix match


def test_find_active_grant_ignores_expired_and_revoked(gdb):
    expired = _grant(gdb, ttl=1)
    gdb.conn.execute("UPDATE grants SET expires_at=? WHERE id=?",
                     (_iso(_now() - timedelta(seconds=1)), expired["id"]))
    gdb.conn.commit()
    assert gdb.find_active_grant("hermes", "skill_manage") is None

    live = _grant(gdb, ttl=300)
    assert gdb.find_active_grant("hermes", "skill_manage")["id"] == live["id"]
    gdb.revoke_grant(live["id"])
    assert gdb.find_active_grant("hermes", "skill_manage") is None


def test_find_active_grant_picks_the_one_expiring_last(gdb):
    """Re-granting before the first ran out must never SHORTEN cover."""
    short = _grant(gdb, ttl=60)
    long_ = _grant(gdb, ttl=3600)
    assert gdb.find_active_grant("hermes", "skill_manage")["id"] == long_["id"]
    gdb.revoke_grant(long_["id"])
    assert gdb.find_active_grant("hermes", "skill_manage")["id"] == short["id"]


def test_revoke_grant_is_idempotent_and_reports_whether_it_changed(gdb):
    g = _grant(gdb)
    row, changed = gdb.revoke_grant(g["id"])
    assert changed is True and row["revoked_at"] is not None and row["state"] == "revoked"
    stamped = row["revoked_at"]
    row2, changed2 = gdb.revoke_grant(g["id"])
    assert changed2 is False and row2["revoked_at"] == stamped     # not re-stamped
    assert gdb.revoke_grant("no-such-grant") is None


def test_revoke_stamps_an_expired_but_unrevoked_grant(gdb):
    g = _grant(gdb, ttl=60)
    gdb.conn.execute("UPDATE grants SET expires_at=? WHERE id=?",
                     (_iso(_now() - timedelta(seconds=1)), g["id"]))
    gdb.conn.commit()
    row, changed = gdb.revoke_grant(g["id"])
    assert changed is True and row["state"] == "revoked"


def test_grants_are_never_deleted(gdb):
    g = _grant(gdb)
    gdb.revoke_grant(g["id"])
    assert gdb.conn.execute("SELECT count(*) FROM grants").fetchone()[0] == 1


def test_list_grants_active_first_then_recent_each_newest_first(gdb):
    old_active = _grant(gdb, tool="a", ttl=3600)
    new_active = _grant(gdb, tool="b", ttl=3600)
    revoked = _grant(gdb, tool="c", ttl=3600)
    gdb.revoke_grant(revoked["id"])
    ids = [g["id"] for g in gdb.list_grants()]
    assert ids[:2] == [new_active["id"], old_active["id"]]   # active, newest first
    assert ids[2] == revoked["id"]                            # inert last
    assert [g["state"] for g in gdb.list_grants()] == ["active", "active", "revoked"]


def test_list_grants_drops_rows_inert_for_more_than_the_window(gdb):
    stale = _grant(gdb, tool="stale", ttl=60)
    gdb.conn.execute("UPDATE grants SET expires_at=? WHERE id=?",
                     (_iso(_now() - timedelta(seconds=GRANT_RECENT_SECONDS + 60)), stale["id"]))
    gdb.conn.commit()
    recent = _grant(gdb, tool="recent", ttl=60)
    gdb.conn.execute("UPDATE grants SET expires_at=? WHERE id=?",
                     (_iso(_now() - timedelta(seconds=60)), recent["id"]))
    gdb.conn.commit()
    listed = {g["id"] for g in gdb.list_grants()}
    assert recent["id"] in listed and stale["id"] not in listed
    assert stale["id"] in {g["id"] for g in gdb.find_grants_by_prefix("")}  # still on disk


def test_find_grants_by_prefix_is_exact_prefix_not_a_pattern(gdb):
    g = _grant(gdb)
    assert [m["id"] for m in gdb.find_grants_by_prefix(g["id"])] == [g["id"]]
    assert [m["id"] for m in gdb.find_grants_by_prefix(g["id"][:8])] == [g["id"]]
    assert gdb.find_grants_by_prefix("zzzzzzzz") == []
    assert gdb.find_grants_by_prefix("%") == []      # '%' is a literal, not a wildcard

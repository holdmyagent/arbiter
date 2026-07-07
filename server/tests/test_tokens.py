import sqlite3

import pytest

def test_create_and_get_by_hash(db):
    row = db.create_token("hermes", "agent", "h" * 64,
                          scopes={"action_types": ["deploy"], "max_severity": "high"},
                          expires_at="2027-01-01T00:00:00+00:00")
    assert row["name"] == "hermes" and row["role"] == "agent"
    assert row["token_hash"] == "h" * 64
    assert row["scopes"] == {"action_types": ["deploy"], "max_severity": "high"}
    assert row["expires_at"] == "2027-01-01T00:00:00+00:00"
    assert row["created_at"] and row["last_used_at"] is None and row["revoked_at"] is None
    got = db.get_token_by_hash("h" * 64)
    assert got["id"] == row["id"] and got["scopes"] == row["scopes"]
    assert db.get_token_by_hash("x" * 64) is None

def test_scopes_none_roundtrip(db):
    row = db.create_token("plain", "warden", "a" * 64)
    assert row["scopes"] is None
    assert db.get_token_by_hash("a" * 64)["scopes"] is None

def test_token_name_unique(db):
    db.create_token("dup", "agent", "1" * 64)
    with pytest.raises(sqlite3.IntegrityError):
        db.create_token("dup", "app", "2" * 64)

def test_token_role_check_constraint(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.create_token("bad", "root", "3" * 64)

def test_list_tokens_in_creation_order(db):
    db.create_token("a", "agent", "4" * 64)
    db.create_token("b", "warden", "5" * 64)
    assert [t["name"] for t in db.list_tokens()] == ["a", "b"]

def test_revoke_token_is_idempotent(db):
    db.create_token("gone", "agent", "6" * 64)
    row = db.revoke_token("gone")
    assert row["revoked_at"] is not None
    first = row["revoked_at"]
    assert db.revoke_token("gone")["revoked_at"] == first  # keeps the original timestamp
    assert db.revoke_token("never-existed") is None

def test_touch_token_last_used(db):
    row = db.create_token("used", "agent", "7" * 64)
    assert row["last_used_at"] is None
    db.touch_token_last_used(row["id"])
    assert db.get_token_by_hash("7" * 64)["last_used_at"] is not None

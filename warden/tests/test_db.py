"""hold_warden.db — WardenDB proposals store (SQLite, WAL, single-read secrets)."""
from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hold_warden.db import WardenDB


@pytest.fixture()
def db(tmp_path: Path) -> WardenDB:
    return WardenDB(tmp_path / "data" / "warden.sqlite3")


def _mk(db: WardenDB, agent: str = "hermes", idem: str | None = None) -> dict:
    return db.create_proposal(
        agent=agent,
        action="restart_service",
        params={"unit": "nginx"},
        canonical='{"action":"restart_service","v":1}',
        action_hash="ab" * 32,
        request_id="req-" + uuid.uuid4().hex[:8],
        idempotency_key=idem,
    )


def test_create_and_get_round_trip(db):
    p = _mk(db, idem="k1")
    assert p["status"] == "pending"
    assert p["agent"] == "hermes"
    assert p["action"] == "restart_service"
    assert p["params"] == {"unit": "nginx"}  # decoded dict, not JSON text
    assert p["canonical"] == '{"action":"restart_service","v":1}'
    assert p["action_hash"] == "ab" * 32
    assert p["request_id"].startswith("req-")
    assert p["idempotency_key"] == "k1"
    assert p["result"] is None and p["receipt"] is None
    datetime.fromisoformat(p["created_at"])
    datetime.fromisoformat(p["updated_at"])
    assert db.get(p["id"]) == p


def test_get_missing_returns_none(db):
    assert db.get("nope") is None


def test_wal_mode_enabled(db):
    assert db._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_parent_dir_created(tmp_path):
    WardenDB(tmp_path / "deep" / "nested" / "warden.sqlite3")  # must not raise


def test_get_by_idem(db):
    p = _mk(db, idem="k1")
    assert db.get_by_idem("hermes", "k1")["id"] == p["id"]
    assert db.get_by_idem("hermes", "other") is None
    assert db.get_by_idem("not-hermes", "k1") is None


def test_idempotency_key_unique_per_agent(db):
    _mk(db, idem="k1")
    with pytest.raises(sqlite3.IntegrityError):
        _mk(db, idem="k1")                    # same (agent, key): rejected
    _mk(db, agent="other-agent", idem="k1")   # same key, different agent: fine
    _mk(db, idem=None)                        # NULL keys never collide (partial index)
    _mk(db, idem=None)

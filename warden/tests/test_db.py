"""hold_warden.db — WardenDB proposals store (SQLite, WAL, single-read secrets)."""
from __future__ import annotations

import json
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


def test_pending_returns_pending_and_executing_only(db):
    p1 = _mk(db)
    p2 = _mk(db)
    p3 = _mk(db)
    p4 = _mk(db)
    db.set_status(p2["id"], "executing")
    db.set_status(p3["id"], "executed")
    db.set_status(p4["id"], "denied")
    ids = {row["id"] for row in db.pending()}
    assert ids == {p1["id"], p2["id"]}


def test_set_status_stores_result_and_receipt(db):
    p = _mk(db)
    result = {"exit_code": 0, "stdout_tail": "ok\n", "stderr_tail": "", "duration_ms": 12}
    receipt = {"request_id": "req-1", "action_hash": "ab" * 32, "decision": "approved",
               "decided_at": "2026-07-06T00:00:00+00:00", "verdict_jws": "e.y.j",
               "executed_at": "2026-07-06T00:00:01+00:00"}
    db.set_status(p["id"], "executed", result=result, receipt=receipt)
    row = db.get(p["id"])
    assert row["status"] == "executed"
    assert row["result"] == result
    assert row["receipt"] == receipt


def test_set_status_without_result_keeps_existing(db):
    p = _mk(db)
    db.set_status(p["id"], "executed", result={"secret": "hunter2"})
    db.set_status(p["id"], "failed")  # status-only update must not clobber result/receipt
    row = db.get(p["id"])
    assert row["status"] == "failed"
    assert row["result"] == {"secret": "hunter2"}


def test_purge_older_than_deletes_only_old_rows(db):
    # No sleeping: backdate created_at directly in SQL to simulate age.
    old = _mk(db)
    fresh = _mk(db)
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
    db._conn.execute("UPDATE proposals SET created_at=? WHERE id=?", (stale_ts, old["id"]))
    db._conn.commit()
    assert db.purge_older_than(7) == 1
    assert db.get(old["id"]) is None
    assert db.get(fresh["id"]) is not None
    assert db.purge_older_than(7) == 0


def test_take_secret_result_single_read(db):
    p = _mk(db)
    db.set_status(p["id"], "executed", result={"secret": "hunter2"},
                  receipt={"decision": "approved"})
    assert db.take_secret_result(p["id"]) == {"secret": "hunter2"}
    assert db.take_secret_result(p["id"]) is None       # second read: gone
    row = db.get(p["id"])
    assert row["result"] is None                        # value destroyed
    assert row["status"] == "executed"                  # status intact
    assert row["receipt"] == {"decision": "approved"}   # receipt intact


def test_take_secret_result_missing_proposal(db):
    assert db.take_secret_result("nope") is None


def test_take_secret_result_two_threads_exactly_one_wins(db):
    p = _mk(db)
    db.set_status(p["id"], "executed", result={"secret": "hunter2"})
    barrier = threading.Barrier(2)
    results: list[dict | None] = []
    results_lock = threading.Lock()

    def taker():
        barrier.wait()  # maximize contention: both threads race the take together
        value = db.take_secret_result(p["id"])
        with results_lock:
            results.append(value)

    threads = [threading.Thread(target=taker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(None) == 1
    assert {"secret": "hunter2"} in results


def test_set_status_executed_with_payload_is_a_single_update(db):
    """0.7 S2: 'executed' and the owed report used to be two UPDATEs in two
    commits — a kill between them lost the outcome forever. Trace every
    statement the call issues and prove exactly one UPDATE carries both."""
    p = _mk(db)
    payload = {"exit_code": 0, "ran": "echo hi", "output": "hi\n", "kind": "command"}
    seen: list[str] = []
    db._conn.set_trace_callback(seen.append)
    db.set_status(p["id"], "executed", result={"exit_code": 0},
                  receipt={"request_id": "req-1"}, report_payload=payload)
    db._conn.set_trace_callback(None)

    updates = [s for s in seen if s.strip().upper().startswith("UPDATE")]
    assert len(updates) == 1
    # sqlite3's trace callback reports the expanded statement (bound params
    # substituted in), never the literal "?" placeholders - assert on the
    # substituted form.
    assert "status='executed'" in updates[0] and "report_pending=" in updates[0]
    row = db.get(p["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 1
    assert json.loads(row["report_payload"]) == payload
    assert row["report_next_at"] is None
    # …and that is exactly the shape reports_due filters on, so the retry sweep
    # picks the row up immediately (status='executed' AND report_pending=1).
    due = db.reports_due(datetime.now(timezone.utc).isoformat())
    assert [r["id"] for r in due] == [p["id"]]


def test_set_status_without_payload_leaves_report_bookkeeping_alone(db):
    """Every other set_status caller (failed/denied/expired/executing) passes no
    payload and must neither arm nor clear the report flag."""
    p = _mk(db)
    payload = {"exit_code": 0, "ran": "echo hi", "output": "hi\n", "kind": "command"}
    db.set_status(p["id"], "executed", report_payload=payload)
    db.set_status(p["id"], "failed")
    row = db.get(p["id"])
    assert row["status"] == "failed"
    assert row["report_pending"] == 1
    assert json.loads(row["report_payload"]) == payload

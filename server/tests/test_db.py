from datetime import timedelta, timezone
from datetime import datetime as _dt

from arbiter.db import Database
from arbiter.models import RequestCreate


def test_create_and_get(db, make):
    r = db.create_request(make(payload={"k":1}, severity="high"))
    got = db.get_request(r["id"])
    assert got["payload"] == {"k":1} and got["status"]=="pending" and got["severity"]=="high"

def test_decision_is_terminal(db, make):
    r = db.create_request(make())
    assert db.set_decision(r["id"], "approve", "iPhone")["status"]=="approved"
    assert db.set_decision(r["id"], "deny", "iPhone") is None

def test_expire_due(db, make):
    r = db.create_request(make(ttl_seconds=-1))
    expired = db.expire_due()
    assert [e["id"] for e in expired] == [r["id"]] and expired[0]["status"] == "expired"
    assert db.get_request(r["id"])["status"]=="expired"
    events = [a["event"] for a in db.get_audit(r["id"])]
    assert "created" in events and "expired" in events

def test_list_filters_by_status(db, make):
    a = db.create_request(make())
    b = db.create_request(make())
    db.set_decision(b["id"], "approve", "iPhone")
    pending = db.list_requests("pending")
    assert len(pending) == 1 and pending[0]["id"] == a["id"]
    assert len(db.list_requests()) == 2

def test_expires_at_computed(db, make):
    from datetime import datetime
    r = db.create_request(make(ttl_seconds=300))
    created = datetime.fromisoformat(r["created_at"])
    expires = datetime.fromisoformat(r["expires_at"])
    assert (expires - created).total_seconds() == 300

def test_list_audit_joins_severity_and_decided_device(db, make):
    db.register_device("tok1", "iPhone")
    r = db.create_request(make(severity="high"))
    db.set_decision(r["id"], "approve", "iPhone")
    rows = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows["approved"]["severity"] == "high"
    assert rows["approved"]["req_title"] == "t"
    assert rows["approved"]["decided_by"] == "iPhone"
    assert rows["approved"]["decided_device"] == "iPhone"

def test_list_audit_decided_device_none_when_no_match(db, make):
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "app")
    rows = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows["approved"]["decided_by"] == "app"
    assert rows["approved"]["decided_device"] is None

def test_list_audit_non_request_event_has_none_severity(db):
    db.add_audit("-", "token_rotated", {"which": "agent"})
    rows = db.list_audit()
    row = next(a for a in rows if a["event"] == "token_rotated")
    assert row["severity"] is None and row["req_title"] is None
    assert row["decided_device"] is None

def test_ping_takes_the_lock_and_raises_when_closed(db):
    # /health calls db.ping(); like every Database method it must go through
    # self._lock (shared-connection RLock discipline, see db.py:77-90 comment).
    import pytest
    import sqlite3
    entered = []
    real = db._lock
    class SpyLock:
        def __enter__(self):
            entered.append(True)
            return real.__enter__()
        def __exit__(self, *a):
            return real.__exit__(*a)
    db._lock = SpyLock()
    db.ping()
    assert entered == [True]
    db._lock = real
    db.conn.close()
    with pytest.raises(sqlite3.ProgrammingError):
        db.ping()

def _past_iso(seconds=60):
    return (_dt.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()

def test_expire_request_with_verdict_atomic_flip():
    db = Database(":memory:")
    req = db.create_request(RequestCreate(title="t", ttl_seconds=300))
    # force it overdue
    with db._lock:
        db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?",
                        (_past_iso(), req["id"]))
        db.conn.commit()
    out = db.expire_request_with_verdict(req["id"], "JWS.B64.SIG", "default:abc123de")
    assert out is not None
    assert out["status"] == "expired"
    assert out["verdict_jws"] == "JWS.B64.SIG"
    assert out["verdict_kid"] == "default:abc123de"
    events = [a["event"] for a in db.get_audit(req["id"])]
    assert "expired" in events and "verdict_issued" in events

def test_expire_request_with_verdict_loses_to_decision():
    db = Database(":memory:")
    req = db.create_request(RequestCreate(title="t", ttl_seconds=300))
    # a decision won first: row is now 'approved', not 'pending'
    db.set_decision(req["id"], "approve", "phone")
    out = db.expire_request_with_verdict(req["id"], "X", "default:kid")
    assert out is None                      # guard refused: not pending
    assert db.get_request(req["id"])["status"] == "approved"
    assert db.get_request(req["id"])["verdict_jws"] is None

def test_open_deadline_rows_covers_pending_and_unconsumed_approved():
    db = Database(":memory:")
    p = db.create_request(RequestCreate(title="pending", ttl_seconds=300))
    a = db.create_request(RequestCreate(title="approved", ttl_seconds=300))
    db.set_decision(a["id"], "approve", "phone")               # approved, unconsumed
    d = db.create_request(RequestCreate(title="denied", ttl_seconds=300))
    db.set_decision(d["id"], "deny", "phone")                  # terminal, excluded
    ids = {r["id"] for r in db.open_deadline_rows()}
    assert p["id"] in ids and a["id"] in ids
    assert d["id"] not in ids

def test_expired_without_verdict():
    db = Database(":memory:")
    r = db.create_request(RequestCreate(title="t", ttl_seconds=300))
    with db._lock:                                             # simulate crash after flip, before verdict
        db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
        db.conn.commit()
    rows = db.expired_without_verdict()
    assert [x["id"] for x in rows] == [r["id"]]
    db.set_verdict(r["id"], "JWS", "kid")                      # once signed, no longer returned

def test_iter_audit_batches_cover_all_rows_in_order(db):
    for i in range(5):
        db.add_audit(f"r{i}", "created", {"i": i})
    rows = list(db.iter_audit(batch=2))              # forces 3 keyset fetches
    assert len(rows) == 5
    assert {r["detail"]["i"] for r in rows} == set(range(5))
    keys = [(r["at"], r["id"]) for r in rows]
    assert keys == sorted(keys)                      # oldest-first (at, id), like before
    assert rows == list(db.iter_audit())             # default batch agrees
    assert db.expired_without_verdict() == []

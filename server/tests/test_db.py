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

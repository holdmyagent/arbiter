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

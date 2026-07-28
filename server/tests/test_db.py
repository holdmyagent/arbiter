import json
import uuid
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

def test_list_audit_decided_device_survives_device_rename_via_attest_key_id(db, make):
    """F.1.5: decided_device must be keyed on devices.id (immutable), never
    devices.name (user-renameable). Once a decision records a verified
    attest_key_id, renaming the device must not lose or misattribute that
    historical decision -- the old name-match join would go stale (None)
    the moment the device is renamed; the id-based join follows the rename."""
    dev = db.register_device("tok1", "Old Name")
    key = db.enroll_device_key(dev["id"], "irrelevant-pubkey-b64")
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "someone")
    db.set_attestation(r["id"], "attested", key["id"])
    rows = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows["approved"]["decided_device"] == "Old Name"
    db.rename_device(dev["id"], "New Name")
    rows2 = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows2["approved"]["decided_device"] == "New Name"

def test_list_audit_decided_device_none_for_grant_row_even_if_name_matches(db, make):
    """A decided_via='grant' row's decided_by names the OPERATOR who issued the
    grant (an identity, e.g. "kevin-phone" or a device's own name), never a
    device that tapped -- but the legacy name-match fallback join only looks
    at devices.name, with no way to tell "this identity happens to equal a
    device name" apart from "a device actually decided this". If an operator
    ever registers a device under the same string used elsewhere as an
    identity, that fallback must not resolve a decided_device for a grant
    row: doing so would paint a phone-tap glyph on a request no phone ever
    saw."""
    db.register_device("tok1", "hermes-phone")
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "hermes-phone", decided_via="grant")
    rows = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows["approved"]["decided_device"] is None


def test_list_audit_decided_device_still_resolves_for_app_token_decision(db, make):
    """Regression guard for the grant-row fix above: an ordinary app-token
    decision (decided_via='app-token', the common case) must still resolve
    its device through the very same fallback."""
    db.register_device("tok1", "iPhone")
    r = db.create_request(make())
    db.set_decision(r["id"], "approve", "iPhone", decided_via="app-token")
    rows = {a["event"]: a for a in db.list_audit(r["id"])}
    assert rows["approved"]["decided_device"] == "iPhone"


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
    assert db.expired_without_verdict() == []

def test_iter_audit_batches_cover_all_rows_in_order(db):
    for i in range(5):
        db.add_audit(f"r{i}", "created", {"i": i})
    rows = list(db.iter_audit(batch=2))              # forces 3 keyset fetches
    assert len(rows) == 5
    assert {r["detail"]["i"] for r in rows} == set(range(5))
    keys = [(r["at"], r["id"]) for r in rows]
    assert keys == sorted(keys)                      # oldest-first (at, id), like before
    assert rows == list(db.iter_audit())             # default batch agrees

def test_iter_audit_tiebreaks_on_id_within_same_at(db):
    # Several rows sharing one `at` timestamp (a same-millisecond burst) must
    # all come back exactly once at every batch size: a naive `at > last_at`
    # keyset predicate (instead of the tuple `(at, id) > (?, ?)`) would
    # silently skip every tie-group member after a page boundary landed
    # mid-tie -- the classic keyset-skip bug item 7's guard exists for.
    tied_at = "2026-01-01T00:00:00.000000+00:00"
    ids = sorted(str(uuid.uuid4()) for _ in range(6))
    with db._lock:
        for i, rid in enumerate(ids):
            db.conn.execute(
                "INSERT INTO audit VALUES (?,?,?,?,?)",
                (rid, f"r{i}", "created", tied_at, json.dumps({"i": i})))
        db.conn.commit()
    full = list(db.iter_audit())
    assert [r["id"] for r in full] == ids             # full read, tie broken by id
    for batch in (1, 2, 3):
        paged = list(db.iter_audit(batch=batch))
        assert [r["id"] for r in paged] == ids        # same order at every batch size


def test_prune_audit_deletes_only_rows_older_than_the_window(db):
    """0.7 S6. No sleeping: backdate `at` directly in SQL to simulate age.
    (`_dt`, `timedelta` and `timezone` are already imported at the top of this
    file.)"""
    db.add_audit("-", "stale")
    db.add_audit("-", "fresh")
    old = (_dt.now(timezone.utc) - timedelta(days=40)).isoformat()
    with db._lock:
        db.conn.execute("UPDATE audit SET at=? WHERE event='stale'", (old,))
        db.conn.commit()

    assert db.prune_audit(30) == 1
    assert [r["event"] for r in db.list_audit()] == ["fresh"]
    assert db.prune_audit(30) == 0                     # idempotent


def test_prune_audit_never_touches_requests(db, make):
    """R5: the audit table only. A request row — the product's evidence — is
    never deleted, however old it is."""
    req = db.create_request(make(title="ancient"))
    old = (_dt.now(timezone.utc) - timedelta(days=400)).isoformat()
    with db._lock:
        db.conn.execute("UPDATE requests SET created_at=? WHERE id=?", (old, req["id"]))
        db.conn.execute("UPDATE audit SET at=?", (old,))
        db.conn.commit()

    assert db.prune_audit(30) >= 1
    assert db.get_request(req["id"]) is not None

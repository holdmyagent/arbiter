import hashlib
from datetime import datetime, timezone
from pathlib import Path
from arbiter.control import ControlPlane
from arbiter.db import Database
from arbiter.provisioning import (provision_tenant, backup_fleet, reconcile_routes,
                                  revoke_cell_token)

def _now(): return datetime.now(timezone.utc).isoformat()
def _h(v): return hashlib.sha256(v.encode()).hexdigest()

def _insert(db, rid, status, *, decided=None, consumed=None):
    db.conn.execute(
        "INSERT INTO requests(id,created_at,title,severity,status,ttl_seconds,"
        "expires_at,decided_at,consumed_at,payload) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rid, _now(), "t", "high", status, 300, _now(), decided, consumed, "{}"))
    db.conn.commit()

def test_invalidate_in_flight_flips_pending_and_unconsumed_approved(tmp_path):
    db = Database(":memory:")
    _insert(db, "p", "pending")
    _insert(db, "a", "approved", decided=_now())              # approved, unconsumed
    _insert(db, "c", "approved", decided=_now(), consumed=_now())  # already consumed
    _insert(db, "d", "denied")
    assert db.invalidate_in_flight() == 2
    assert db.get_request("p")["status"] == "expired"
    assert db.get_request("a")["status"] == "expired"
    assert db.get_request("c")["status"] == "approved"   # consumed rows untouched
    assert db.get_request("d")["status"] == "denied"

def test_active_token_hashes_excludes_revoked(tmp_path):
    db = Database(":memory:")
    db.create_token("a", "app", "h_a")
    db.create_token("b", "app", "h_b")
    db.revoke_token("b")
    assert db.active_token_hashes() == {"h_a"}

def test_backup_to_produces_readable_snapshot(tmp_path):
    src = Database(str(tmp_path / "src.sqlite3"))
    src.create_token("x", "app", "h_x")
    dest = tmp_path / "snap.sqlite3"
    src.backup_to(str(dest))
    assert Database(str(dest)).active_token_hashes() == {"h_x"}

def test_backup_fleet_writes_control_last_and_per_cell(tmp_path):
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    provision_tenant(control, tmp_path / "tenants", "acme")
    out = tmp_path / "bk"
    backup_fleet(control, out)
    assert (out / "control.sqlite3").is_file()
    assert (out / "tenants" / "acme.sqlite3").is_file()

def test_reconcile_drops_route_without_live_cell_token(tmp_path):
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    res = provision_tenant(control, tmp_path / "tenants", "acme")
    cell = Database(str(res.dir / "arbiter.sqlite3"))
    cell.revoke_token("app")                  # cell no longer has a live token for that hash
    dropped = reconcile_routes(tmp_path / "control" / "control.db")
    assert dropped >= 1
    assert control.resolve(_h(res.app_token)) is None   # orphan route removed → fail closed

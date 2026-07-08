import hashlib
from datetime import datetime, timezone
from pathlib import Path
from arbiter.control import ControlPlane
from arbiter.db import Database
from arbiter.provisioning import (provision_tenant, backup_fleet, reconcile_routes,
                                  revoke_cell_token, snapshot_db, restore_fleet)

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

def test_restore_prerevoke_smear_keeps_token_invalid(tmp_path):
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    res = provision_tenant(control, tmp_path / "tenants", "acme")
    cell_path = res.dir / "arbiter.sqlite3"
    control_db_path = tmp_path / "control" / "control.db"
    backup = tmp_path / "bk"; (backup / "tenants").mkdir(parents=True)
    # (1) cell snapshot FIRST — pre-revoke: token present + unrevoked
    snapshot_db(cell_path, backup / "tenants" / "acme.sqlite3")
    # (2) revoke happens between the two snapshots (cell revoked_at + route removed)
    revoke_cell_token(control, Database(str(cell_path)), "app")
    # (3) control snapshot LAST — post-revoke: route already gone
    snapshot_db(control_db_path, backup / "control.sqlite3")
    # restore the smeared backup and resolve the app token
    restore_fleet(control_db_path, backup)
    control2 = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    assert control2.resolve(_h(res.app_token)) is None   # invalid: route absent → fail closed

def test_restore_preconsume_snapshot_forces_remint_no_second_execution(tmp_path):
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    res = provision_tenant(control, tmp_path / "tenants", "acme")
    cell_path = res.dir / "arbiter.sqlite3"
    control_db_path = tmp_path / "control" / "control.db"
    cell = Database(str(cell_path))
    now = datetime.now(timezone.utc).isoformat()
    cell.conn.execute(
        "INSERT INTO requests(id,created_at,title,severity,status,ttl_seconds,"
        "expires_at,decided_at,payload) VALUES (?,?,?,?,?,?,?,?,?)",
        ("r1", now, "pay", "high", "approved", 300, now, now, "{}")); cell.conn.commit()
    backup = tmp_path / "bk"; (backup / "tenants").mkdir(parents=True)
    snapshot_db(cell_path, backup / "tenants" / "acme.sqlite3")     # pre-consume
    snapshot_db(control_db_path, backup / "control.sqlite3")
    # the approval is consumed + executed
    assert cell.consume_request("r1", approval_ttl_seconds=600)[0] == 200
    # DISASTER: roll back to the pre-consume snapshot
    restore_fleet(control_db_path, backup)
    cell2 = Database(str(cell_path))
    assert cell2.get_request("r1")["status"] == "expired"          # re-minted / invalidated
    assert cell2.consume_request("r1", approval_ttl_seconds=600)[0] != 200  # no second execution

import hashlib
import shutil
import sqlite3
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
    backup = tmp_path / "bk"
    (backup / "tenants").mkdir(parents=True)
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
        ("r1", now, "pay", "high", "approved", 300, now, now, "{}"))
    cell.conn.commit()
    backup = tmp_path / "bk"
    (backup / "tenants").mkdir(parents=True)
    snapshot_db(cell_path, backup / "tenants" / "acme.sqlite3")     # pre-consume
    snapshot_db(control_db_path, backup / "control.sqlite3")
    # the approval is consumed + executed
    assert cell.consume_request("r1", approval_ttl_seconds=600)[0] == 200
    # DISASTER: roll back to the pre-consume snapshot
    restore_fleet(control_db_path, backup)
    cell2 = Database(str(cell_path))
    assert cell2.get_request("r1")["status"] == "expired"          # re-minted / invalidated
    assert cell2.consume_request("r1", approval_ttl_seconds=600)[0] != 200  # no second execution

def test_restore_strips_stale_control_wal_no_post_backup_replay(tmp_path):
    """Reviewer-proven regression (§12): a live control.db-wal left by a crashed
    server carries committed-but-uncheckpointed frames. The old restore_fleet did
    a raw shutil.copyfile of control.sqlite3 onto control_db_path WITHOUT first
    stripping control_db_path's own stale -wal/-shm (unlike the cell path, which
    already did this) — so on next open, SQLite replayed those post-backup
    frames onto the "restored" file. This is NOT backstopped by reconcile_routes
    in general: it only drops routes whose token has no live cell counterpart,
    and a fully-minted post-backup tenant (real cell dir + real live token) sails
    right through it. This test mints a whole tenant AFTER the backup, proves the
    raw-copy-without-strip really does replay it (the reviewer's exact finding),
    then proves restore_fleet's fixed code path rolls it back cleanly."""
    control = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    provision_tenant(control, tmp_path / "tenants", "acme")          # pre-backup tenant
    control_db_path = tmp_path / "control" / "control.db"
    control_wal = Path(str(control_db_path) + "-wal")

    backup = tmp_path / "bk"
    (backup / "tenants").mkdir(parents=True)
    backup_fleet(control, backup)                                    # clean, pre-"evil" snapshot

    # POST-backup disaster: a whole new tenant is minted (real cell dir, real
    # live cell token) while the SAME control connection stays open, so the
    # roster row + its token route land only in control.db-wal, never
    # checkpointed to the main file — exactly what a crash leaves behind.
    evil = provision_tenant(control, tmp_path / "tenants", "evil")
    evil_hash = _h(evil.app_token)
    assert control.resolve(evil_hash) is not None            # live: visible via the open connection
    assert control_wal.exists() and control_wal.stat().st_size > 0   # frames live ONLY in the WAL

    # --- demonstrate the reviewer's finding: a raw copy that does NOT strip the
    # destination's stale sidecars DOES replay the post-backup tenant, contrary
    # to the false "SQLite discards on salt mismatch" claim ---
    raw_dest = tmp_path / "raw_replay_demo" / "control.db"
    raw_dest.parent.mkdir()
    shutil.copyfile(backup / "control.sqlite3", raw_dest)     # the stale main-file copy...
    shutil.copyfile(control_wal, str(raw_dest) + "-wal")      # ...paired with the live stale WAL
    conn = sqlite3.connect(str(raw_dest))
    try:
        row = conn.execute(
            "SELECT tenant_id FROM token_route WHERE token_hash=?", (evil_hash,)).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == "evil"   # proves: un-stripped raw copy DOES replay

    # --- the actual fix: restore_fleet must strip control_db_path's sidecars
    # first, so the same stale WAL cannot replay onto the restored file ---
    restore_fleet(control_db_path, backup)
    assert not control_wal.exists()
    assert not Path(str(control_db_path) + "-shm").exists()
    control2 = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    assert control2.resolve(evil_hash) is None   # clean rollback: post-backup tenant did not survive

"""§16 backup/restore fail-closed gate (I17): a restored pre-revoke snapshot
keeps a killed token invalid; a restored pre-consume snapshot makes consume
fail closed (no replay) — §15.12/§12.

Reconciliations against the actual H7/H8 producers (the brief's
`arbiter.backup.snapshot/restore` module does not exist):
  - snapshot  -> `arbiter.provisioning.backup_fleet(control, out_dir)`
  - restore   -> `arbiter.provisioning.restore_fleet(control_db_path, backup_dir)`
    (runs reconcile_routes + invalidate_in_flight internally — no separate
    `reconcile_on_open` call needed)

CRITICAL: restore_fleet is an OFFLINE file-replace — it unlinks+copies the
control.db and cell db files on disk. The live `control`/`registry` objects
used to set up each scenario hold OPEN connections to the OLD files, so their
handles go stale the moment restore_fleet runs. Every post-restore assertion
below re-opens a FRESH `ControlPlane.open(...)` + `TenantRegistry(...)` from
the restored files first (mirrors H8's own tests in
`server/tests/test_backup_restore.py`).
"""
import asyncio
import hashlib

from arbiter.models import RequestCreate
from arbiter.provisioning import backup_fleet, restore_fleet

from tests.isolation.conftest import ControlPlane, TenantRegistry, mint_into_cell


def _fresh(tmp_path, cfg, name="t"):
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)
    d = root / name
    d.mkdir(parents=True)
    epoch = control.create_tenant(name, str(d))
    return root, control, registry, name, epoch


def _no_live_cell_token(registry, tid, epoch, th):
    async def _q():
        async with registry.hold(tid, epoch) as cell:
            row = cell.db.get_token_by_hash(th)
            return row is None or row["revoked_at"] is not None
    return asyncio.run(_q())


def test_restore_pre_revoke_snapshot_keeps_token_invalid(tmp_path, cfg):
    root, control, registry, tid, epoch = _fresh(tmp_path, cfg)
    bearer = mint_into_cell(control, registry, tid, epoch, "leaked", "agent")
    th = hashlib.sha256(bearer.encode()).hexdigest()

    # Revoke IN THE CELL ONLY first (matches revoke_cell_token's real ordering:
    # cell-side revoked_at is written before the router-side route removal).
    async def revoke_cell_only():
        async with registry.hold(tid, epoch) as cell:
            cell.db.revoke_token("leaked")
    asyncio.run(revoke_cell_only())

    # Snapshot NOW, before the router-side removal lands: cells-first/control-
    # last (§12) means the backup captures the cell ALREADY revoked, but the
    # control-side route STILL PRESENT — a stale "pre-revoke route" backup.
    dest = tmp_path / "snap1"
    backup_fleet(control, dest)

    # The revoke's router-side half completes on the LIVE store, after the
    # backup was taken (a real production revoke, unaware a stale backup
    # exists).
    control.remove_route(th)

    # Disaster: restore the stale backup. Its control.db still has the route;
    # only the reconcile step run inside restore_fleet (comparing against the
    # restored cell's own live-token set) can drop it and keep the token dead.
    restore_fleet(control.db_path, dest)

    control2 = ControlPlane.open(root / "control", root)
    TenantRegistry(control2, cfg=cfg, sender=None)
    assert control2.resolve(th) is None


def test_restore_pre_consume_snapshot_consume_fails_closed(tmp_path, cfg):
    root, control, registry, tid, epoch = _fresh(tmp_path, cfg)

    async def setup_and_approve():
        async with registry.hold(tid, epoch) as cell:
            req = cell.db.create_request(RequestCreate(title="pay", ttl_seconds=600))
            cell.db.set_decision(req["id"], "approve", "app")
            return req["id"]
    rid = asyncio.run(setup_and_approve())

    # Snapshot the approved-but-unconsumed state.
    dest = tmp_path / "snap2"
    backup_fleet(control, dest)

    # The action executes: consume it (money moves).
    async def consume():
        async with registry.hold(tid, epoch) as cell:
            return cell.db.consume_request(rid, approval_ttl_seconds=600)
    code, _ = asyncio.run(consume())
    assert code == 200

    # Disaster: roll back to the pre-consume snapshot. restore_fleet must force
    # invalidate_in_flight on the restored cell so the re-appeared
    # approved-unconsumed row cannot be consumed a second time (§12).
    restore_fleet(control.db_path, dest)

    control2 = ControlPlane.open(root / "control", root)
    registry2 = TenantRegistry(control2, cfg=cfg, sender=None)

    async def consume2():
        async with registry2.hold(tid, epoch) as cell:
            return cell.db.consume_request(rid, approval_ttl_seconds=600)
    code2, _ = asyncio.run(consume2())
    assert code2 != 200, "consume re-executed after restore — replay not fail-closed"

"""Task I19 (§16 scheduler-durability gate): a dropped heap-push is still
recovered by the level-triggered rescan; a cold cell's stale approval still
flips on rescan; a SIGTERM between the expire-flip commit and the sign commit
is recovered into a signed terminal verdict (§15.10/§6).

Each test wraps ITS ENTIRE scenario in a single asyncio.run(...) call. The
real TenantRegistry's _map_lock (and the scheduler's own _wake Event) bind to
whichever event loop first awaits them; a second asyncio.run() call spins up
a NEW loop and would hit "Future attached to a different loop" the moment the
scheduler or registry touched that state again. One asyncio.run per test
keeps everything on one loop (mirrors tests/isolation/test_refcount.py)."""
import asyncio
from datetime import datetime, timedelta, timezone

from arbiter.models import RequestCreate
from arbiter.scheduler import ExpiryScheduler
from tests.isolation.conftest import ControlPlane, TenantRegistry


def _reg(cfg, tmp_path):
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)
    d = root / "t"
    d.mkdir(parents=True)
    epoch = control.create_tenant("t", str(d))
    return control, registry, "t", epoch


def test_dropped_heap_push_is_recovered_by_the_rescan(cfg, tmp_path):
    control, registry, tid, epoch = _reg(cfg, tmp_path)
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)

    async def scenario():
        async with registry.hold(tid, epoch) as cell:
            rid = cell.db.create_request(RequestCreate(title="p", ttl_seconds=1))["id"]
        # deliberately DO NOT schedule() -- the heap-push was "dropped".
        fired = await sched.rescan(now=future)
        return rid, fired

    rid, fired = asyncio.run(scenario())
    assert rid in [r["id"] for r in fired], "rescan did not recover the un-scheduled row"


def test_cold_cell_stale_approval_flips_on_rescan(cfg, tmp_path):
    control, registry, tid, epoch = _reg(cfg, tmp_path)
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
    future = datetime.now(timezone.utc) + timedelta(days=1)  # past approval_ttl

    async def scenario():
        async with registry.hold(tid, epoch) as cell:
            rid = cell.db.create_request(RequestCreate(title="a", ttl_seconds=600))["id"]
            cell.db.set_decision(rid, "approve", "app")
        # deliberately never scheduled -- a cold cell's approval decision alone
        # never pushed a heap entry either.
        await sched.rescan(now=future)
        async with registry.hold(tid, epoch) as cell:
            return cell.db.get_request(rid)["status"]

    assert asyncio.run(scenario()) == "expired"


def test_recovery_signs_a_terminal_verdict_left_unsigned(cfg, tmp_path):
    control, registry, tid, epoch = _reg(cfg, tmp_path)
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds)

    async def scenario():
        # simulate SIGTERM between the flip commit and the sign commit:
        # status='expired' but verdict_jws IS NULL
        async with registry.hold(tid, epoch) as cell:
            rid = cell.db.create_request(RequestCreate(title="x", ttl_seconds=1))["id"]
            with cell.db._lock:
                cell.db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (rid,))
                cell.db.conn.commit()
        recovered = await sched.recover(now=datetime.now(timezone.utc))
        async with registry.hold(tid, epoch) as cell:
            return rid, recovered, cell.db.get_request(rid)["verdict_jws"]

    rid, recovered, jws = asyncio.run(scenario())
    assert rid in [r["id"] for r in recovered]
    assert jws, "recovery left an expired row without a terminal verdict"

"""Task I20 (§16 scheduler-fairness/FD-budget gate): alice's large batch of
overdue rows does not starve bob's single due row in one bounded tick, and a
cold-open-heavy tick never pushes the registry's live open-cell count past
the FD budget (§15.13/§6).

Each test wraps its ENTIRE scenario in a single asyncio.run(...) call -- the
real TenantRegistry's _map_lock (and the scheduler's own _wake Event) bind to
whichever event loop first awaits them, so a second asyncio.run() would hit
"Future attached to a different loop" (mirrors test_scheduler_durability.py /
test_refcount.py)."""
import asyncio
import heapq
from datetime import datetime, timedelta, timezone

from arbiter.models import RequestCreate
from arbiter.scheduler import ExpiryScheduler
from tests.isolation.conftest import ControlPlane, TenantRegistry


def _two(cfg, tmp_path):
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)
    epochs = {}
    for n in ("alice", "bob"):
        d = root / n
        d.mkdir(parents=True)
        epochs[n] = control.create_tenant(n, str(d))
    return control, registry, epochs


async def _seed(registry, epochs, tenant_id, count):
    async with registry.hold(tenant_id, epochs[tenant_id]) as cell:
        for i in range(count):
            cell.db.create_request(RequestCreate(title=f"{tenant_id}-{i}", ttl_seconds=1))


def test_one_tenants_batch_does_not_starve_the_other(cfg, tmp_path):
    control, registry, epochs = _two(cfg, tmp_path)
    cap = 5
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds,
                            per_tenant_batch=cap)
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)

    async def scenario():
        await _seed(registry, epochs, "alice", 50)   # large overdue batch
        await _seed(registry, epochs, "bob", 1)       # one overdue row
        fired = await sched.tick(now=future)          # ONE bounded, round-robin tick
        async with registry.hold("alice", epochs["alice"]) as cell:
            alice_expired = len(cell.db.list_requests("expired"))
        async with registry.hold("bob", epochs["bob"]) as cell:
            bob_expired = len(cell.db.list_requests("expired"))
        return fired, alice_expired, bob_expired

    fired, alice_expired, bob_expired = asyncio.run(scenario())
    assert fired, "tick fired nothing -- not a no-op"
    # bob's single due row expired in the SAME tick alice's 50-row batch was
    # drained round-robin -- it was not starved behind alice's batch.
    assert bob_expired == 1, "bob's expiry starved behind alice's batch"
    # structural fairness proof: alice's contribution to THIS tick was capped
    # (never all 50 in one pass), so the round-robin bound is real, not vacuous.
    assert alice_expired <= cap, "per-tenant batch cap was not honored for alice"


def test_removing_the_per_tenant_cap_would_have_starved_bob(cfg, tmp_path):
    """Non-vacuity mutation (§16, I20): monkeypatch _fire_due to a NAIVE variant
    that drains the globally due-ordered queue up to a single FLAT cap, with no
    per-tenant grouping/round-robin at all -- proving the real _fire_due's
    per-tenant grouping (not accident, not "a single tick fires everything
    anyway") is what keeps bob's row from starving behind alice's much larger,
    earlier-scheduled batch. If this naive variant did NOT starve bob, the
    fairness assertion above would hold regardless of the round-robin cap."""
    control, registry, epochs = _two(cfg, tmp_path)
    cap = 5
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds,
                            per_tenant_batch=cap)
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)

    async def naive_fire_due(now=None):
        # Same due-discovery as the real _fire_due, but fires a single FLAT
        # cap's worth of entries in heap (deadline/seq) order -- no grouping
        # by tenant, so a large earlier-created batch drains the whole cap
        # before a later tenant's row is ever reached.
        now_ts = now
        due = []
        while sched._heap and sched._heap[0][0] <= now_ts:
            due.append(heapq.heappop(sched._heap))
        head, tail = due[:cap], due[cap:]
        now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
        fired = []
        for entry in head:
            fired.extend(await sched._fire_one(entry, now=now_dt))
        for entry in tail:
            heapq.heappush(sched._heap, entry)
        return fired

    async def scenario():
        await _seed(registry, epochs, "alice", 50)
        await _seed(registry, epochs, "bob", 1)
        sched._fire_due = naive_fire_due   # remove the per-tenant round-robin
        await sched.tick(now=future)
        async with registry.hold("bob", epochs["bob"]) as cell:
            return len(cell.db.list_requests("expired"))

    bob_expired = asyncio.run(scenario())
    assert bob_expired == 0, \
        "expected the naive (uncapped-per-tenant) firer to starve bob -- " \
        "if it didn't, the fairness mechanism isn't load-bearing"


def test_fd_budget_never_exceeded_during_a_tick(cfg, tmp_path):
    control, registry, epochs = _two(cfg, tmp_path)
    sched = ExpiryScheduler(registry, control,
                            approval_ttl_seconds=cfg.policy.approval_ttl_seconds,
                            per_tenant_batch=5)
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)

    async def scenario():
        await _seed(registry, epochs, "alice", 20)
        await _seed(registry, epochs, "bob", 20)
        await sched.tick(now=future)   # cold-opens both cells via registry.hold

    asyncio.run(scenario())
    # non-vacuity: the tick's cold opens actually left live cells behind, so
    # the inequality below is exercising real state, not 0 < budget trivially.
    assert registry.open_cell_count() > 0, "tick opened no cells -- inequality would be vacuous"
    assert registry.open_cell_count() * 3 + registry.fd_headroom() < registry.fd_budget()

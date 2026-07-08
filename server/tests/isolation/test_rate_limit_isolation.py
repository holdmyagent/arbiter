"""§16 rate-limiter isolation: alice's `agent` burst never throttles bob's `agent`
(create_limiter is per-cell, C4); failed auths from a shared ingress don't 429
the fleet (the auth-failure limiter is keyed on trusted_client_id, C3, and must
never gate a request that SUCCESSFULLY authenticates)."""

import asyncio

from tests.isolation.conftest import bearer_hdr, mint_into_cell


def test_create_limiter_is_per_tenant(two_tenant):
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    # cap comes from the cfg fixture's rate_limit_per_minute (default 30) via
    # cell.create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)
    # burst alice's agent until it 429s
    saw_429 = False
    for i in range(40):
        r = tt.client.post("/v1/requests", headers=a.agent_hdr,
                           json={"title": f"a{i}", "idempotency_key": f"a{i}"})
        if r.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "alice never hit her own create limit"
    # bob's agent (same token NAME 'bob-agent' vs 'alice-agent', same bucket only if
    # keyed on bare name) must be completely unthrottled
    rb = tt.client.post("/v1/requests", headers=b.agent_hdr,
                       json={"title": "b0", "idempotency_key": "b0"})
    assert rb.status_code == 200, "bob throttled by alice's burst — shared bucket"

    # Directly prove per-CELL isolation (not just per-name): a regression that
    # makes create_limiter a process-global keyed on bare name would still pass
    # everything above, since alice's and bob's agents have different names.
    # Acquire both live cells through the registry and assert distinct limiter
    # objects — the only way this passes is if each cell owns its own limiter.
    async def _cells():
        async with tt.registry.hold(a.tenant_id, a.epoch) as alice_cell, \
                   tt.registry.hold(b.tenant_id, b.epoch) as bob_cell:
            return alice_cell, bob_cell
    alice_cell, bob_cell = asyncio.run(_cells())
    assert alice_cell.create_limiter is not bob_cell.create_limiter, \
        "alice and bob share one create_limiter object — not per-cell"


def test_create_limiter_survives_identically_named_agents_across_tenants(two_tenant):
    """The practically-meaningful proof: two tenants can independently name an
    agent the SAME string ("agent"). Under a limiter keyed on bare name (shared
    across cells), alice's burst on her "agent" would collide with bob's
    identically-named "agent" and throttle him too. Under per-cell limiters,
    the shared name is irrelevant — bob is untouched."""
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    alice_bearer = mint_into_cell(tt.control, tt.registry, "alice", a.epoch, "agent", "agent")
    bob_bearer = mint_into_cell(tt.control, tt.registry, "bob", b.epoch, "agent", "agent")
    alice_hdr, bob_hdr = bearer_hdr(alice_bearer), bearer_hdr(bob_bearer)

    saw_429 = False
    for i in range(40):
        r = tt.client.post("/v1/requests", headers=alice_hdr,
                           json={"title": f"a{i}", "idempotency_key": f"same-name-a{i}"})
        if r.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "alice never hit her own create limit"

    rb = tt.client.post("/v1/requests", headers=bob_hdr,
                       json={"title": "b0", "idempotency_key": "same-name-b0"})
    assert rb.status_code == 200, \
        "bob's identically-named 'agent' throttled by alice's burst — limiter keyed on name, not cell"


def test_bad_auth_from_shared_ingress_does_not_429_the_fleet(two_tenant):
    tt = two_tenant
    b = tt.tenants["bob"]
    # hammer invalid bearers from the (single, shared) TestClient source IP
    for _ in range(30):
        tt.client.post("/v1/requests",
                      headers={"Authorization": "Bearer hma_agent_" + "0" * 48},
                      json={"title": "x"})
    # bob's VALID traffic must still authenticate (auth limiter not keyed on bare IP)
    r = tt.client.post("/v1/requests", headers=b.agent_hdr,
                      json={"title": "still-ok", "idempotency_key": "k"})
    assert r.status_code in (200,), f"fleet-wide auth 429 leaked to bob: {r.status_code}"

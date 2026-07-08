"""§16 rate-limiter isolation: alice's `agent` burst never throttles bob's `agent`
(create_limiter is per-cell, C4); failed auths from a shared ingress don't 429
the fleet (the auth-failure limiter is keyed on trusted_client_id, C3, and must
never gate a request that SUCCESSFULLY authenticates)."""


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

import threading


def test_keys_never_returns_a_neighbors_jwks_under_eviction(two_tenant):
    """§16 gate: GET /v1/keys always serves the caller's OWN pinned tenant's
    JWKS, even while a churn thread is concurrently evicting idle cells
    (§15.4/§7: require_cell pins the resolved cell for the handler's whole
    lifetime; acquire() never hands back a cell mid-eviction/reopen).

    try_evict_idle() (I6) is async, so a plain thread cannot call it
    directly -- doing so would just build an unawaited coroutine and evict
    NOTHING, making the "race" vacuous. Instead the churn drives it on the
    app's own lifespan event loop via the app.state.evict_tick seam (added
    in app.py's lifespan, mirroring the existing scheduler_tick pattern),
    which hops onto that loop with asyncio.run_coroutine_threadsafe. Cells
    go idle (refcount 0) the instant each /v1/keys handler releases them, so
    genuine evictions are expected between requests -- verified below via an
    evictions-happened counter so the test cannot pass on a no-op churn.
    """
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    stop = threading.Event()
    evictions = 0
    churn_errors = []

    def churn():
        nonlocal evictions
        while not stop.is_set():
            try:
                n = tt.app.state.evict_tick(timeout=2.0)
                evictions += n
            except Exception as exc:  # pragma: no cover - diagnostic only
                churn_errors.append(exc)

    t = threading.Thread(target=churn, daemon=True)
    t.start()
    try:
        for _ in range(200):
            ka = tt.client.get("/v1/keys", headers=a.app_hdr).json()["keys"][0]["kid"]
            kb = tt.client.get("/v1/keys", headers=b.app_hdr).json()["keys"][0]["kid"]
            assert ka.startswith("alice:"), f"alice got {ka}"
            assert kb.startswith("bob:"), f"bob got {kb}"
            assert ka != kb
    finally:
        stop.set()
        t.join(timeout=5)

    assert not churn_errors, f"churn thread errored: {churn_errors}"
    # Non-vacuity: the churn must have genuinely evicted cells (real reopen
    # races forced), not spun on a no-op -- otherwise the race under test
    # never existed during this run.
    assert evictions > 0, "churn never evicted a cell; the race was never exercised"

import itertools

def test_request_detail_requires_token(client, agent_headers, app_headers):
    rid = client.post("/v1/requests", headers=agent_headers, json={"title": "x"}).json()["id"]
    assert client.get(f"/v1/requests/{rid}").status_code == 401
    assert client.get(f"/v1/requests/{rid}", headers=agent_headers).status_code == 200
    assert client.get(f"/v1/requests/{rid}", headers=app_headers).status_code == 200

def test_health_is_minimal(client):
    assert client.get("/health").json() == {"ok": True}

def test_devices_list_requires_app_token(client, app_headers):
    assert client.get("/v1/devices").status_code == 401
    assert client.get("/v1/devices", headers=app_headers).status_code == 200

def test_security_headers_on_html(client):
    r = client.get("/", follow_redirects=False)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"

def test_auth_failures_rate_limited(client):
    bad = {"Authorization": "Bearer wrong"}
    codes = [client.get("/v1/requests", headers=bad).status_code for _ in range(12)]
    assert codes[0] == 403 and 429 in codes

def test_limiter_unit_blocks_and_expires():
    from arbiter.auth import SlidingWindowLimiter
    t = itertools.count()
    lim = SlidingWindowLimiter(3, 60.0, clock=lambda: next(t))
    for _ in range(3):
        lim.record_failure("ip")
    assert lim.blocked("ip")
    lim2 = SlidingWindowLimiter(3, 2.0, clock=lambda: next(t))
    for _ in range(3):
        lim2.record_failure("ip")
    assert not lim2.blocked("ip")  # clock already advanced past the window

def test_limiter_blocked_does_not_create_entries():
    from arbiter.auth import SlidingWindowLimiter
    lim = SlidingWindowLimiter(3, 60.0)
    assert not lim.blocked("never-seen")
    assert "never-seen" not in lim._hits

def test_limiter_per_key_isolation():
    from arbiter.auth import SlidingWindowLimiter
    lim = SlidingWindowLimiter(2, 60.0)
    lim.record_failure("a")
    lim.record_failure("a")
    assert lim.blocked("a") and not lim.blocked("b")

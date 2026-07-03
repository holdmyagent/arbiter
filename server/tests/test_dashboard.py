def _login(client, password="test-admin"):
    r = client.post("/dashboard/login", data={"password": password}, follow_redirects=False)
    return r

def test_login_success_sets_cookie_and_redirects(client):
    r = _login(client)
    assert r.status_code == 303 and "hma_session" in r.cookies

def test_login_failure_no_cookie(client):
    r = _login(client, "wrong")
    assert r.status_code in (200, 401) and "hma_session" not in r.cookies

def test_login_rate_limited(client):
    for _ in range(6): _login(client, "wrong")
    assert _login(client, "wrong").status_code == 429

def test_pair_requires_session(client):
    r = client.get("/dashboard/pair", follow_redirects=False)
    assert r.status_code in (302, 303) and "/dashboard/login" in r.headers["location"]

def test_pair_shows_qr_when_logged_in(client):
    _login(client)
    r = client.get("/dashboard/pair")
    assert r.status_code == 200 and "<svg" in r.text and "hma pair" in r.text

def test_old_pair_redirects(client):
    r = client.get("/pair", follow_redirects=False)
    assert r.status_code in (302, 303, 307, 308) and "/dashboard/pair" in r.headers["location"]

def test_logout_requires_csrf(client):
    _login(client)
    assert client.post("/dashboard/logout", data={}).status_code == 403

def test_stream_accepts_session_cookie(client, agent_headers):
    _login(client)
    with client.websocket_connect("/v1/stream") as ws:   # cookie jar carries hma_session
        client.post("/v1/requests", headers=agent_headers, json={"title": "x"})
        assert ws.receive_json()["event"] == "request.created"

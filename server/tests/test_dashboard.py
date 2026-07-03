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
    for _ in range(6):
        _login(client, "wrong")
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
    assert r.status_code == 302 and "/dashboard/pair" in r.headers["location"]

def test_logout_requires_csrf(client):
    _login(client)
    assert client.post("/dashboard/logout", data={}).status_code == 403

def test_stream_accepts_session_cookie(client, agent_headers):
    _login(client)
    with client.websocket_connect("/v1/stream") as ws:   # cookie jar carries hma_session
        client.post("/v1/requests", headers=agent_headers, json={"title": "x"})
        assert ws.receive_json()["event"] == "request.created"

# Keep this test LAST in the file: it revokes a session value in arbiter.web's
# module-level _REVOKED set, and TimestampSigner's 1-second resolution over a
# constant payload means a later login in the same second would mint the same
# (already revoked) value.
def test_logout_invalidates_session_replay(client):
    _login(client)
    csrf = client.get("/dashboard/pair").text.split('name="csrf" value="')[1].split('"')[0]
    old_cookie = client.cookies.get("hma_session")
    client.post("/dashboard/logout", data={"csrf": csrf})
    client.cookies.set("hma_session", old_cookie)  # replay the pre-logout value
    r = client.get("/dashboard/pair", follow_redirects=False)
    assert r.status_code == 303 and "/dashboard/login" in r.headers["location"]

def test_requests_page_lists_and_fragment(client, agent_headers):
    _login(client)
    client.post("/v1/requests", headers=agent_headers, json={"title": "Deploy X", "severity": "critical"})
    page = client.get("/dashboard/requests")
    assert "Deploy X" in page.text and "critical" in page.text
    frag = client.get("/dashboard/requests?fragment=1")
    assert "Deploy X" in frag.text and "<html" not in frag.text

def test_request_detail_slip(client, agent_headers):
    _login(client)
    rid = client.post("/v1/requests", headers=agent_headers,
                      json={"title": "Deploy", "target": "prod-cluster"}).json()["id"]
    page = client.get(f"/dashboard/requests/{rid}")
    assert "prod-cluster" in page.text and "created" in page.text  # audit inline
    assert "Approve" not in page.text and "Deny" not in page.text  # view-only

def test_devices_rename_and_delete(client, app_headers):
    _login(client)
    client.post("/v1/devices", headers=app_headers, json={"apns_token": "tok1", "name": "iPhone"})
    did = client.get("/v1/devices", headers=app_headers).json()[0]["id"]
    csrf = client.get("/dashboard/devices").text.split('name="csrf" value="')[1].split('"')[0]
    client.post(f"/dashboard/devices/{did}/rename", data={"name": "Kevin's iPhone", "csrf": csrf})
    assert "Kevin" in client.get("/dashboard/devices").text
    client.post(f"/dashboard/devices/{did}/delete", data={"csrf": csrf})
    assert client.get("/v1/devices", headers=app_headers).json() == []

def test_audit_page_filters(client, agent_headers):
    _login(client)
    rid = client.post("/v1/requests", headers=agent_headers, json={"title": "A"}).json()["id"]
    page = client.get(f"/dashboard/audit?request_id={rid}")
    assert "created" in page.text

def test_rotate_app_token_persists_and_audits(client, tmp_path, cfg, monkeypatch):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[auth]\nagent_token = "test-agent"\napp_token = "test-app"\n'
                        'admin_password = "test-admin"\nsession_secret = "test-secret"\n')
    monkeypatch.setenv("HMA_CONFIG", str(cfg_file))
    _login(client)
    csrf = client.get("/dashboard/settings").text.split('name="csrf" value="')[1].split('"')[0]
    r = client.post("/dashboard/settings/rotate", data={"which": "app", "csrf": csrf})
    assert r.status_code in (200, 303)
    assert 'app_token = "test-app"' not in cfg_file.read_text()
    assert cfg.auth.app_token != "test-app"

def _all_paths(router):
    # Schema-independent route enumeration: walks nested routers (FastAPI's
    # _IncludedRouter exposes original_router), so include_in_schema=False
    # routes are still seen — unlike openapi()["paths"].
    paths = []
    for r in getattr(router, "routes", []):
        p = getattr(r, "path", None)
        if p is not None:
            paths.append(p)
        inner = getattr(r, "original_router", None) or (r if hasattr(r, "routes") and p is None else None)
        if inner is not None and inner is not router:
            paths.extend(_all_paths(inner))
    return paths

def test_no_decision_routes_under_dashboard(client):
    paths = _all_paths(client.app.router)
    dash = [p for p in paths if p.startswith("/dashboard")]
    assert len(dash) >= 11          # guards against a silently-empty walk
    assert not any("decision" in p for p in dash)

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
                      json={"title": "Deploy", "target": "prod-cluster",
                            "description": "DROP TABLE events;"}).json()["id"]
    page = client.get(f"/dashboard/requests/{rid}")
    assert "prod-cluster" in page.text and "created" in page.text  # audit inline
    assert "DROP TABLE events;" in page.text  # description = the gated command, on the slip
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

def _client_for(cfg):
    from arbiter.apns import APNsSender
    from arbiter.app import create_app
    from arbiter.db import Database
    from fastapi.testclient import TestClient
    app = create_app(cfg, Database(":memory:"), APNsSender(cfg))
    return TestClient(app)

def test_rotate_writes_loaded_config_path_not_default(tmp_path, monkeypatch):
    # A `--config /custom/path` deployment: the cfg's loaded_path is the
    # custom file, which already exists with known tokens. Rotation must
    # write back there — not to $HMA_CONFIG or the ~/.config default, which
    # this test points somewhere else entirely to prove they're untouched.
    from arbiter.config import Config
    custom = tmp_path / "custom" / "config.toml"
    custom.parent.mkdir(parents=True)
    custom.write_text('[auth]\nagent_token = "test-agent"\napp_token = "test-app"\n'
                      'admin_password = "test-admin"\nsession_secret = "test-secret"\n')
    default_cfg = tmp_path / "unrelated-default-config.toml"
    monkeypatch.setenv("HMA_CONFIG", str(default_cfg))

    cfg = Config.load(str(custom))
    cfg.server.db_path = str(tmp_path / "t.sqlite3")
    assert cfg.loaded_path == str(custom)

    with _client_for(cfg) as client:
        _login(client)
        csrf = client.get("/dashboard/settings").text.split('name="csrf" value="')[1].split('"')[0]
        r = client.post("/dashboard/settings/rotate", data={"which": "app", "csrf": csrf})
        assert r.status_code in (200, 303)

    assert 'app_token = "test-app"' not in custom.read_text()
    assert cfg.auth.app_token != "test-app"
    assert oct(custom.stat().st_mode & 0o777) == "0o600"
    assert not default_cfg.exists()

def test_rotate_creates_missing_parent_dir(tmp_path):
    # loaded_path can point at a not-yet-existing directory (e.g. a fresh
    # --config path nobody has `hma init`-ed yet) — rotate must mkdir it
    # rather than crash on the write.
    from arbiter.config import Config
    custom = tmp_path / "new" / "nested" / "config.toml"
    cfg = Config.load(str(custom))
    cfg.auth.agent_token = "test-agent"
    cfg.auth.app_token = "test-app"
    cfg.auth.admin_password = "test-admin"
    cfg.auth.session_secret = "test-secret"
    cfg.server.db_path = str(tmp_path / "t.sqlite3")

    with _client_for(cfg) as client:
        _login(client)
        csrf = client.get("/dashboard/settings").text.split('name="csrf" value="')[1].split('"')[0]
        r = client.post("/dashboard/settings/rotate", data={"which": "agent", "csrf": csrf})
        assert r.status_code in (200, 303)

    assert custom.exists()
    assert oct(custom.stat().st_mode & 0o777) == "0o600"
    assert cfg.auth.agent_token != "test-agent"

def test_notify_policy_toggle_persists_and_applies(tmp_path, monkeypatch):
    from arbiter.config import Config
    p = tmp_path / "config.toml"
    p.write_text('[auth]\nagent_token = "test-agent"\napp_token = "test-app"\n'
                 'admin_password = "test-admin"\nsession_secret = "test-secret"\n')
    cfg = Config.load(str(p))
    cfg.server.db_path = str(tmp_path / "t.sqlite3")
    with _client_for(cfg) as client:
        _login(client)
        csrf = client.get("/dashboard/settings").text.split('name="csrf" value="')[1].split('"')[0]
        r = client.post("/dashboard/settings/notify-policy",
                        data={"severity": "low", "csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
        assert cfg.notify_severities["low"] is False          # in-memory flip
        assert Config.load(str(p)).notify_severities["low"] is False  # persisted
        # toggling again re-enables
        client.post("/dashboard/settings/notify-policy", data={"severity": "low", "csrf": csrf})
        assert cfg.notify_severities["low"] is True
        assert oct(p.stat().st_mode & 0o777) == "0o600"


def test_notify_policy_requires_csrf_and_valid_severity(client):
    _login(client)
    assert client.post("/dashboard/settings/notify-policy",
                       data={"severity": "low"}).status_code == 403
    csrf = client.get("/dashboard/settings").text.split('name="csrf" value="')[1].split('"')[0]
    assert client.post("/dashboard/settings/notify-policy",
                       data={"severity": "bogus", "csrf": csrf}).status_code == 400

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

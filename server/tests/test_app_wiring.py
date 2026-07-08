

def test_no_tenant_scoped_object_on_app_state(client):
    st = client.app_ref.state
    # §15.1 — nothing per-tenant lives on app.state
    for banned in ("db", "hub", "create_limiter", "login_limiter", "verdict_kid", "expire_pass"):
        assert not hasattr(st, banned), f"app.state.{banned} must not exist"
    for required in ("registry", "control", "cfg", "auth_limiter", "notify_tasks", "session_check"):
        assert hasattr(st, required), f"app.state.{required} missing"


def test_health_ok_on_default_cell(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True, "db": True}


def test_legacy_app_token_resolves_default(client, app_headers):
    # legacy cfg.auth.app_token → default cell; a protected route no longer 500s
    r = client.get("/v1/requests", headers=app_headers)
    assert r.status_code == 200

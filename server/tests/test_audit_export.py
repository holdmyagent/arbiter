from arbiter.web import make_session


def _seed(client, tenant):
    env = client.env
    env.provision(tenant)
    atok = env.mint(tenant, "agent", "agent")
    app_ = env.mint(tenant, "app", "app")
    wtok = env.mint(tenant, "warden", "warden")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": f"t-{tenant}"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {app_}"},
                json={"decision": "approve"})
    client.post(f"/v1/requests/{rid}/consume", headers={"Authorization": f"Bearer {wtok}"})
    return app_, rid


def test_export_streams_only_callers_cell(client):
    aapp, rid_a = _seed(client, "a")
    bapp, rid_b = _seed(client, "b")
    la = client.get("/v1/audit/export", headers={"Authorization": f"Bearer {aapp}"})
    lb = client.get("/v1/audit/export", headers={"Authorization": f"Bearer {bapp}"})
    atext, btext = la.text, lb.text
    # cell.db.iter_audit() rows carry request_id/event/detail, not the request
    # title (audit's "created" detail is only {"severity": ...} -- no JOIN to
    # requests.title), so isolation is asserted on request_id, the field that
    # is actually in the exported rows and unique per seeded request.
    assert rid_a in atext
    assert rid_b not in atext          # A's export never carries B's rows
    assert rid_a not in btext
    assert rid_b in btext


def test_export_requires_app_role_or_admin_session(client):
    assert client.get("/v1/audit/export").status_code == 403
    assert client.get("/v1/audit/export",
                      headers={"Authorization": "Bearer test-agent"}).status_code == 403
    # NOTE: the brief drives this via POST /dashboard/login, but that route
    # currently 500s (it reads app.state.login_limiter, which §15.1/
    # test_app_wiring.py explicitly bans from app.state -- it's pending the
    # dashboard group's own per-cell port, same blocker test_dashboard.py and
    # test_security.py already xfail). Sign a session cookie directly with the
    # same signer the (broken) route would use, so this test exercises
    # audit_export's session_check branch -- this task's actual surface --
    # without depending on the unrelated, not-yet-ported login endpoint.
    client.cookies.set("hma_session", make_session(client.app_ref.state.cfg))
    assert client.get("/v1/audit/export").status_code == 200   # admin session -> default cell


def test_export_unknown_format_422(client, app_headers):
    assert client.get("/v1/audit/export", params={"format": "csv"},
                      headers=app_headers).status_code == 422


def test_export_auth_failures_rate_limited(client):
    bad = {"Authorization": "Bearer wrong"}
    codes = [client.get("/v1/audit/export", headers=bad).status_code for _ in range(12)]
    assert codes[0] == 403 and 429 in codes

import json

from fastapi.testclient import TestClient

from arbiter.app import create_app
from arbiter.web import make_session

from tests.conftest import build_registry_env


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


def test_export_disabled_default_blocks_session(client):
    # A valid admin session must NOT reach a disabled default tenant: the
    # session path re-reads control.is_disabled on every resolution, same as
    # resolve_identity does for bearers, and denies with the same generic 403.
    client.env.control.disable_tenant("default")
    client.cookies.set("hma_session", make_session(client.app_ref.state.cfg))
    assert client.get("/v1/audit/export").status_code == 403


def test_policy_denied_and_rate_limited_events(cfg, tmp_path):
    # Restored from the pre-C7 test_audit_export.py (it passed at base and was
    # dropped by the C7 full-file replacement): policy_denied and rate_limited
    # must land in the audit log with their detail payloads, not just surface
    # as HTTP statuses (test_policy.py covers only the status codes). Adapted
    # per-cell: the legacy agent token resolves to the default cell, whose db
    # is env.default_db. Builds its own app (not the `client` fixture) because
    # rate_limit_per_minute is baked into the cell's create_limiter at cell
    # open, so cfg must be mutated before the first request opens the cell.
    cfg.policy.deny_action_types = ["db.drop"]
    cfg.policy.rate_limit_per_minute = 2   # the denied create now counts (rate-limit-first)
    env = build_registry_env(cfg, tmp_path)
    client = TestClient(create_app(cfg, env.registry, env.control))
    agent = {"Authorization": "Bearer test-agent"}
    assert client.post("/v1/requests", headers=agent,
                       json={"title": "t", "action_type": "db.drop"}).status_code == 403
    assert client.post("/v1/requests", headers=agent,
                       json={"title": "t"}).status_code == 200
    assert client.post("/v1/requests", headers=agent,
                       json={"title": "t2"}).status_code == 429
    rows = {a["event"]: a for a in env.default_db.list_audit(limit=500)}
    assert "policy_denied" in rows and "rate_limited" in rows
    denied = json.loads(rows["policy_denied"]["detail"])
    assert denied["action_type"] == "db.drop" and denied["identity"] == "agent"
    limited = json.loads(rows["rate_limited"]["detail"])
    assert limited["identity"] == "agent"


def test_export_unknown_format_422(client, app_headers):
    assert client.get("/v1/audit/export", params={"format": "csv"},
                      headers=app_headers).status_code == 422


def test_export_auth_failures_rate_limited(client):
    bad = {"Authorization": "Bearer wrong"}
    codes = [client.get("/v1/audit/export", headers=bad).status_code for _ in range(12)]
    assert codes[0] == 403 and 429 in codes

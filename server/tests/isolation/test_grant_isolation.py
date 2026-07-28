"""§16 gate: a grant is cell-scoped. Tenant alice's grant must never answer
for tenant bob -- grants live in the per-tenant cell DB, and this proves the
auto-approval lookup inherits that isolation rather than reaching across.

The `two_tenant` fixture comes from tests/isolation/conftest.py: two provisioned
tenants (alice, bob) behind ONE live app, each with its own app/agent bearer.
"""
PAYLOAD = {"agent": "hermes", "tool": "skill_manage"}


def _create(tt, tenant, payload=PAYLOAD):
    h = tt.tenants[tenant].agent_hdr
    r = tt.client.post("/v1/requests", headers=h,
                       json={"title": "t", "severity": "high", "payload": dict(payload)})
    assert r.status_code == 200
    return r.json()


def _grant_into(tt, tenant):
    from arbiter.db import Database
    db = Database(str(tt.tenants[tenant].dir / "arbiter.sqlite3"))
    g = db.create_grant(agent="hermes", tool="skill_manage", granted_by="alice-phone",
                        granted_via="app-token", request_id=None, ttl_seconds=900)
    db.conn.close()
    return g


def test_a_grant_in_one_tenant_never_auto_approves_in_another(two_tenant):
    _grant_into(two_tenant, "alice")
    assert _create(two_tenant, "alice")["status"] == "approved"
    assert _create(two_tenant, "bob")["status"] == "pending"


def test_a_tenants_grant_list_shows_only_its_own(two_tenant):
    g = _grant_into(two_tenant, "alice")
    a = two_tenant.client.get("/v1/grants", headers=two_tenant.tenants["alice"].app_hdr)
    b = two_tenant.client.get("/v1/grants", headers=two_tenant.tenants["bob"].app_hdr)
    assert [x["id"] for x in a.json()["grants"]] == [g["id"]]
    assert b.json()["grants"] == []

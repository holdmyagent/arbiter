def test_app_bearer_cannot_read_foreign_request_or_audit(two_tenant):
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    # bob creates a request in bob's cell
    bob_rid = tt.client.post("/v1/requests", headers=b.agent_hdr,
                             json={"title": "bob-private"}).json()["id"]
    # BASELINE: bob's own app bearer can read it
    assert tt.client.get(f"/v1/requests/{bob_rid}", headers=b.app_hdr).status_code == 200
    # ISOLATION: alice's app bearer 404s on bob's rid (generic, no existence oracle)
    r = tt.client.get(f"/v1/requests/{bob_rid}", headers=a.app_hdr)
    assert r.status_code == 404
    # alice's audit export must not mention bob's rid
    export = tt.client.get("/v1/audit/export", headers=a.app_hdr).text
    assert bob_rid not in export
    assert "bob-private" not in export
    # bob's own export DOES contain it (non-vacuous)
    assert bob_rid in tt.client.get("/v1/audit/export", headers=b.app_hdr).text


def test_legacy_app_token_resolves_strictly_to_default(cfg, tmp_path):
    from tests.isolation.conftest import (ControlPlane, TenantRegistry, create_app,
                                          mint_into_cell)
    from fastapi.testclient import TestClient
    root = tmp_path / "fleet"
    root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)
    d_def = root / "default"
    d_def.mkdir(parents=True)
    control.create_tenant("default", d_def)
    d_other = root / "alice"
    d_other.mkdir(parents=True)
    ep2 = control.create_tenant("alice", d_other)
    alice_agent = mint_into_cell(control, registry, "alice", ep2, "alice-agent", "agent")
    app = create_app(cfg, registry, control, sender=None)
    with TestClient(app) as c:
        # legacy cfg.auth.app_token (set in the cfg fixture) → 'default' cell:
        # it can decide in default, but a request created in ALICE is invisible to it.
        rid = c.post("/v1/requests", headers={"Authorization": f"Bearer {alice_agent}"},
                     json={"title": "in-alice"}).json()["id"]
        r = c.get(f"/v1/requests/{rid}",
                  headers={"Authorization": f"Bearer {cfg.auth.app_token}"})
        assert r.status_code == 404  # legacy app_token is default-only, cannot see alice

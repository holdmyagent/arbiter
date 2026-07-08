import hashlib


def test_route_without_a_cell_token_is_a_hard_403(two_tenant):
    tt = two_tenant
    a = tt.tenants["alice"]
    # forge a bearer routed to alice in the ROUTER, but never minted into the cell
    forged = "hma_agent_" + "f" * 48
    th = hashlib.sha256(forged.encode()).hexdigest()
    tt.control.add_route(th, "alice")   # router says alice…
    # …but alice's cell has no such token row → resolve_identity must reject
    r = tt.client.post("/v1/requests",
                       headers={"Authorization": f"Bearer {forged}"},
                       json={"title": "x"})
    assert r.status_code == 403
    # generic body — no "unknown tenant"/"no cell row" oracle
    assert r.json()["detail"] in ("invalid token", "forbidden")
    # BASELINE: a genuinely-minted alice bearer still works
    assert tt.client.post("/v1/requests", headers=a.agent_hdr,
                          json={"title": "ok"}).status_code == 200

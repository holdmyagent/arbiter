def test_event_on_cell_a_never_reaches_cell_b(two_tenant):
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws_a, \
         tt.client.websocket_connect("/v1/stream", headers=b.app_hdr) as ws_b:
        rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                             json={"title": "alice-secret"}).json()["id"]
        # BASELINE (non-vacuous): alice's own socket sees it
        evt = ws_a.receive_json()
        assert evt["event"] == "request.created"
        assert evt["request"]["id"] == rid
        assert evt["request"]["title"] == "alice-secret"
        # FENCE: publish an event on BOB's cell; the FIRST thing bob's socket
        # sees must be bob's own event, proving alice's earlier event never
        # queued on B (a global hub would have delivered alice's event first).
        rid_b = tt.client.post("/v1/requests", headers=b.agent_hdr,
                               json={"title": "bob-only"}).json()["id"]
        first_b = ws_b.receive_json()
        assert first_b["request"]["id"] == rid_b and first_b["request"]["title"] == "bob-only", \
            f"cell B socket saw a foreign event first: {first_b}"

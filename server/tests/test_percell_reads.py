def test_cross_tenant_get_is_404(client):
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agentA", "agent")
    bapp = env.mint("b", "appB", "app")
    aapp = env.mint("a", "appA", "app")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": "secret-A"}).json()["id"]
    # B (even app-role, unrestricted within its own cell) cannot see A's rid
    assert client.get(f"/v1/requests/{rid}",
                      headers={"Authorization": f"Bearer {bapp}"}).status_code == 404
    # A's app can
    assert client.get(f"/v1/requests/{rid}",
                      headers={"Authorization": f"Bearer {aapp}"}).status_code == 200


def test_cross_tenant_verdict_is_404(client):
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agentA", "agent")
    bapp = env.mint("b", "appB", "app")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": "t"}).json()["id"]
    assert client.get(f"/v1/requests/{rid}/verdict",
                      headers={"Authorization": f"Bearer {bapp}"}).status_code == 404

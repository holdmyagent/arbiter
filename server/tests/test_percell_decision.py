import jwt

def test_decision_signs_with_cell_signer_and_tenant_binds(client):
    env = client.env
    env.provision("a")
    atok = env.mint("a", "agentA", "agent")
    aapp = env.mint("a", "appA", "app")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": "t"}).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {aapp}"},
                    json={"decision": "approve"})
    assert d.status_code == 200
    v = client.get(f"/v1/requests/{rid}/verdict",
                   headers={"Authorization": f"Bearer {aapp}"}).json()
    hdr = jwt.get_unverified_header(v["verdict"])
    body = jwt.decode(v["verdict"], options={"verify_signature": False})
    assert hdr["kid"].startswith("a:")                     # kid = f"{tenant_id}:{hash8}"
    assert body["aud"] == "hma-verdict:a"                  # audience tenant-bound
    assert body["hma"]["tenant_id"] == "a"

def test_cross_tenant_decision_is_404(client):
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agentA", "agent")
    bapp = env.mint("b", "appB", "app")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": "t"}).json()["id"]
    assert client.post(f"/v1/requests/{rid}/decision",
                       headers={"Authorization": f"Bearer {bapp}"},
                       json={"decision": "approve"}).status_code == 404

def test_consume_scoped_to_cell(client):
    env = client.env
    env.provision("a")
    atok = env.mint("a", "agentA", "agent")
    aapp = env.mint("a", "appA", "app")
    awarden = env.mint("a", "wardenA", "warden")
    rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                      json={"title": "t"}).json()["id"]
    client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {aapp}"},
                json={"decision": "approve"})
    c = client.post(f"/v1/requests/{rid}/consume", headers={"Authorization": f"Bearer {awarden}"})
    assert c.status_code == 200 and "consumed_at" in c.json()

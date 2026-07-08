def test_create_and_list_scoped_to_caller_cell(client):
    env = client.env
    env.provision("b"); env.provision("a")
    atok = env.mint("a", "agentA", "agent")
    btok = env.mint("b", "agentB", "agent")
    aapp = env.mint("a", "appA", "app")
    bapp = env.mint("b", "appB", "app")
    ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                     json={"title": "for-A"})
    rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                     json={"title": "for-B"})
    assert ra.status_code == 200 and rb.status_code == 200
    # A's app sees ONLY A's request; B's app sees ONLY B's
    la = client.get("/v1/requests", headers={"Authorization": f"Bearer {aapp}"}).json()
    lb = client.get("/v1/requests", headers={"Authorization": f"Bearer {bapp}"}).json()
    assert [r["title"] for r in la] == ["for-A"]
    assert [r["title"] for r in lb] == ["for-B"]


def test_create_rate_limit_is_per_cell(client, cfg):
    # B's agent burst must NEVER throttle A's agent (§13 — separate buckets)
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agent", "agent")     # SAME name in both cells
    btok = env.mint("b", "agent", "agent")
    # drive B's 'agent' bucket to the limit
    for _ in range(cfg.policy.rate_limit_per_minute + 2):
        client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                    json={"title": "x", "idempotency_key": None})
    rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"}, json={"title": "y"})
    ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"}, json={"title": "z"})
    assert rb.status_code == 429
    assert ra.status_code == 200            # A untouched

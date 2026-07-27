"""FIX3 Finding 1: the agent credential is the one this whole system exists
to distrust — the arbiter exists so an agent must get human approval before
acting. Handing that same credential the *output* of an approved command
(exec_ran/exec_output) inverts the trust model. These tests prove the
redaction lands on every route that can hand an agent-role caller a request
row carrying execution data, while app/warden keep the full row and the
agent's own read access is not narrowed (no new 403/404).
"""

AGENT = {"Authorization": "Bearer test-agent"}
APP = {"Authorization": "Bearer test-app"}


def _warden_headers(client, name="warden1"):
    tok = client.env.mint("default", name, "warden")
    return {"Authorization": f"Bearer {tok}"}


def _request_with_exec_result(client, *, creator=AGENT, ran="cat /etc/shadow",
                              output="root:$6$...", exit_code=0, kind="command",
                              idempotency_key=None):
    """Build a fully-executed row: `creator` opens it, app approves, a warden
    consumes and reports the execution result — the exact shape the reviewer
    proved an agent-role bearer could read back in full."""
    body = {"title": "t"}
    if idempotency_key is not None:
        body["idempotency_key"] = idempotency_key
    rid = client.post("/v1/requests", headers=creator, json=body).json()["id"]
    d = client.post(f"/v1/requests/{rid}/decision", headers=APP, json={"decision": "approve"})
    assert d.status_code == 200
    # distinct name from any warden the caller minted as `creator`: mint_cell_token
    # enforces UNIQUE(name), and consume() has no ownership check, so any warden
    # can consume — this one need not be (and must not collide with) the creator.
    warden = _warden_headers(client, name="warden-consumer")
    assert client.post(f"/v1/requests/{rid}/consume", headers=warden).status_code == 200
    r = client.post(f"/v1/requests/{rid}/consume", headers=warden,
                    json={"mode": "exec_result", "exit_code": exit_code, "ran": ran,
                          "output": output, "kind": kind})
    assert r.status_code == 200
    return rid


def test_agent_cannot_read_exec_ran_or_output(client):
    rid = _request_with_exec_result(client)
    r = client.get(f"/v1/requests/{rid}", headers=AGENT)
    assert r.status_code == 200            # no new 403/404 — agent still reads its own row
    body = r.json()
    assert body["exec_ran"] is None
    assert body["exec_output"] is None
    # exec_kind/exec_exit_code stay: an agent may learn whether its action
    # succeeded, and neither field can carry command text or output.
    assert body["exec_kind"] == "command"
    assert body["exec_exit_code"] == 0
    # status/decision fields are untouched — this is redaction, not restriction
    assert body["status"] == "approved"
    assert body["id"] == rid


def test_app_sees_full_exec_payload(client):
    rid = _request_with_exec_result(client)
    body = client.get(f"/v1/requests/{rid}", headers=APP).json()
    assert body["exec_ran"] == "cat /etc/shadow"
    assert body["exec_output"] == "root:$6$..."
    assert body["exec_kind"] == "command"
    assert body["exec_exit_code"] == 0


def test_warden_sees_full_exec_payload(client):
    """A warden reading back its OWN created-and-consumed row (the only shape
    get_()'s ownership check lets a warden GET at all) keeps the full
    payload — the warden wrote the data."""
    warden = _warden_headers(client, name="warden-creator")
    rid = _request_with_exec_result(client, creator=warden, ran="systemctl status x",
                                    output="inactive\n", exit_code=1)
    body = client.get(f"/v1/requests/{rid}", headers=warden).json()
    assert body["exec_ran"] == "systemctl status x"
    assert body["exec_output"] == "inactive\n"
    assert body["exec_kind"] == "command"
    assert body["exec_exit_code"] == 1


def test_agent_idempotent_replay_of_executed_request_is_also_redacted(client):
    """POST /v1/requests's idempotency-replay path (db.get_request_by_idem)
    can hand back an already-decided-and-executed row to the SAME agent
    identity that originally created it — a second route (distinct from GET
    /v1/requests/{rid}) capable of leaking exec_ran/exec_output to an
    agent-role caller. 'Do not assume there is only one.'"""
    rid = _request_with_exec_result(client, idempotency_key="k1")
    replay = client.post("/v1/requests", headers=AGENT,
                         json={"title": "t", "idempotency_key": "k1"})
    assert replay.status_code == 200
    body = replay.json()
    assert body["id"] == rid
    assert body["exec_ran"] is None
    assert body["exec_output"] is None
    assert body["exec_kind"] == "command"
    assert body["exec_exit_code"] == 0

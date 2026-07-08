import asyncio

import httpx

class Recorder:
    """Records webhook POSTs via an httpx MockTransport — WebhookNotifier passes
    `transport` straight to httpx.AsyncClient(transport=...), so a MockTransport
    is the correct hook (NOT a plain callable)."""
    def __init__(self):
        self.calls = []
    def _handler(self, request):
        self.calls.append((str(request.url), request.content))
        return httpx.Response(200)
    def transport(self):
        return httpx.MockTransport(self._handler)

def test_b_body_egresses_only_to_b_sink(client, tmp_path):
    """§16 webhook egress isolation — B's request body must reach B's sink only.
    Proven at the Dispatcher layer with per-cell CellDelivery: A and B get
    different webhook URLs; a delivery for B's request carries B's title to B's
    URL and never to A's."""
    from arbiter.notify import CellDelivery, build_cell_dispatcher
    from arbiter.config import WebhookCfg
    from arbiter.db import Database

    a_rec, b_rec = Recorder(), Recorder()
    a_del = CellDelivery(webhook=WebhookCfg(url="https://a.example/hook"))
    b_del = CellDelivery(webhook=WebhookCfg(url="https://b.example/hook"))
    a_disp = build_cell_dispatcher(a_del, Database(":memory:"), sender=None,
                                   transport=a_rec.transport())
    b_disp = build_cell_dispatcher(b_del, Database(":memory:"), sender=None,
                                   transport=b_rec.transport())
    req_b = {"id": "r-b", "title": "B-SECRET", "severity": "high", "status": "approved",
             "expires_at": "2999-01-01T00:00:00+00:00", "callback_url": None}
    asyncio.run(b_disp.request_decided(req_b))
    assert any("b.example" in url for url, _ in b_rec.calls)
    assert a_rec.calls == []                              # A's sink saw nothing of B's
    assert any(b"B-SECRET" in body for _, body in b_rec.calls)

def test_cross_tenant_list_is_empty(client):
    env = client.env
    env.provision("a"); env.provision("b")
    atok = env.mint("a", "agentA", "agent")
    bapp = env.mint("b", "appB", "app")
    client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"}, json={"title": "A"})
    assert client.get("/v1/requests", headers={"Authorization": f"Bearer {bapp}"}).json() == []

def test_keys_returns_callers_cell_jwks(client):
    env = client.env
    env.provision("a"); env.provision("b")
    aapp = env.mint("a", "appA", "app")
    bapp = env.mint("b", "appB", "app")
    ka = client.get("/v1/keys", headers={"Authorization": f"Bearer {aapp}"}).json()
    kb = client.get("/v1/keys", headers={"Authorization": f"Bearer {bapp}"}).json()
    akid = ka["keys"][0]["kid"]; bkid = kb["keys"][0]["kid"]
    assert akid.startswith("a:") and bkid.startswith("b:") and akid != bkid

def test_devices_scoped_to_cell(client):
    env = client.env
    env.provision("a"); env.provision("b")
    aapp = env.mint("a", "appA", "app")
    bapp = env.mint("b", "appB", "app")
    client.post("/v1/devices", headers={"Authorization": f"Bearer {aapp}"},
                json={"apns_token": "tok-a", "name": "phoneA"})
    assert client.get("/v1/devices", headers={"Authorization": f"Bearer {bapp}"}).json() == []

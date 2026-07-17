"""Registry-acquire escapes (review #3): EpochChanged must map to the same
generic 403 as every resolution failure; CapacityExceeded to 503. Before the
fix both escaped as unhandled exceptions (500 / crashed WS)."""
import hashlib

from arbiter.registry import CapacityExceeded, EpochChanged


def _boom(exc):
    async def raiser(tenant_id, epoch):
        raise exc(tenant_id)
    return raiser


def test_epoch_changed_is_generic_403_on_bearer_path(client, app_headers, monkeypatch):
    monkeypatch.setattr(client.env.registry, "acquire", _boom(EpochChanged))
    r = client.get("/v1/requests", headers=app_headers)
    assert r.status_code == 403
    assert r.json() == {"detail": "forbidden"}     # constant body, no oracle (§11)


def test_capacity_exceeded_is_503_on_bearer_path(client, app_headers, monkeypatch):
    monkeypatch.setattr(client.env.registry, "acquire", _boom(CapacityExceeded))
    assert client.get("/v1/requests", headers=app_headers).status_code == 503


def test_dashboard_session_path_maps_escapes(client, monkeypatch):
    r = client.post("/dashboard/login", data={"password": "test-admin"},
                    follow_redirects=False)
    assert r.status_code == 303                    # session first, then break acquire
    monkeypatch.setattr(client.env.registry, "acquire", _boom(EpochChanged))
    assert client.get("/dashboard/requests").status_code == 403
    monkeypatch.setattr(client.env.registry, "acquire", _boom(CapacityExceeded))
    assert client.get("/dashboard/requests").status_code == 503


def test_enroll_pairing_path_maps_escapes(client, monkeypatch):
    # enroll.py resolves via registry.hold -> self.acquire, so the same
    # handlers cover the phone-facing pairing path too.
    code = "hma_pair_escape_test"
    ch = hashlib.sha256(code.encode()).hexdigest()
    client.env.default_db.mint_pairing(ch, "2099-01-01T00:00:00+00:00")
    client.env.control.add_route(ch, "default")
    monkeypatch.setattr(client.env.registry, "acquire", _boom(CapacityExceeded))
    r = client.post("/v1/devices/enroll", headers={"Authorization": f"Bearer {code}"},
                    json={"apns_token": "t-escape", "name": "phone"})
    assert r.status_code == 503

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from arbiter.auth import trusted_client_id
from arbiter.app import require_cell


def _req(peer, xff=None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return SimpleNamespace(client=SimpleNamespace(host=peer),
                           headers={k.lower(): v for k, v in headers.items()})


def _cfg(trusted):
    return SimpleNamespace(server=SimpleNamespace(trusted_proxies=trusted))


def test_no_trusted_proxy_uses_direct_peer():
    assert trusted_client_id(_req("1.2.3.4"), _cfg([])) == "1.2.3.4"


def test_untrusted_peer_ignores_xff():
    # peer is NOT a trusted proxy: XFF is attacker-controlled, must be ignored
    assert trusted_client_id(_req("9.9.9.9", xff="7.7.7.7"), _cfg(["10.0.0.0/8"])) == "9.9.9.9"


def test_trusted_proxy_uses_real_client_from_xff():
    # peer IS the ingress proxy: the rightmost non-proxy XFF hop is the client
    got = trusted_client_id(_req("10.0.0.5", xff="7.7.7.7, 10.0.0.9"), _cfg(["10.0.0.0/8"]))
    assert got == "7.7.7.7"


@pytest.mark.xfail(strict=False, reason="/v1/requests app-role listing ported in C4")
def test_require_cell_releases_on_success_and_failure(client, app_headers):
    reg = client.env.registry
    released = []
    orig = reg.release
    reg.release = lambda cell: (released.append(cell), orig(cell))[1]
    # a ported route (app-role) succeeds and releases exactly once
    assert client.get("/v1/requests", headers=app_headers).status_code == 200
    assert len(released) == 1
    released.clear()
    # wrong role → 403 but still releases the pin acquired by resolve_identity
    assert client.get("/v1/requests", headers={"Authorization": "Bearer test-agent"}).status_code == 403
    assert len(released) == 1


@pytest.mark.xfail(strict=False, reason="/v1/requests app-role listing ported in C4")
def test_bad_token_trips_fleet_limiter(client):
    bad = {"Authorization": "Bearer nope"}
    codes = [client.get("/v1/requests", headers=bad).status_code for _ in range(12)]
    assert codes[0] == 403 and 429 in codes

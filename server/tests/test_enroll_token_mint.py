"""iOS 0.6 A1 — per-device token minted at enrolment. Unit half: sanitise + mint."""
import re

from arbiter.cli import _mint_pair_code
from arbiter.enroll import _sanitise_token_name

TOKEN_RE = re.compile(r"hma_app_[0-9a-f]{48}")


def test_sanitise_basic():
    assert _sanitise_token_name("Kevin's iPhone 17") == "kevin-s-iphone-17"

def test_sanitise_collapses_runs_and_trims():
    assert _sanitise_token_name("  --Wild  ***  Name--  ") == "wild-name"

def test_sanitise_caps_at_64():
    assert len(_sanitise_token_name("x" * 200)) <= 64

def test_sanitise_empty_falls_back():
    assert _sanitise_token_name("!!!") == "device"


# ── end-to-end half: real /v1/devices/enroll route, real registry/control ──

def _mint_code(client, minutes=15):
    """Mint a single-use pairing code against the 'default' tenant the shared
    `client` fixture provisions (conftest.py's `registry_env`)."""
    code, _ = _mint_pair_code(client.env.control, "default", minutes)
    return code


def _create_pending(client):
    """Create a pending approval request as the agent (conftest.py's
    `agent_headers` shape), returning its id."""
    r = client.post("/v1/requests", headers={"Authorization": "Bearer test-agent"},
                    json={"title": "t"})
    return r.json()["id"]


def _enroll(client, code, name="Kevin's iPhone 17", apns="apns-e2e-1"):
    return client.post("/v1/devices/enroll",
                       headers={"Authorization": f"Bearer {code}"},
                       json={"apns_token": apns, "name": name})


def test_enroll_returns_named_token_that_decides(client):
    code = _mint_code(client)
    r = _enroll(client, code)
    assert r.status_code == 200
    tok = r.json()["token"]
    assert TOKEN_RE.fullmatch(tok)
    # create a pending request as the agent, then decide with the minted token
    rid = _create_pending(client)
    d = client.post(f"/v1/requests/{rid}/decision",
                    headers={"Authorization": f"Bearer {tok}"},
                    json={"decision": "approve"})
    assert d.status_code == 200
    row = client.db.get_request(rid)
    assert row["decided_via"] == "app-token"
    assert row["decided_by"] == "kevin-s-iphone-17"


def test_reenroll_rotates_and_old_token_denied(client):
    t1 = _enroll(client, _mint_code(client)).json()["token"]
    t2 = _enroll(client, _mint_code(client)).json()["token"]   # same apns_token
    assert t1 != t2
    # old token is revoked: any authed call now 403s (auth denies generically —
    # the design's "401s" is imprecise; the server's deny is a uniform 403)
    r = client.get("/v1/requests?status=pending",
                   headers={"Authorization": f"Bearer {t1}"})
    assert r.status_code == 403
    r2 = client.get("/v1/requests?status=pending",
                    headers={"Authorization": f"Bearer {t2}"})
    assert r2.status_code == 200
    # rotation suffixed the name (revoked rows keep their UNIQUE name)
    names = [t["name"] for t in client.db.list_tokens()]
    assert "kevin-s-iphone-17" in names and "kevin-s-iphone-17-2" in names


def test_mint_failure_still_enrolls_200_without_token(client, monkeypatch):
    import arbiter.app as app_mod
    monkeypatch.setattr(app_mod, "mint_device_token",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = _enroll(client, _mint_code(client), apns="apns-mintfail")
    assert r.status_code == 200
    assert "token" not in r.json()
    assert r.json()["id"]                          # device row still written


def test_reserved_device_name_is_suffixed_not_minted_verbatim(client):
    r = _enroll(client, _mint_code(client), name="app", apns="apns-reserved")
    tok_names = [t["name"] for t in client.db.list_tokens()]
    assert "token" in r.json()
    assert "app-2" in tok_names        # never a minted token literally named "app"

"""iOS 0.6 A1 — per-device token minted at enrolment. Unit half: sanitise + mint."""
import re
import sqlite3

from arbiter import enroll
from arbiter.cli import _mint_pair_code
from arbiter.enroll import _sanitise_token_name

TOKEN_RE = re.compile(r"hma_app_[0-9a-f]{48}")


def test_sanitise_basic():
    assert _sanitise_token_name("Kevin's iPhone 17") == "kevin-s-iphone-17"

def test_sanitise_collapses_runs_and_trims():
    assert _sanitise_token_name("  --Wild  ***  Name--  ") == "wild-name"

def test_sanitise_caps_at_62():
    # capped below 64 so a mint's "-N" rotation suffix never pushes the final
    # minted name past the documented 64-char cap
    assert len(_sanitise_token_name("x" * 200)) <= 62

def test_sanitise_empty_falls_back():
    assert _sanitise_token_name("!!!") == "device"


# ── end-to-end half: real /v1/devices/enroll route, real registry/control ──

def _mint_code(client, minutes=15):
    """Mint a single-use pairing code against the 'default' tenant the shared
    `client` fixture provisions (conftest.py's `registry_env`)."""
    code, _ = _mint_pair_code(client.env.control, "default", minutes)
    return code


def _create_pending(client, agent_headers):
    """Create a pending approval request as the agent, returning its id."""
    r = client.post("/v1/requests", headers=agent_headers, json={"title": "t"})
    return r.json()["id"]


def _enroll(client, code, name="Kevin's iPhone 17", apns="apns-e2e-1"):
    return client.post("/v1/devices/enroll",
                       headers={"Authorization": f"Bearer {code}"},
                       json={"apns_token": apns, "name": name})


def test_enroll_returns_named_token_that_decides(client, agent_headers):
    code = _mint_code(client)
    r = _enroll(client, code)
    assert r.status_code == 200
    body = r.json()
    tok = body["token"]
    assert TOKEN_RE.fullmatch(tok)
    # response reflects the newly minted name, not the pre-mint snapshot (§review #1)
    assert body["token_name"] == "kevin-s-iphone-17"
    # create a pending request as the agent, then decide with the minted token
    rid = _create_pending(client, agent_headers)
    d = client.post(f"/v1/requests/{rid}/decision",
                    headers={"Authorization": f"Bearer {tok}"},
                    json={"decision": "approve"})
    assert d.status_code == 200
    row = client.db.get_request(rid)
    assert row["decided_via"] == "app-token"
    assert row["decided_by"] == "kevin-s-iphone-17"


def test_reenroll_rotates_and_old_token_denied(client):
    r1 = _enroll(client, _mint_code(client))
    t1 = r1.json()["token"]
    assert r1.json()["token_name"] == "kevin-s-iphone-17"
    r2 = _enroll(client, _mint_code(client))          # same apns_token
    t2 = r2.json()["token"]
    # response reflects the ROTATED name, not the just-revoked predecessor (§review #1)
    assert r2.json()["token_name"] == "kevin-s-iphone-17-2"
    assert t1 != t2
    # old token is revoked: any authed call now 403s (auth denies generically —
    # the design's "401s" is imprecise; the server's deny is a uniform 403)
    r = client.get("/v1/requests?status=pending",
                   headers={"Authorization": f"Bearer {t1}"})
    assert r.status_code == 403
    r2b = client.get("/v1/requests?status=pending",
                     headers={"Authorization": f"Bearer {t2}"})
    assert r2b.status_code == 200
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


def test_revoke_failure_still_enrolls_200_with_new_token(client, monkeypatch):
    """A re-pair whose revoke-the-predecessor step blows up must still hand the
    phone its new, working token (§review #2/#3) — the token is attached to
    the response right after a successful mint, before the revoke/link writes."""
    import arbiter.app as app_mod
    _enroll(client, _mint_code(client), apns="apns-revokefail")   # first pair
    monkeypatch.setattr(app_mod, "revoke_cell_token",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = _enroll(client, _mint_code(client), apns="apns-revokefail")   # re-pair
    assert r.status_code == 200
    assert TOKEN_RE.fullmatch(r.json()["token"])


def test_reserved_device_name_is_suffixed_not_minted_verbatim(client):
    r = _enroll(client, _mint_code(client), name="app", apns="apns-reserved")
    tok_names = [t["name"] for t in client.db.list_tokens()]
    assert "token" in r.json()
    assert "app-2" in tok_names        # never a minted token literally named "app"
    dev_names = {d["apns_token"]: d["token_name"] for d in client.db.list_devices()}
    assert dev_names["apns-reserved"] == "app-2"


# ── 0.7 S3: candidate widening (base, -2..-9, then three 8-hex attempts) ──

class _FakeCell:
    """mint_device_token only ever passes cell.db and cell.tenant_id through to
    mint_cell_token, which these tests replace — so both can be inert."""
    db = None
    tenant_id = "default"


def test_candidate_names_order_and_hex_tail(monkeypatch):
    seq = iter(["aaaaaaaa", "bbbbbbbb", "cccccccc"])
    monkeypatch.setattr(enroll.secrets, "token_hex", lambda n: next(seq))
    assert list(enroll._candidate_names("kevin")) == [
        "kevin", "kevin-2", "kevin-3", "kevin-4", "kevin-5",
        "kevin-6", "kevin-7", "kevin-8", "kevin-9",
        "kevin-aaaaaaaa", "kevin-bbbbbbbb", "kevin-cccccccc"]


def test_candidate_names_never_exceed_the_64_char_cap():
    base = _sanitise_token_name("x" * 200)          # the pinned 62-char base cap
    assert len(base) == 62
    names = list(enroll._candidate_names(base))
    assert max(len(n) for n in names) == 64         # "<62>-9" and "<55>-<8 hex>"
    assert all(re.fullmatch(r"[a-z0-9-]{1,64}", n) for n in names)


def test_mint_falls_back_to_a_hex_suffix_when_the_numeric_run_is_taken(monkeypatch):
    taken = {"kevin-s-iphone-17"} | {f"kevin-s-iphone-17-{i}" for i in range(2, 10)}
    tried: list[str] = []

    def _mint(control, cell_db, tenant_id, name, role):
        tried.append(name)
        if name in taken:
            raise sqlite3.IntegrityError("UNIQUE constraint failed: tokens.name")
        return f"hma_{role}_" + "0" * 48

    monkeypatch.setattr(enroll, "mint_cell_token", _mint)
    name, value = enroll.mint_device_token(None, _FakeCell(), {}, "Kevin's iPhone 17")
    assert re.fullmatch(r"kevin-s-iphone-17-[0-9a-f]{8}", name)
    assert TOKEN_RE.fullmatch(value)
    assert len(tried) == 10                         # base + -2..-9 + one hex attempt


def test_mint_gives_up_after_exactly_three_hex_attempts(monkeypatch):
    tried: list[str] = []

    def _always_taken(control, cell_db, tenant_id, name, role):
        tried.append(name)
        raise sqlite3.IntegrityError("UNIQUE constraint failed: tokens.name")

    monkeypatch.setattr(enroll, "mint_cell_token", _always_taken)
    monkeypatch.setattr(enroll.secrets, "token_hex", lambda n: "abcd1234")
    assert enroll.mint_device_token(None, _FakeCell(), {}, "Kevin's iPhone 17") is None
    assert tried == (["kevin-s-iphone-17"]
                     + [f"kevin-s-iphone-17-{i}" for i in range(2, 10)]
                     + ["kevin-s-iphone-17-abcd1234"] * 3)

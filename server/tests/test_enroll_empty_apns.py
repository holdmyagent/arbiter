"""0.7 S1 (F-B1-1) — an empty apns_token enrolment never links or revokes.

Device rows are keyed on `apns_token` (UNIQUE), so every enrolment that sends
"" — a pairing done before the phone has an APNs token, or any Simulator,
which never gets one — lands on the SAME device row. Before this fix the
second such enrolment read the FIRST device's `token_name` off that shared row
and revoked it: an approval outage on an innocent, working phone.
"""
import re

from arbiter.cli import _mint_pair_code

TOKEN_RE = re.compile(r"hma_app_[0-9a-f]{48}")


def _enroll(client, name, apns):
    """One enrolment through the real route; each needs its own single-use code."""
    code, _ = _mint_pair_code(client.env.control, "default", 15)
    return client.post("/v1/devices/enroll",
                       headers={"Authorization": f"Bearer {code}"},
                       json={"apns_token": apns, "name": name})


def test_empty_apns_enrol_mints_without_linking(client):
    r = _enroll(client, "Kevin's iPhone 17", "")
    assert r.status_code == 200
    body = r.json()
    assert TOKEN_RE.fullmatch(body["token"])            # the mint still happens
    assert body["token_name"] == "kevin-s-iphone-17"    # names the token just handed back
    rows = {d["apns_token"]: d for d in client.db.list_devices()}
    assert rows[""]["token_name"] is None               # the shared ROW is never linked


def test_two_empty_apns_enrolments_never_revoke_each_other(client):
    first = _enroll(client, "Simulator A", "").json()["token"]
    second = _enroll(client, "Simulator B", "").json()["token"]
    assert first != second
    # Both credentials still work: neither enrolment revoked the other's token.
    for tok in (first, second):
        r = client.get("/v1/requests?status=pending",
                       headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
    revoked = {t["name"]: t["revoked_at"] for t in client.db.list_tokens()}
    assert revoked["simulator-a"] is None and revoked["simulator-b"] is None


def test_real_apns_rotation_is_unchanged(client):
    r1 = _enroll(client, "Kevin's iPhone 17", "apns-real-1")
    t1 = r1.json()["token"]
    assert r1.json()["token_name"] == "kevin-s-iphone-17"
    r2 = _enroll(client, "Kevin's iPhone 17", "apns-real-1")   # the same device re-pairs
    assert r2.json()["token_name"] == "kevin-s-iphone-17-2"    # rotated
    # the predecessor is revoked, exactly as in 0.6
    assert client.get("/v1/requests?status=pending",
                      headers={"Authorization": f"Bearer {t1}"}).status_code == 403
    rows = {d["apns_token"]: d for d in client.db.list_devices()}
    assert rows["apns-real-1"]["token_name"] == "kevin-s-iphone-17-2"   # the row IS linked

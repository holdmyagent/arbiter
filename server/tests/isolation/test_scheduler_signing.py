"""Task I9 (§16): the scheduler signs each expiry with the FIRING cell's own
key. Bob's expiry verdict must verify under bob's JWKS and FAIL under alice's
(and under the wrong audience even with the right key) — invariant §15.10/§6."""
import pytest
from datetime import datetime, timedelta, timezone

import jwt

from tests.isolation.conftest import pubkey_for


def _pub(client, hdr):
    kid, key = pubkey_for(client, hdr)
    return kid, key


def test_expiry_verdict_signed_by_the_firing_cell_only(two_tenant):
    tt = two_tenant
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    # a pending request in bob that will expire
    rid = tt.client.post("/v1/requests", headers=b.agent_hdr,
                         json={"title": "bob-expiring"}).json()["id"]
    # fire the scheduler far in the future so bob's row is overdue
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)
    fired = tt.app.state.scheduler_tick(now=future)
    assert rid in [r["id"] for r in fired]
    # the verdict is readable in bob's cell and carries bob's tenant binding
    v = tt.client.get(f"/v1/requests/{rid}/verdict", headers=b.app_hdr)
    assert v.status_code == 200
    jws = v.json()["verdict"]
    kid_b, key_b = _pub(tt.client, b.app_hdr)
    kid_a, key_a = _pub(tt.client, a.app_hdr)
    # BASELINE: verifies under bob's key + bob audience + bob tenant claim
    claims = jwt.decode(jws, key=key_b, algorithms=["EdDSA"], audience="hma-verdict:bob")
    assert claims["hma"]["decision"] == "expired"
    assert claims["hma"]["tenant_id"] == "bob"
    assert jwt.get_unverified_header(jws)["kid"] == kid_b and kid_b.startswith("bob:")
    # ISOLATION: alice's key must NOT verify bob's expiry verdict
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(jws, key=key_a, algorithms=["EdDSA"], audience="hma-verdict:bob")
    # and the wrong audience is rejected even under the right key
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(jws, key=key_b, algorithms=["EdDSA"], audience="hma-verdict:alice")

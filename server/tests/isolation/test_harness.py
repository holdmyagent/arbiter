from tests.isolation.conftest import pubkey_for


def test_two_tenants_provisioned_distinctly(two_tenant):
    tt = two_tenant
    assert set(tt.tenants) == {"alice", "bob"}
    a, b = tt.tenants["alice"], tt.tenants["bob"]
    # distinct dirs, distinct epochs are independent monotonic values
    assert a.dir != b.dir and a.dir.is_dir() and b.dir.is_dir()
    # each app bearer resolves to its own tenant's JWKS with a tenant-namespaced kid
    kid_a, _ = pubkey_for(tt.client, a.app_hdr)
    kid_b, _ = pubkey_for(tt.client, b.app_hdr)
    assert kid_a.startswith("alice:") and kid_b.startswith("bob:")
    assert kid_a != kid_b


def test_router_routes_only_full_hashes(two_tenant):
    import hashlib
    tt = two_tenant
    a = tt.tenants["alice"]
    full = hashlib.sha256(a.app_bearer.encode()).hexdigest()
    assert tt.control.resolve(full) == ("alice", a.epoch)
    # a truncated hash must NOT route (no shard/route on a truncated hash)
    assert tt.control.resolve(full[:32]) is None

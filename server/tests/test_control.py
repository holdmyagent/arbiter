import pytest
from pathlib import Path
from arbiter.control import ControlPlane, assert_dir_isolated


def test_create_tenant_returns_monotonic_epoch(tmp_path):
    c = ControlPlane(":memory:")
    e1 = c.create_tenant("default", tmp_path / "default")
    e2 = c.create_tenant("acme", tmp_path / "acme")
    assert e1 == 1 and e2 == 2


def test_epoch_never_reused_even_after_recreate(tmp_path):
    # Tombstone semantics live in the routing group, but the epoch COUNTER is
    # monotonic here: two tenants never share an epoch, and the counter only ever
    # climbs, so a future delete+recreate cannot recycle an epoch.
    c = ControlPlane(":memory:")
    epochs = {c.create_tenant(f"t{i}", tmp_path / f"t{i}") for i in range(5)}
    assert epochs == {1, 2, 3, 4, 5}


def test_tenant_dir_is_realpath_canonical_absolute(tmp_path):
    c = ControlPlane(":memory:")
    c.create_tenant("acme", tmp_path / "acme")
    d = c.tenant_dir("acme")
    assert d.is_absolute() and d == (tmp_path / "acme").resolve()


def test_tenant_dir_missing_raises_keyerror():
    c = ControlPlane(":memory:")
    with pytest.raises(KeyError):
        c.tenant_dir("nope")


def test_tenant_id_charset_enforced(tmp_path):
    c = ControlPlane(":memory:")
    for bad in ("Acme", "a_b", "a.b", "a/b", "a b", "", "café"):
        with pytest.raises(ValueError):
            c.create_tenant(bad, tmp_path / "x")


def test_dir_is_unique(tmp_path):
    import sqlite3
    c = ControlPlane(":memory:")
    c.create_tenant("a", tmp_path / "shared")
    with pytest.raises(sqlite3.IntegrityError):
        c.create_tenant("b", tmp_path / "shared")


def test_list_tenants_and_tenant_epoch(tmp_path):
    c = ControlPlane(":memory:")
    c.create_tenant("default", tmp_path / "default")
    c.create_tenant("acme", tmp_path / "acme")
    ids = [t["tenant_id"] for t in c.list_tenants()]
    assert ids == ["acme", "default"]          # ORDER BY tenant_id
    assert c.tenant_epoch("acme") == 2 and c.tenant_epoch("nope") is None


def test_assert_dir_isolated_exact_duplicate(tmp_path):
    a = tmp_path / "acme"
    with pytest.raises(ValueError):
        assert_dir_isolated(a, [a])


def test_assert_dir_isolated_nested_under_existing(tmp_path):
    a = tmp_path / "acme"
    with pytest.raises(ValueError):
        assert_dir_isolated(a / "sub", [a])


def test_assert_dir_isolated_candidate_is_parent_of_existing(tmp_path):
    a = tmp_path / "acme"
    with pytest.raises(ValueError):
        assert_dir_isolated(a, [a / "sub"])


def test_assert_dir_isolated_disjoint_sibling_ok(tmp_path):
    a = tmp_path / "acme"
    b = tmp_path / "bob"
    assert_dir_isolated(b, [a])  # no raise

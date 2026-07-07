import os
import stat
from pathlib import Path

import pytest

from arbiter.control import ControlPlane, assert_dir_isolated


def _open(tmp_path) -> ControlPlane:
    root = tmp_path / "tenants"
    root.mkdir()
    return ControlPlane.open(tmp_path / "control", root)


def test_open_creates_schema_and_mac_key(tmp_path):
    cp = _open(tmp_path)
    tables = {r[0] for r in cp.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"tenants", "token_route"} <= tables
    key_path = tmp_path / "control" / "control_mac.key"
    assert key_path.is_file()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600


def test_mac_is_deterministic_and_key_bound(tmp_path):
    cp = _open(tmp_path)
    h = "a" * 64
    m1 = cp._mac(h, "acme", 1)
    assert m1 == cp._mac(h, "acme", 1)            # deterministic
    assert m1 != cp._mac(h, "acme", 2)            # epoch-bound
    assert m1 != cp._mac(h, "other", 1)           # tenant-bound
    # A second control plane with its own key produces different MACs.
    cp2 = ControlPlane.open(tmp_path / "control2", tmp_path / "tenants")
    assert cp2._mac(h, "acme", 1) != m1


def test_create_tenant_returns_monotonic_epochs(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    e1 = cp.create_tenant("acme", str(root / "acme"))
    e2 = cp.create_tenant("globex", str(root / "globex"))
    assert e1 == 1 and e2 == 2
    assert cp.epoch_of("acme") == 1
    assert cp.tenant_dir("acme") == (root / "acme").resolve()
    ids = {t["tenant_id"] for t in cp.list_tenants()}
    assert ids == {"acme", "globex"}


def test_create_tenant_rejects_bad_charset(tmp_path):
    cp = _open(tmp_path)
    for bad_id in ("Acme_Corp", "", "café", "a.b", "a/b", "a b"):
        with pytest.raises(ValueError):
            cp.create_tenant(bad_id, str(tmp_path / "tenants" / bad_id))


def test_create_tenant_rejects_dir_outside_root(tmp_path):
    cp = _open(tmp_path)
    with pytest.raises(ValueError):
        cp.create_tenant("acme", "/etc/acme")


def test_create_tenant_rejects_live_duplicate(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    cp.create_tenant("acme", str(root / "acme"))
    with pytest.raises(ValueError):
        cp.create_tenant("acme", str(root / "acme2"))


def test_create_tenant_rejects_overlapping_dir(tmp_path):
    # §15.7 mint-side isolation: a dir that duplicates, nests under, is a parent of,
    # or symlink/`..`-resolves into an existing live tenant's dir is rejected.
    import os
    cp = _open(tmp_path)
    root = (tmp_path / "tenants")
    (root / "acme").mkdir(parents=True)
    cp.create_tenant("acme", str(root / "acme"))
    with pytest.raises(ValueError):
        cp.create_tenant("dup", str(root / "acme"))            # exact duplicate
    with pytest.raises(ValueError):
        cp.create_tenant("nested", str(root / "acme" / "sub"))  # nested under acme
    os.symlink(root / "acme", root / "acme-link", target_is_directory=True)
    with pytest.raises(ValueError):
        cp.create_tenant("linked", str(root / "acme-link"))     # symlink back into acme
    with pytest.raises(ValueError):
        cp.create_tenant("dotdot", str(root / "x" / ".." / "acme"))  # `..` resolves to acme


def test_epoch_of_unknown_is_none(tmp_path):
    cp = _open(tmp_path)
    assert cp.epoch_of("nope") is None


def test_tenant_dir_missing_raises_keyerror(tmp_path):
    cp = _open(tmp_path)
    with pytest.raises(KeyError):
        cp.tenant_dir("nope")


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


def test_resolve_roundtrip_and_full_hash_only(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    h = "b" * 64
    cp.add_route(h, "acme")
    assert cp.resolve(h) == ("acme", 1)
    # A truncated hash is a different PK — it never routes.
    assert cp.resolve(h[:8]) is None
    assert cp.resolve("c" * 64) is None            # unknown route


def test_resolve_rejects_tampered_route(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    cp.create_tenant("victim", str(tmp_path / "tenants" / "victim"))
    h = "d" * 64
    cp.add_route(h, "acme")
    # Attacker repoints the route to another tenant WITHOUT the MAC key.
    cp.conn.execute("UPDATE token_route SET tenant_id='victim' WHERE token_hash=?", (h,))
    cp.conn.commit()
    assert cp.resolve(h) is None                   # MAC over (hash,victim,epoch) fails


def test_remove_route(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    h = "e" * 64
    cp.add_route(h, "acme")
    cp.remove_route(h)
    assert cp.resolve(h) is None


def test_is_disabled(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    assert cp.is_disabled("acme") is False
    assert cp.is_disabled("ghost") is True         # absent -> fail closed


def test_disable_then_resolution_reports_disabled(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    cp.disable_tenant("acme")
    assert cp.is_disabled("acme") is True


def test_tombstone_recreate_gets_new_epoch_and_stale_route_fails_closed(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    cp.create_tenant("acme", str(root / "acme"))       # epoch 1
    h = "f" * 64
    cp.add_route(h, "acme")                            # MAC bound to epoch 1
    assert cp.resolve(h) == ("acme", 1)
    cp.tombstone_tenant("acme")
    # tenant_id is free again; recreate gets a fresh, higher, non-recycled epoch.
    e2 = cp.create_tenant("acme", str(root / "acme-v2"))
    assert e2 == 2
    # The stale route (MAC over epoch 1) no longer verifies against live epoch 2.
    assert cp.resolve(h) is None


def test_resolve_fails_closed_on_tampered_mac(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    h = "1" * 64
    cp.add_route(h, "acme")
    cp.conn.execute("UPDATE token_route SET mac='deadbeef' WHERE token_hash=?", (h,))
    cp.conn.commit()
    assert cp.resolve(h) is None


def test_resolve_fails_closed_on_stale_epoch_after_recreate(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    cp.create_tenant("acme", str(root / "acme"))       # epoch 1
    h = "2" * 64
    cp.add_route(h, "acme")                            # MAC bound to epoch 1
    cp.tombstone_tenant("acme")
    cp.create_tenant("acme", str(root / "acme-v2"))    # epoch 2
    assert cp.resolve(h) is None                       # old route binds old epoch


def test_is_disabled_true_for_disabled_tenant(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    cp.disable_tenant("acme")
    assert cp.is_disabled("acme") is True

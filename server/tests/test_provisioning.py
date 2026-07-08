import pytest
from pathlib import Path

from arbiter.provisioning import canonicalize_tenant_dir, assert_dir_isolated, TenantDirError
from arbiter import control as control_mod


def test_canonicalize_rejects_bad_charset(tmp_path):
    for bad in ("../evil", "Bad_Name", "a/b", "UP", "sp ace"):
        with pytest.raises(TenantDirError):
            canonicalize_tenant_dir(bad, tmp_path)


def test_canonicalize_returns_abs_realpath_under_root(tmp_path):
    root = tmp_path / "tenants"
    p = canonicalize_tenant_dir("acme", root)
    assert p.is_absolute() and p == (root.resolve() / "acme")


def test_canonicalize_rejects_symlink_escape(tmp_path):
    root = tmp_path / "tenants"; root.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    (root / "evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(TenantDirError):
        canonicalize_tenant_dir("evil", root)


def test_assert_dir_isolated_rejects_overlap_both_directions(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    with pytest.raises(TenantDirError):
        assert_dir_isolated(a, [a])                 # exact duplicate
    with pytest.raises(TenantDirError):
        assert_dir_isolated(tmp_path, [a])          # candidate is parent of existing
    with pytest.raises(TenantDirError):
        assert_dir_isolated(a / "child", [a])       # candidate is child of existing
    assert_dir_isolated(tmp_path / "b", [a])        # sibling — no raise


def test_assert_dir_isolated_rejects_symlink_into_existing(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    link = tmp_path / "link-to-a"
    link.symlink_to(a, target_is_directory=True)
    with pytest.raises(TenantDirError):
        assert_dir_isolated(link, [a])
    with pytest.raises(TenantDirError):
        assert_dir_isolated(link / "child", [a])


def test_assert_dir_isolated_rejects_dotdot_resolving_into_existing(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    dotdot_candidate = b / ".." / "a"
    with pytest.raises(TenantDirError):
        assert_dir_isolated(dotdot_candidate, [a])


def test_provisioning_and_control_isolation_logic_agree(tmp_path):
    """§15.7: the provisioning-side and control-side non-overlap checks must stay in
    lock-step. Exercise both on the identical set of inputs and assert they agree on
    every verdict (raise vs. no-raise) even though they raise different exception
    types (TenantDirError vs. ValueError)."""
    a = tmp_path / "a"; a.mkdir()
    link = tmp_path / "link-to-a"
    link.symlink_to(a, target_is_directory=True)
    cases = [
        (a, [a]),                 # exact duplicate
        (tmp_path, [a]),          # parent of existing
        (a / "child", [a]),       # child of existing
        (tmp_path / "b", [a]),    # sibling — no raise
        (link, [a]),              # symlink into existing
        (link / "child", [a]),    # symlink-descendant into existing
    ]
    for candidate, existing in cases:
        prov_raised = False
        ctrl_raised = False
        try:
            assert_dir_isolated(candidate, existing)
        except TenantDirError:
            prov_raised = True
        try:
            control_mod.assert_dir_isolated(candidate, existing)
        except ValueError:
            ctrl_raised = True
        assert prov_raised == ctrl_raised, (candidate, existing)

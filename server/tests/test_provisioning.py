import hashlib

import pytest

from arbiter.db import Database
from arbiter.provisioning import canonicalize_tenant_dir, assert_dir_isolated, TenantDirError
from arbiter import control as control_mod
from arbiter.control import ControlPlane
from arbiter.signing import KEY_FILENAME
from arbiter.provisioning import provision_tenant, mint_cell_token, revoke_cell_token


def _h(v):
    return hashlib.sha256(v.encode()).hexdigest()


def _control(tmp_path):
    # NOTE: the H2 brief's illustrative `ControlPlane(tmp_path / "control.sqlite3")`
    # doesn't match the shipped constructor (`ControlPlane(db_path, mac_key,
    # tenants_root)` / classmethod `.open(control_dir, tenants_root)` — same drift
    # H1's report flagged for `signing.load_or_create_keypair`). Use the real API.
    root = tmp_path / "tenants"
    return ControlPlane.open(tmp_path / "control", root), root


def test_canonicalize_rejects_bad_charset(tmp_path):
    for bad in ("../evil", "Bad_Name", "a/b", "UP", "sp ace"):
        with pytest.raises(TenantDirError):
            canonicalize_tenant_dir(bad, tmp_path)


def test_canonicalize_returns_abs_realpath_under_root(tmp_path):
    root = tmp_path / "tenants"
    p = canonicalize_tenant_dir("acme", root)
    assert p.is_absolute() and p == (root.resolve() / "acme")


def test_canonicalize_rejects_symlink_escape(tmp_path):
    root = tmp_path / "tenants"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(TenantDirError):
        canonicalize_tenant_dir("evil", root)


def test_assert_dir_isolated_rejects_overlap_both_directions(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    with pytest.raises(TenantDirError):
        assert_dir_isolated(a, [a])                 # exact duplicate
    with pytest.raises(TenantDirError):
        assert_dir_isolated(tmp_path, [a])          # candidate is parent of existing
    with pytest.raises(TenantDirError):
        assert_dir_isolated(a / "child", [a])       # candidate is child of existing
    assert_dir_isolated(tmp_path / "b", [a])        # sibling — no raise


def test_assert_dir_isolated_rejects_symlink_into_existing(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    link = tmp_path / "link-to-a"
    link.symlink_to(a, target_is_directory=True)
    with pytest.raises(TenantDirError):
        assert_dir_isolated(link, [a])
    with pytest.raises(TenantDirError):
        assert_dir_isolated(link / "child", [a])


def test_assert_dir_isolated_rejects_dotdot_resolving_into_existing(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    b = tmp_path / "b"
    b.mkdir()
    dotdot_candidate = b / ".." / "a"
    with pytest.raises(TenantDirError):
        assert_dir_isolated(dotdot_candidate, [a])


def test_provisioning_and_control_isolation_logic_agree(tmp_path):
    """§15.7: the provisioning-side and control-side non-overlap checks must stay in
    lock-step. Exercise both on the identical set of inputs and assert they agree on
    every verdict (raise vs. no-raise) even though they raise different exception
    types (TenantDirError vs. ValueError)."""
    a = tmp_path / "a"
    a.mkdir()
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


def test_provision_two_tenants_have_distinct_keys_and_tokens(tmp_path):
    control, root = _control(tmp_path)
    a = provision_tenant(control, root, "alpha")
    b = provision_tenant(control, root, "beta")
    # distinct on-disk key bytes (§15.7: no two cells load identical key bytes)
    assert (a.dir / KEY_FILENAME).read_bytes() != (b.dir / KEY_FILENAME).read_bytes()
    assert a.epoch != b.epoch or a.tenant_id != b.tenant_id
    assert a.app_token.startswith("hma_app_") and a.warden_token.startswith("hma_warden_")
    # both first-tokens route to their own tenant
    assert control.resolve(_h(a.app_token))[0] == "alpha"
    assert control.resolve(_h(b.warden_token))[0] == "beta"


def test_provision_duplicate_tenant_id_rejected(tmp_path):
    control, root = _control(tmp_path)
    provision_tenant(control, root, "acme")
    with pytest.raises(Exception):
        provision_tenant(control, root, "acme")   # dir already exists / tenant exists


def test_mint_writes_cell_row_then_route_and_revoke_reverses(tmp_path):
    # NOTE: the H3 brief's illustrative `ControlPlane(tmp_path / "control.sqlite3")`
    # doesn't match the shipped constructor — same drift noted in `_control` above.
    # Use the real API + the already-provisioned tenant's cell DB.
    control, root = _control(tmp_path)
    a = provision_tenant(control, root, "acme")
    cell = Database(str(a.dir / "arbiter.sqlite3"))
    tok = mint_cell_token(control, cell, "acme", "hermes", "agent")
    h = _h(tok)
    assert cell.get_token_by_hash(h)["name"] == "hermes"   # cell row present
    assert control.resolve(h)[0] == "acme"                 # route present
    revoke_cell_token(control, cell, "hermes")
    assert cell.get_token_by_hash(h)["revoked_at"] is not None  # cell revoked
    assert control.resolve(h) is None                          # route removed


def test_revoke_cell_token_missing_name_raises_keyerror(tmp_path):
    control, root = _control(tmp_path)
    a = provision_tenant(control, root, "acme")
    cell = Database(str(a.dir / "arbiter.sqlite3"))
    with pytest.raises(KeyError):
        revoke_cell_token(control, cell, "nonexistent")

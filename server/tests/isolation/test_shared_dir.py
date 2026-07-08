import os

import pytest

from tests.isolation.conftest import ControlPlane, TenantRegistry
from arbiter.config import Config
from arbiter.registry import open_cell
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _raw_pub(cell):
    return cell.signer.signing_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def test_overlapping_dirs_rejected_at_mint(tmp_path):
    # MINT side (§15.7): control.create_tenant itself rejects a dir that overlaps an
    # existing tenant (its own assert_dir_isolated guard), so each call RAISES.
    root = tmp_path / "fleet"; root.mkdir()
    control = ControlPlane.open(root / "control", root)
    a = root / "alice"; a.mkdir()
    control.create_tenant("alice", a)
    # exact duplicate
    with pytest.raises(ValueError):
        control.create_tenant("dup", a)
    # a prefix / nested dir (bob under alice) is overlapping → rejected
    with pytest.raises(ValueError):
        control.create_tenant("nested", a / "sub")
    # a symlink pointing back into alice → rejected (realpath-canonical unique)
    link = root / "alice-link"
    os.symlink(a, link)
    with pytest.raises(ValueError):
        control.create_tenant("linked", link)
    # a '..' escape resolving to alice → rejected
    with pytest.raises(ValueError):
        control.create_tenant("dotdot", root / "bob" / ".." / "alice")


def test_two_live_cells_never_load_identical_key_bytes(cfg, tmp_path):
    root = tmp_path / "fleet"; root.mkdir()
    control = ControlPlane.open(root / "control", root)
    registry = TenantRegistry(control, cfg=cfg, sender=None)
    import asyncio
    da = root / "alice"; da.mkdir(); ea = control.create_tenant("alice", da)
    db = root / "bob"; db.mkdir(); eb = control.create_tenant("bob", db)

    async def run():
        ca = await registry.acquire("alice", ea)
        cb = await registry.acquire("bob", eb)
        try:
            assert _raw_pub(ca) != _raw_pub(cb), "two cells loaded identical key bytes"
            assert ca.signer.kid != cb.signer.kid
        finally:
            registry.release(ca); registry.release(cb)

    asyncio.run(run())


def test_overlapping_dir_rejected_at_open(tmp_path):
    # OPEN side (§15.7 "AND at open"): with cell A already open at dir X, an open of a
    # SECOND cell whose dir equals or nests under X is rejected at open by the SAME
    # assert_dir_isolated guard mint uses — defense-in-depth against a control.db that
    # was symlink/`..`-swapped AFTER mint so two live tenants resolve to one dir.
    cfg = Config.load(str(tmp_path / "absent.toml"))
    x = (tmp_path / "fleet" / "alice"); x.mkdir(parents=True); x = x.resolve()
    open_cell("alice", x, 1, cfg)                                    # A opens fine
    with pytest.raises(ValueError):
        open_cell("intruder", x, 1, cfg, other_open_dirs=[x])        # exact overlap
    with pytest.raises(ValueError):
        open_cell("intruder", x / "sub", 1, cfg, other_open_dirs=[x])  # nested overlap

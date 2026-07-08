"""Tenant provisioning: dir-isolation guards (spec §14/§15.7).

Enforces that every tenant dir is realpath-canonical, `[a-z0-9-]`-only, lives
directly under a fixed root, and never overlaps another tenant's dir. This is
the provisioning-side (mint-path) home for the guard; the registry's cell-open
path and `ControlPlane.create_tenant` share a byte-identical-logic copy that
lives in the leaf module `arbiter.control` (see that module's
`assert_dir_isolated` for why it must live there instead of being imported
from here — no import cycle). Keep the two bodies in lock-step per §15.7.
"""
from __future__ import annotations

import re
from pathlib import Path

_TENANT_ID_RE = re.compile(r"^[a-z0-9-]+$")


class TenantDirError(Exception):
    """A tenant dir is off-charset, escapes the root, or overlaps another tenant."""


def canonicalize_tenant_dir(tenant_id: str, root: Path) -> Path:
    if not _TENANT_ID_RE.match(tenant_id):
        raise TenantDirError(f"tenant_id must match [a-z0-9-]: {tenant_id!r}")
    root = Path(root).expanduser().resolve()
    resolved = (root / tenant_id).resolve()
    # A valid id has no separators, so the ONLY way resolved.parent != root is a
    # symlink at root/<id> pointing elsewhere — reject it (defeats key-sharing).
    if resolved.parent != root:
        raise TenantDirError(f"tenant dir escapes root: {resolved} not directly under {root}")
    return resolved


def assert_dir_isolated(candidate: Path, existing: list[Path]) -> None:
    c = Path(candidate).resolve()
    for other in existing:
        o = Path(other).resolve()
        if c == o or c.is_relative_to(o) or o.is_relative_to(c):
            raise TenantDirError(f"tenant dir overlaps existing dir: {c} vs {o}")

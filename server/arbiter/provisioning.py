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

import hashlib
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .db import Database
from .signing import load_or_create_signer

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


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mint_cell_token(control, cell_db: Database, tenant_id: str, name: str, role: str,
                     scopes: dict | None = None, expires_at: str | None = None) -> str:
    """Mint a token: CELL row first, ROUTER row second (§12 — a cell row without
    a route is unusable, so a crash between the two fails closed rather than
    handing out a ghost credential). Returns the clear token; shown once, never
    stored (only its hash is persisted)."""
    value = f"hma_{role}_{secrets.token_hex(24)}"
    token_hash = _hash_token(value)
    cell_db.create_token(name, role, token_hash, scopes, expires_at)  # CELL ROW FIRST
    control.add_route(token_hash, tenant_id)                          # router row SECOND
    cell_db.add_audit("-", "token_created", {"name": name, "role": role})
    return value


def revoke_cell_token(control, cell_db: Database, name: str) -> str:
    """Revoke a token: in-cell `revoked_at` first, router row removed second, so
    a cells-first/control-last backup that smears across the revoke sees the
    route already gone (§12 fail-closed). Raises KeyError if no such token."""
    row = cell_db.revoke_token(name)          # in-cell revoked_at FIRST
    if row is None:
        raise KeyError(name)
    control.remove_route(row["token_hash"])   # remove route SECOND
    cell_db.add_audit("-", "token_revoked", {"name": name})
    return name


@dataclass
class ProvisionResult:
    tenant_id: str
    epoch: int
    dir: Path
    app_token: str
    warden_token: str


def provision_tenant(control, root: Path, tenant_id: str) -> ProvisionResult:
    """Mint a fresh, isolated, key-distinct tenant cell (§14). Canonicalizes and
    isolation-checks the dir, creates a fresh migrated cell DB, mints this cell's
    OWN Ed25519 signing key (§15.7: no two cells ever load identical key bytes),
    registers the tenant with control for a fresh monotonic epoch, and mints the
    first app + warden tokens.

    Ordering matters for fail-closed behavior on a partial failure: the dir is
    created (and the cell DB/key minted) BEFORE control.create_tenant runs, so a
    crash before registration leaves an orphaned, unregistered directory (inert —
    never routable, never claims a live tenant_id) rather than a control-registered
    tenant with no working cell. control.create_tenant re-applies the identical
    §15.7 non-overlap check against the persisted roster (the authoritative
    mint-time rejection); the check here is a redundant early guard that must stay
    logic-identical to it.
    """
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    canon = canonicalize_tenant_dir(tenant_id, root)
    existing = [Path(t["dir"]) for t in control.list_tenants()]
    assert_dir_isolated(canon, existing)          # redundant early guard, see docstring
    canon.mkdir(parents=True, exist_ok=False)     # fresh dir; a collision fails closed
    cell_db = Database(str(canon / "arbiter.sqlite3"))   # runs the migration ladder
    load_or_create_signer(tenant_id, canon)       # mint this cell's OWN Ed25519 key
    epoch = control.create_tenant(tenant_id, str(canon))  # fresh monotonic epoch, MAC'd row
    app_token = mint_cell_token(control, cell_db, tenant_id, "app", "app")
    warden_token = mint_cell_token(control, cell_db, tenant_id, "warden", "warden")
    return ProvisionResult(tenant_id, epoch, canon, app_token, warden_token)

"""Device enrollment binding (§10).

A pairing credential is tenant-bound, single-use, and short-expiry. It is
resolved to its cell exactly like resolve_identity — router is a hint, the cell
is the authority — and the in-cell single-use redeem (Database.redeem_pairing)
is the authority that rejects a replayed or expired code. The tenant is derived
solely from the credential; no caller-supplied hint is ever consulted. Every
failure is the constant generic_403() padded to a fixed timing floor so a
caller cannot distinguish route-miss / disabled / in-cell-invalid.
"""
import hashlib
import re
import sqlite3
from contextlib import asynccontextmanager

from .errors import EqualizedFloor, generic_403
from .provisioning import RESERVED_TOKEN_NAMES, mint_cell_token

EQUALIZE_FLOOR = EqualizedFloor(0.05)


@asynccontextmanager
async def resolve_pairing(code: str, registry, control, *, floor: EqualizedFloor = EQUALIZE_FLOOR):
    """Yield the pinned Cell for a valid single-use pairing credential, else
    raise generic_403(). The cell stays pinned (registry.hold) for the body so
    the caller can write the device row before release. Single-use: redeem is
    committed before yielding, so the code cannot be replayed."""
    started = floor.clock()

    async def _fail():
        await floor.wait(started)
        raise generic_403()

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    route = control.resolve(code_hash)
    if route is None:
        await _fail()
    tenant_id, epoch = route
    if control.is_disabled(tenant_id):
        await _fail()
    async with registry.hold(tenant_id, epoch) as cell:
        if cell.epoch != epoch:
            await _fail()
        redeem_code, _ = cell.db.redeem_pairing(code_hash)
        if redeem_code != 200:
            await _fail()
        await floor.wait(started)     # equalize the SUCCESS path to the same floor
        yield cell


_NAME_KEEP = re.compile(r"[^a-z0-9-]+")


def _sanitise_token_name(raw: str) -> str:
    """Sanitise a device name to the token-name charset used across this
    project (^[a-z0-9-]{1,64}$): lowercase, runs of anything else become one
    dash, trimmed, capped at 62 so a mint's "-N" rotation suffix (up to
    "-9") can never push the final minted name past the documented 64-char
    cap. Falls back to 'device' so a mint is always attempted."""
    s = _NAME_KEEP.sub("-", raw.lower()).strip("-")
    while "--" in s:
        s = s.replace("--", "-")
    return s[:62].rstrip("-") or "device"


def mint_device_token(control, cell, device: dict, requested_name: str) -> tuple[str, str] | None:
    """Mint an app-role token named for DEVICE at enrolment; returns
    (token_name, token_value) or None if no candidate name is free.
    Reserved names are treated as taken (suffixed), never minted verbatim.
    The caller revokes the device's previous token AFTER a successful mint —
    a failed mint must leave the old credential untouched (R1)."""
    base = _sanitise_token_name(requested_name)
    candidates = [base] + [f"{base}-{i}" for i in range(2, 10)]
    for cand in candidates:
        if cand in RESERVED_TOKEN_NAMES:
            continue
        try:
            value = mint_cell_token(control, cell.db, cell.tenant_id, cand, "app")
        except sqlite3.IntegrityError:
            continue
        return cand, value
    return None

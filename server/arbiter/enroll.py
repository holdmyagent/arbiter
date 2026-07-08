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
from contextlib import asynccontextmanager

from .errors import EqualizedFloor, generic_403

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

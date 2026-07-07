from dataclasses import dataclass
from pathlib import Path

from .control import assert_dir_isolated   # §15.7 shared mint/open non-overlap guard (leaf module)
from .db import Database
from .notify import Dispatcher
from .auth import SlidingWindowLimiter
from .signing import Signer, load_or_create_signer
from .stream import Hub


@dataclass(eq=False)
class Cell:
    """The per-tenant isolation unit. Owns ALL tenant-scoped state; the ONLY path
    to this tenant's db/signer/hub/dispatcher/limiters. Nothing here lives on
    app.state (§3/§15.1). eq=False so binding is by object identity, never value."""
    tenant_id: str
    epoch: int
    dir: Path
    db: Database
    signer: Signer
    hub: Hub
    dispatcher: Dispatcher
    create_limiter: SlidingWindowLimiter
    login_limiter: SlidingWindowLimiter


def open_cell(tenant_id: str, dir, epoch: int, cfg, sender=None, other_open_dirs=()) -> Cell:
    """Build a fully-initialized Cell. Blocking (SQLite migrations + key mint);
    the registry runs it via asyncio.to_thread so it never blocks the event loop,
    and the single-flight future keeps the half-built cell unobservable until this
    returns (§5/§15.3).

    dir is re-validated realpath-canonical + absolute at open, AND re-checked for
    non-overlap against every OTHER currently-open cell's dir (§7/§14/§15.7: a shared
    dir hands two live cells the same key = silent cross-tenant forgery). The mint side
    (`ControlPlane.create_tenant`) enforces the same guard against the persisted roster;
    this is the "isolation AND at open" half — it also catches a control.db that was
    tampered/symlink-swapped AFTER mint so two live tenants now resolve to one dir.
    `other_open_dirs` is supplied by `TenantRegistry.acquire` (the dirs of all live
    `_Entry` cells, captured under the map lock). Dispatcher is built with THIS cell's
    db + the process delivery cfg; the notify group refines per-tenant
    webhook/ntfy/allowlist overrides (§9)."""
    d = Path(dir).expanduser()
    if not d.is_absolute():
        raise ValueError(f"cell dir must be absolute, got {dir!r}")
    resolved = d.resolve()
    if resolved != d:
        raise ValueError(f"cell dir must be realpath-canonical, got {dir!r}")
    # §15.7 at-open isolation: reject a dir overlapping any other LIVE cell's dir.
    # Same guard create_tenant applies at mint (shared arbiter.control.assert_dir_isolated).
    assert_dir_isolated(resolved, other_open_dirs)   # raises ValueError on overlap
    resolved.mkdir(parents=True, exist_ok=True)

    db = Database(str(resolved / "arbiter.sqlite3"))          # runs the full migration ladder
    signer = load_or_create_signer(tenant_id, resolved)        # per-cell key, namespaced kid
    hub = Hub()
    dispatcher = Dispatcher(cfg, db, sender=sender)
    create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)
    login_limiter = SlidingWindowLimiter(5, 60.0)
    return Cell(tenant_id=tenant_id, epoch=epoch, dir=resolved, db=db, signer=signer,
                hub=hub, dispatcher=dispatcher, create_limiter=create_limiter,
                login_limiter=login_limiter)

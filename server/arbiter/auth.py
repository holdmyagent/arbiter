import hashlib
import ipaddress
import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NoReturn

from fastapi import HTTPException, Request

log = logging.getLogger("arbiter.auth")

class SlidingWindowLimiter:
    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = defaultdict(deque)

    def _prune(self, key: str):
        q, now = self._hits[key], self.clock()
        while q and now - q[0] > self.window:
            q.popleft()

    def record_failure(self, key: str):
        self._prune(key)
        self._hits[key].append(self.clock())

    def blocked(self, key: str) -> bool:
        q = self._hits.get(key)
        if not q:
            return False
        now = self.clock()
        while q and now - q[0] > self.window:
            q.popleft()
        if not q:
            del self._hits[key]
        return len(q) >= self.limit

def trusted_client_id(request, cfg) -> str:
    """A TRUSTED per-caller key for the fleet auth-failure limiter (§13). Never
    key solely on a shared ingress IP (10 bad tokens would 429 the whole fleet).
    With no configured proxies the direct peer IS the trusted id; behind a
    configured trusted proxy, believe X-Forwarded-For and return the rightmost
    hop that is NOT itself a trusted proxy (the real client)."""
    peer = request.client.host if request.client else "unknown"
    trusted = getattr(cfg.server, "trusted_proxies", None) or []
    if not trusted:
        return peer
    def _in_trusted(ip_s: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            return False
        return any(ip in ipaddress.ip_network(c, strict=False) for c in trusted)
    if not _in_trusted(peer):
        return peer                      # peer isn't our proxy → XFF untrusted
    xff = request.headers.get("x-forwarded-for", "")
    for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
        if not _in_trusted(hop):
            return hop
    return peer

@dataclass
class Identity:
    # Field set matches the pinned contract Identity(tenant_id, name, role, scopes,
    # epoch, legacy). name/role stay first (all construction is keyword-based, so
    # membership — not position — is what composes) and the rest carry defaults so
    # this remains a drop-in for existing keyword constructions.
    name: str
    role: str                 # "agent" | "warden" | "app"
    tenant_id: str | None = None
    scopes: dict | None = None
    epoch: int | None = None
    legacy: bool = False      # True only for the static [auth] config tokens (deprecated)

_LEGACY_WARNED = False  # deprecation warning fires once per process

def _warn_legacy_once() -> None:
    global _LEGACY_WARNED
    if not _LEGACY_WARNED:
        _LEGACY_WARNED = True
        log.warning("legacy config token in use - static [auth] tokens are deprecated; "
                    "mint scoped tokens with hma token create")

def _deny() -> "NoReturn":
    # One identical generic 403 for route-miss / bad-MAC / in-cell-invalid /
    # disabled / epoch-mismatch — no tenant-existence or "real route key" oracle
    # in the status or body (spec §11).
    raise HTTPException(403, "forbidden")

async def resolve_identity(request: Request, registry, control):
    """Derive (Identity, Cell) from the bearer alone (spec §4). Router is a HINT;
    the cell is the authority. Returns a REFCOUNT-PINNED cell — the caller MUST
    registry.release(cell) exactly once. Any failure raises a generic 403 and
    releases the pin if one was taken."""
    cfg = request.app.state.cfg
    auth = request.headers.get("authorization", "")
    bearer = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
    # Hash unconditionally: a missing/short bearer takes the same dominant-cost
    # path as a real one (equalized-timing generic 403, §11).
    token_hash = hashlib.sha256(bearer.encode()).hexdigest()

    tenant_id = None
    epoch = None
    legacy_role = None
    if bearer and cfg.auth.app_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.app_token.encode()):
        tenant_id, legacy_role = "default", "app"          # strict 'default' (§14)
        _warn_legacy_once()
    elif bearer and cfg.auth.agent_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.agent_token.encode()):
        tenant_id, legacy_role = "default", "agent"        # hold-sdk 0.2.1 back-compat
        _warn_legacy_once()
    else:
        resolved = control.resolve(token_hash)             # (tenant_id, epoch) | None; MAC-verified
        if resolved is not None:
            tenant_id, epoch = resolved

    if tenant_id is None:
        _deny()                                            # route miss / bad MAC / unknown token

    if legacy_role is not None:
        epoch = control.epoch_of("default")
        if epoch is None:
            _deny()                                        # 'default' cell not provisioned

    if control.is_disabled(tenant_id):                     # read on EVERY resolution, never cached
        _deny()

    cell = await registry.acquire(tenant_id, epoch)        # pins; caller MUST release
    try:
        if cell.epoch != epoch:                            # snapshot-consistent / TOCTOU (§5)
            _deny()
        if legacy_role is not None:
            return (Identity(name=legacy_role, role=legacy_role, tenant_id="default",
                             scopes=None, epoch=epoch, legacy=True), cell)
        row = cell.db.get_token_by_hash(token_hash)        # re-validate in the CELL (full hex)
        if row is None:                                    # route hint but no cell row -> hard 403
            _deny()
        if row["revoked_at"] is not None:
            _deny()
        if row["expires_at"] is not None and \
                datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            _deny()
        cell.db.touch_token_last_used(row["id"])
        return (Identity(name=row["name"], role=row["role"], tenant_id=tenant_id,
                         scopes=row["scopes"], epoch=epoch, legacy=False), cell)
    except BaseException:
        registry.release(cell)                             # release the pin on EVERY failure exit
        raise


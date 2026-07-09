import hashlib
import ipaddress
import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NoReturn

from fastapi import Header, HTTPException, Request

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

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

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

def _check(request: Request, authorization: str | None, expected: tuple[str, ...], limiter: SlidingWindowLimiter):
    ip = _client_ip(request)
    if limiter.blocked(ip):
        raise HTTPException(429, "too many failed auth attempts")
    if not authorization or not authorization.startswith("Bearer "):
        limiter.record_failure(ip)
        log.warning("auth_failure ip=%s reason=missing_bearer", ip)
        raise HTTPException(401, "missing bearer token")
    supplied = authorization.removeprefix("Bearer ")
    if not any(secrets.compare_digest(supplied.encode(), e.encode()) for e in expected):
        limiter.record_failure(ip)
        log.warning("auth_failure ip=%s reason=invalid_token", ip)  # never log the supplied value
        raise HTTPException(403, "invalid token")

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

def _resolve_identity_legacy(db, cfg, bearer: str) -> Identity | None:
    """Single-tenant resolver (shipped pre-multitenancy). Still used by require_role
    and the inline /v1/audit/export check until Group C rewires routes onto the
    multi-tenant resolve_identity(request, registry, control) below (this task,
    B5, adds that resolver alongside — it does not touch existing route wiring).
    DB tokens first (sha256 lookup, revocation + expiry checks, last-used touch),
    then the legacy config tokens, which map to the fixed single identities
    Identity("agent","agent",legacy=True) / Identity("app","app",legacy=True)
    (deprecated; warns once per process)."""
    row = db.get_token_by_hash(hashlib.sha256(bearer.encode()).hexdigest())
    if row is not None:
        if row["revoked_at"] is not None:
            return None
        if row["expires_at"] is not None and \
                datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            return None
        db.touch_token_last_used(row["id"])
        return Identity(name=row["name"], role=row["role"])
    if cfg.auth.agent_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.agent_token.encode()):
        _warn_legacy_once()
        return Identity(name="agent", role="agent", legacy=True)
    if cfg.auth.app_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.app_token.encode()):
        _warn_legacy_once()
        return Identity(name="app", role="app", legacy=True)
    return None

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

def require_role(*roles: str):
    """FastAPI dependency factory: authenticate the bearer and return its Identity;
    403 unless identity.role is in *roles. Reads cfg/db/limiter off request.app.state
    (set in create_app), so the factory itself takes no cfg arguments and route
    modules can call require_role("agent", "warden") directly."""
    def dep(request: Request, authorization: str | None = Header(default=None)) -> Identity:
        st = request.app.state
        ip = _client_ip(request)
        if st.auth_limiter.blocked(ip):
            raise HTTPException(429, "too many failed auth attempts")
        if not authorization or not authorization.startswith("Bearer "):
            st.auth_limiter.record_failure(ip)
            log.warning("auth_failure ip=%s reason=missing_bearer", ip)
            raise HTTPException(401, "missing bearer token")
        ident = _resolve_identity_legacy(st.db, st.cfg, authorization.removeprefix("Bearer "))
        if ident is None:
            st.auth_limiter.record_failure(ip)
            log.warning("auth_failure ip=%s reason=invalid_token", ip)  # never log the supplied value
            raise HTTPException(403, "invalid token")
        if ident.role not in roles:
            st.auth_limiter.record_failure(ip)
            log.warning("auth_failure ip=%s reason=role_not_allowed role=%s", ip, ident.role)
            raise HTTPException(403, "invalid token")
        return ident
    return dep


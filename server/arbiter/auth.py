import hashlib
import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

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
    name: str
    role: str             # "agent" | "warden" | "app"
    legacy: bool = False  # True only for the static [auth] config tokens (deprecated)

_LEGACY_WARNED = False  # deprecation warning fires once per process

def _warn_legacy_once() -> None:
    global _LEGACY_WARNED
    if not _LEGACY_WARNED:
        _LEGACY_WARNED = True
        log.warning("legacy config token in use - static [auth] tokens are deprecated; "
                    "mint scoped tokens with hma token create")

def resolve_identity(db, cfg, bearer: str) -> Identity | None:
    """DB tokens first (sha256 lookup, revocation + expiry checks, last-used touch),
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
        ident = resolve_identity(st.db, st.cfg, authorization.removeprefix("Bearer "))
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


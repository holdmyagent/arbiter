import logging, secrets, time
from collections import defaultdict, deque
from fastapi import Header, HTTPException, Request

log = logging.getLogger("arbiter.auth")

class SlidingWindowLimiter:
    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = defaultdict(deque)

    def _prune(self, key: str):
        q, now = self._hits[key], self.clock()
        while q and now - q[0] > self.window: q.popleft()

    def record_failure(self, key: str):
        self._prune(key); self._hits[key].append(self.clock())

    def blocked(self, key: str) -> bool:
        self._prune(key); return len(self._hits[key]) >= self.limit

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
    if not any(secrets.compare_digest(supplied, e) for e in expected):
        limiter.record_failure(ip)
        log.warning("auth_failure ip=%s reason=invalid_token", ip)  # never log the supplied value
        raise HTTPException(403, "invalid token")

def require_agent(cfg, limiter):
    def dep(request: Request, authorization: str | None = Header(default=None)):
        _check(request, authorization, (cfg.auth.agent_token,), limiter)
    return dep

def require_app(cfg, limiter):
    def dep(request: Request, authorization: str | None = Header(default=None)):
        _check(request, authorization, (cfg.auth.app_token,), limiter)
    return dep

def require_agent_or_app(cfg, limiter):
    def dep(request: Request, authorization: str | None = Header(default=None)):
        _check(request, authorization, (cfg.auth.agent_token, cfg.auth.app_token), limiter)
    return dep

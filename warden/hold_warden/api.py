"""Hand-written ASGI app for the warden's agent-facing API (no framework).

The whole HTTP surface is four routes; staying a few hundred auditable lines is
the point (spec section 4). JSON in, JSON out; errors are {"detail": "<msg>"}.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time

import httpx

from hold_warden.arbiter import ArbiterAuthError, ArbiterUnavailable
from hold_warden.config import ParamValidationError, WardenConfig
from hold_warden.secrets import resolve
from hold_warden.service import Orchestrator, ProposeError

log = logging.getLogger("hold_warden.api")

HEALTH_PROBE_TTL_S = 60.0
EXECUTE_DEFAULT_TIMEOUT_S = 240.0
EXECUTE_POLL_INTERVAL_S = 0.5
TERMINAL_STATUSES = ("executed", "denied", "expired", "failed")


def _now_monotonic() -> float:
    """Module-level so tests can monkeypatch time (no sleeps in tests)."""
    return time.monotonic()


def _arbiter_reachable(base_url: str) -> bool:
    try:
        return httpx.get(f"{base_url.rstrip('/')}/health",
                         timeout=5.0).status_code == 200
    except httpx.HTTPError:
        return False


class WardenAPI:
    """ASGI 3 application. One instance per process; its only state is the
    resolved agent-token map and the cached arbiter health probe."""

    def __init__(self, orch: Orchestrator, cfg: WardenConfig):
        self.orch = orch
        self.cfg = cfg
        # Agent tokens are needed on every request and rotation requires a
        # restart anyway (no SIGHUP), so resolve the refs once at startup.
        self._agent_tokens = {name: resolve(ref)
                              for name, ref in cfg.agents.items()}
        self._health_checked_at: float | None = None
        self._health_ok = False

    # ------------------------------------------------------------ ASGI 3
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        body = await self._read_body(receive)
        status, payload = await self._dispatch(
            scope["method"], scope["path"], scope, body)
        await self._respond(send, status, payload)

    @staticmethod
    async def _lifespan(receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    @staticmethod
    async def _read_body(receive) -> bytes:
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        return b"".join(chunks)

    @staticmethod
    async def _respond(send, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(raw)).encode())]})
        await send({"type": "http.response.body", "body": raw})

    # ---------------------------------------------------------- routing
    async def _dispatch(self, method: str, path: str, scope, body: bytes):
        if method == "GET" and path == "/health":
            return self._health()
        agent = self._authenticate(scope)
        if agent is None:
            return 401, {"detail": "invalid or missing bearer token"}
        return 404, {"detail": "not found"}

    def _authenticate(self, scope) -> str | None:
        """Constant-time bearer compare against every [agents.*] token."""
        header = None
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                header = value.decode("latin-1")
                break
        if header is None or not header.startswith("Bearer "):
            return None
        presented = header[len("Bearer "):].encode()
        for name, expected in self._agent_tokens.items():
            if hmac.compare_digest(presented, expected.encode()):
                return name
        return None

    # ----------------------------------------------------------- health
    def _health(self):
        now = _now_monotonic()
        if (self._health_checked_at is None
                or now - self._health_checked_at > HEALTH_PROBE_TTL_S):
            self._health_ok = _arbiter_reachable(self.cfg.arbiter_url)
            self._health_checked_at = now
        return (200, {"ok": True}) if self._health_ok else (503, {"ok": False})


def create_asgi_app(orch: Orchestrator, cfg: WardenConfig) -> WardenAPI:
    return WardenAPI(orch, cfg)

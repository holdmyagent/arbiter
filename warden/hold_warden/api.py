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
        if method == "POST" and path == "/v1/propose":
            return self._propose(agent, body)
        if method == "GET" and path.startswith("/v1/proposals/"):
            return self._get_proposal(agent, path[len("/v1/proposals/"):])
        if method == "POST" and path == "/v1/execute":
            return await self._execute(agent, body)
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

    # ---------------------------------------------------------- propose
    @staticmethod
    def _parse(body: bytes) -> dict | None:
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _propose(self, agent: str, body: bytes):
        data = self._parse(body)
        if data is None:
            return 422, {"detail": "body must be a JSON object"}
        return self._propose_impl(agent, data)

    def _propose_impl(self, agent: str, data: dict):
        action = data.get("action")
        params = data.get("params", {})
        idem = data.get("idempotency_key")
        if not isinstance(action, str) or not action:
            return 422, {"detail": "'action' must be a non-empty string"}
        if not isinstance(params, dict) or not all(
                isinstance(k, str) and isinstance(v, str)
                for k, v in params.items()):
            return 422, {"detail": "'params' must be an object with string values"}
        if idem is not None and (not isinstance(idem, str)
                                 or not idem or len(idem) > 128):
            return 422, {"detail": "'idempotency_key' must be a string of 1-128 chars"}
        try:
            row = self.orch.propose(agent, action, params, idem)
        except ParamValidationError as exc:
            return 422, {"detail": str(exc)}
        except ProposeError as exc:
            return 404, {"detail": str(exc)}
        except ArbiterAuthError:
            return 502, {"detail": "arbiter rejected the warden token (see warden logs)"}
        except ArbiterUnavailable:
            return 502, {"detail": "arbiter unreachable"}
        return 201, {"proposal_id": row["id"], "request_id": row["request_id"],
                     "status": row["status"], "expires_at": row.get("expires_at")}

    # ------------------------------------------------------ get proposal
    def _get_proposal(self, agent: str, proposal_id: str):
        row = self.orch.db.get(proposal_id)
        if row is None or row["agent"] != agent:
            # 404 for foreign proposals too: no existence leak across agents.
            return 404, {"detail": "not found"}
        return 200, self._proposal_view(row)

    def _proposal_view(self, row: dict) -> dict:
        out = {"status": row["status"]}
        result = row.get("result")
        if isinstance(result, str):
            result = json.loads(result)
        if isinstance(result, dict) and "secret" in result:
            # secret adapter: single retrieval - returns the value, then NULLs it
            result = self.orch.db.take_secret_result(row["id"])
        if result is not None:
            out["result"] = result
        receipt = row.get("receipt")
        if isinstance(receipt, str):
            receipt = json.loads(receipt)
        if receipt is not None:
            out["receipt"] = receipt
        return out

    # ------------------------------------------------------------ execute
    async def _execute(self, agent: str, body: bytes):
        """Blocking convenience wrapper: propose, then long-poll the proposal
        until terminal or timeout (default 240s), then 202 so the caller can
        switch to GET /v1/proposals/{id} polling."""
        data = self._parse(body)
        if data is None:
            return 422, {"detail": "body must be a JSON object"}
        timeout_s = data.pop("timeout_s", EXECUTE_DEFAULT_TIMEOUT_S)
        if (not isinstance(timeout_s, (int, float))
                or isinstance(timeout_s, bool) or timeout_s < 0):
            return 422, {"detail": "'timeout_s' must be a non-negative number"}
        status, payload = self._propose_impl(agent, data)
        if status != 201:
            return status, payload
        pid = payload["proposal_id"]
        deadline = _now_monotonic() + float(timeout_s)
        while True:
            row = self.orch.db.get(pid)
            if row is not None and row["status"] in TERMINAL_STATUSES:
                view = self._proposal_view(row)
                view["proposal_id"] = pid
                return 200, view
            if _now_monotonic() >= deadline:
                return 202, {"proposal_id": pid}
            await asyncio.sleep(EXECUTE_POLL_INTERVAL_S)

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

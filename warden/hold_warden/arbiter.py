"""Warden -> arbiter HTTP client."""
from __future__ import annotations

import httpx


class ArbiterAuthError(Exception):
    """401/403 from the arbiter — warden token rejected/rotated. Proposal fails,
    service.py logs CRITICAL, the daemon stays up."""


class ArbiterUnavailable(Exception):
    """Network error, 5xx, or unexpected response — retryable, fail closed."""


class ArbiterConflict(Exception):
    """Consume returned 409 (not approved / already consumed). Never execute."""


class ArbiterStale(Exception):
    """Consume returned 410 (approval older than approval_ttl_seconds). Never execute."""


class ArbiterClient:
    def __init__(self, base_url: str, token: str, timeout_s: int = 10):
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout_s,
        )

    def create_request(self, *, title: str, description: str, action_type: str, severity: str,
                       ttl_seconds: int, payload: dict, canonical_action: str,
                       action_hash: str, idempotency_key: str) -> dict:
        resp = self._client.post("/v1/requests", json={
            "title": title,
            "description": description,
            "action_type": action_type,
            "severity": severity,
            "ttl_seconds": ttl_seconds,
            "payload": payload,
            "canonical_action": canonical_action,
            "action_hash": action_hash,
            "idempotency_key": idempotency_key,
        })
        return resp.json()

    def get_request(self, rid: str) -> dict:
        return self._client.get(f"/v1/requests/{rid}").json()

    def get_verdict(self, rid: str) -> str:
        return self._client.get(f"/v1/requests/{rid}/verdict").json()["verdict"]

    def consume(self, rid: str) -> None:
        self._client.post(f"/v1/requests/{rid}/consume")

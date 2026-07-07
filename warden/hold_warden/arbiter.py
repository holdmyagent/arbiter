"""Warden -> arbiter HTTP client.

Exception mapping (the orchestrator's fail-closed table keys off these):
- 401/403            -> ArbiterAuthError   (warden token revoked/rotated: proposal fails,
                                            CRITICAL log in service.py, daemon stays up)
- network error/5xx  -> ArbiterUnavailable (retryable: propose -> 502 no side effects;
                                            verdict poll -> keep polling until expires_at)
- consume 409        -> ArbiterConflict    (not approved / already consumed: never execute)
- consume 410        -> ArbiterStale       (approval older than approval_ttl: never execute)
- any other unexpected status (404 "no verdict yet", 422, non-JSON body, ...)
                     -> ArbiterUnavailable with the status + body text in the message.
"""
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

    def _request(self, method: str, path: str, json_body: dict | None = None) -> httpx.Response:
        try:
            resp = self._client.request(method, path, json=json_body)
        except httpx.HTTPError as exc:
            raise ArbiterUnavailable(f"arbiter unreachable: {exc}") from exc
        if resp.status_code in (401, 403):
            raise ArbiterAuthError(
                f"arbiter rejected warden token ({resp.status_code}): {resp.text}")
        if resp.status_code >= 500:
            raise ArbiterUnavailable(f"arbiter error {resp.status_code}: {resp.text}")
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> dict:
        try:
            return resp.json()
        except ValueError as exc:
            raise ArbiterUnavailable(
                f"arbiter returned non-JSON ({resp.status_code})") from exc

    def create_request(self, *, title: str, description: str, action_type: str, severity: str,
                       ttl_seconds: int, payload: dict, canonical_action: str,
                       action_hash: str, idempotency_key: str) -> dict:
        resp = self._request("POST", "/v1/requests", {
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
        if resp.status_code not in (200, 201):
            raise ArbiterUnavailable(f"create failed ({resp.status_code}): {resp.text}")
        return self._json(resp)

    def get_request(self, rid: str) -> dict:
        resp = self._request("GET", f"/v1/requests/{rid}")
        if resp.status_code != 200:
            raise ArbiterUnavailable(f"get_request failed ({resp.status_code}): {resp.text}")
        return self._json(resp)

    def get_verdict(self, rid: str) -> str:
        resp = self._request("GET", f"/v1/requests/{rid}/verdict")
        if resp.status_code != 200:
            # 404 = "no verdict yet" — retryable by contract (keep polling until expires_at).
            raise ArbiterUnavailable(f"no verdict ({resp.status_code}): {resp.text}")
        jws = self._json(resp).get("verdict")
        if not isinstance(jws, str) or not jws:
            raise ArbiterUnavailable(f"verdict response malformed: {resp.text}")
        return jws

    def consume(self, rid: str) -> None:
        resp = self._request("POST", f"/v1/requests/{rid}/consume")
        if resp.status_code == 409:
            raise ArbiterConflict(f"consume conflict: {resp.text}")
        if resp.status_code == 410:
            raise ArbiterStale(f"approval stale: {resp.text}")
        if resp.status_code != 200:
            raise ArbiterUnavailable(f"consume failed ({resp.status_code}): {resp.text}")

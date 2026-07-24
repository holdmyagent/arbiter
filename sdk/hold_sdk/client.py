import time
import warnings
import httpx

class ArbiterClient:
    def __init__(self, base_url, agent_token, verify=True):
        if verify is False:
            warnings.warn(
                "TLS verification disabled — vulnerable to MITM; "
                "add your CA to the trust store instead", stacklevel=2)
        self.base_url = base_url.rstrip("/")
        self.agent_token = agent_token
        self._http = httpx.Client(base_url=self.base_url, verify=verify, timeout=10)

    def request_approval(self, title, description="", action_type="generic",
                         payload=None, severity="medium", ttl=300, target=None,
                         poll_interval=2, timeout=None,
                         idempotency_key=None, callback_url=None) -> str:
        body = {"title": title, "description": description, "action_type": action_type,
                "payload": payload or {}, "severity": severity, "ttl_seconds": ttl,
                "target": target}
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        if callback_url is not None:
            body["callback_url"] = callback_url
        try:
            r = self._http.post("/v1/requests",
                headers={"Authorization": f"Bearer {self.agent_token}"},
                json=body)
            r.raise_for_status()
            rid = r.json()["id"]
        except Exception:
            return "denied"  # fail-closed
        deadline = time.time() + (timeout if timeout is not None else ttl + 5)
        while time.time() < deadline:
            try:
                g = self._http.get(f"/v1/requests/{rid}",
                    headers={"Authorization": f"Bearer {self.agent_token}"})
                g.raise_for_status()
                status = g.json()["status"]
            except Exception:
                status = None            # transient poll failure — keep waiting
            if status in ("approved", "denied", "expired"):
                return status
            time.sleep(poll_interval)
        # Deadline reached without a terminal status: one final read, so a
        # server-side expiry (or late decision) is reported truthfully.
        try:
            g = self._http.get(f"/v1/requests/{rid}",
                headers={"Authorization": f"Bearer {self.agent_token}"})
            g.raise_for_status()
            status = g.json()["status"]
            if status in ("approved", "denied", "expired"):
                return status
        except Exception:
            pass
        return "denied"  # fail-closed: outcome unknown at deadline

    # ── gate-facing policy (agent_token / policy:read-resolved) ──────────────
    # The gate-facing read surface only. The write/admin surface (presets,
    # overlay, active, test) needs the app-role decision credential and has no
    # Python consumer — it lives in the macOS app's ArbiterKit — so it is
    # deliberately not carried here. Unlike request_approval's fail-closed
    # polling loop, these raise on non-2xx (like a plain typed client) so the
    # gate's sync process can fall back to its OWN local most-restrictive.

    def get_resolved_policy(self) -> dict:
        """GET /v1/policy — the resolved policy the gate consumes.

        Raises on non-200 (httpx.HTTPStatusError) so the caller/gate can fall
        back to its own local most-restrictive rather than acting on a partial
        or missing policy."""
        r = self._http.get("/v1/policy",
            headers={"Authorization": f"Bearer {self.agent_token}"})
        r.raise_for_status()
        return r.json()

    def report_gate_status(self, version: int, etag: str, fetched_at: str,
                           most_restrictive: bool) -> dict:
        """POST /v1/policy/gate-status — report what the gate is enforcing
        (closed-loop telemetry). Returns the stored record (the reported fields
        plus a server-stamped ``reported_at``). Raises on non-200."""
        r = self._http.post("/v1/policy/gate-status",
            headers={"Authorization": f"Bearer {self.agent_token}"},
            json={"version": version, "etag": etag,
                  "fetched_at": fetched_at, "most_restrictive": most_restrictive})
        r.raise_for_status()
        return r.json()

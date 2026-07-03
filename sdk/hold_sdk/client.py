import time
import httpx

class ArbiterClient:
    def __init__(self, base_url, agent_token, app_token=None, verify=True):
        self.base_url = base_url.rstrip("/")
        self.agent_token = agent_token
        self._http = httpx.Client(base_url=self.base_url, verify=verify, timeout=10)

    def request_approval(self, title, description="", action_type="generic",
                         payload=None, severity="medium", ttl=300, target=None,
                         poll_interval=2, timeout=None) -> str:
        try:
            r = self._http.post("/v1/requests",
                headers={"Authorization": f"Bearer {self.agent_token}"},
                json={"title": title, "description": description, "action_type": action_type,
                      "payload": payload or {}, "severity": severity, "ttl_seconds": ttl, "target": target})
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
                return "denied"  # fail-closed
            if status in ("approved", "denied", "expired"):
                return status
            time.sleep(poll_interval)
        return "denied"  # fail-closed on local timeout

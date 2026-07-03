import os
import time
import httpx

def request_approval(title, *, description="", severity="medium", target=None,
                     ttl_seconds=300, payload=None, action_type="generic",
                     server_url=None, token=None, poll_interval=2, timeout=None,
                     _transport=None) -> str:
    server_url = server_url or os.environ.get("HMA_SERVER_URL")
    token = token or os.environ.get("HMA_AGENT_TOKEN")
    if not server_url or not token:
        return "denied"  # fail-closed: unconfigured is a no
    hdr = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(base_url=server_url.rstrip("/"), timeout=10, transport=_transport) as c:
            r = c.post("/v1/requests", headers=hdr, json={
                "title": title, "description": description, "action_type": action_type,
                "payload": payload or {}, "severity": severity,
                "ttl_seconds": ttl_seconds, "target": target})
            r.raise_for_status()
            rid = r.json()["id"]
            deadline = time.time() + (timeout if timeout is not None else ttl_seconds + 5)
            while time.time() < deadline:
                g = c.get(f"/v1/requests/{rid}", headers=hdr)
                g.raise_for_status()
                status = g.json()["status"]
                if status in ("approved", "denied", "expired"):
                    return status
                time.sleep(poll_interval)
    except Exception:
        return "denied"  # fail-closed
    return "denied"      # local timeout

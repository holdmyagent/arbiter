import asyncio
import hashlib
import hmac
import json
import logging
import httpx

log = logging.getLogger("arbiter.webhook")

def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

class WebhookNotifier:
    def __init__(self, cfg, transport=None, sleeps=(1.0, 5.0, 25.0)):
        self.cfg, self.transport, self.sleeps = cfg, transport, tuple(sleeps)

    async def deliver(self, url: str, event: str, req: dict) -> bool:
        body = json.dumps({"event": event, "request": req}).encode()
        headers = {"content-type": "application/json"}
        if self.cfg.secret:
            headers["X-HMA-Signature"] = sign(self.cfg.secret, body)
        attempts = len(self.sleeps) if self.sleeps else 1
        for i in range(attempts):
            try:
                async with httpx.AsyncClient(transport=self.transport, timeout=10) as c:
                    r = await c.post(url, headers=headers, content=body)
                if r.status_code < 300:
                    return True
                if r.status_code < 500:
                    return False          # hard client error: no retry
            except httpx.HTTPError as exc:
                log.warning("webhook attempt %d to %s failed: %s", i + 1, url, exc)
            if i + 1 < attempts:
                await asyncio.sleep(self.sleeps[i])
        return False

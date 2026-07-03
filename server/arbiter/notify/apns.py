import asyncio
import time
import json
import logging
import httpx
import jwt
log = logging.getLogger("arbiter.apns")
_LEVEL = {"low":"passive","medium":"active","high":"time-sensitive","critical":"critical"}

def build_payload(req: dict, sound: bool = True, badge: int | None = None) -> dict:
    aps: dict = {
        "alert": {"title": req["title"], "body": req.get("description","") or req.get("action_type","")},
        "interruption-level": _LEVEL.get(req["severity"], "active"),
    }
    if sound:
        aps["sound"] = "default"
    if badge is not None:
        aps["badge"] = badge
    return {
        "aps": aps,
        "request_id": req["id"],
        "severity": req["severity"],
    }

class APNsSender:
    def __init__(self, cfg):
        self.cfg = cfg
        self._jwt = None
        self._jwt_at = 0.0

    def _token(self) -> str:
        if self._jwt and time.time() - self._jwt_at < 3000:
            return self._jwt
        with open(self.cfg.apns.key_path) as f:
            key = f.read()
        self._jwt = jwt.encode({"iss": self.cfg.apns.team_id, "iat": int(time.time())},
                               key, algorithm="ES256", headers={"kid": self.cfg.apns.key_id})
        self._jwt_at = time.time()
        return self._jwt

    async def send(self, device_token: str, payload: dict) -> str:
        if not self.cfg.apns.configured:
            log.info("APNs not configured; skipping push for %s", payload.get("request_id"))
            return "skipped"
        host = "api.sandbox.push.apple.com" if self.cfg.apns.sandbox else "api.push.apple.com"
        headers = {"authorization": f"bearer {self._token()}",
                   "apns-topic": self.cfg.apns.bundle_id, "apns-push-type": "alert"}
        async with httpx.AsyncClient(http2=True) as client:
            r = await client.post(f"https://{host}/3/device/{device_token}",
                                  headers=headers, content=json.dumps(payload), timeout=10)
        return "sent" if r.status_code==200 else f"error:{r.status_code}:{r.text}"


def _classify(result: str) -> str:
    """Classify a sender result as ok | transient | hard.

    - Non-"error:" results ("sent", "skipped") are terminal successes → "ok".
    - "error:exception:…" (a raised send exception) and 5xx server errors are "transient".
    - 4xx client errors (e.g. 400 Bad Request, 410 Unregistered) are "hard" — never retried.
    """
    if not result.startswith("error:"):
        return "ok"
    parts = result.split(":", 2)
    code = parts[1] if len(parts) > 1 else ""
    if code == "exception":
        return "transient"
    if code.isdigit():
        n = int(code)
        if n == 429 or 500 <= n <= 599:  # 429 Too Many Requests is a back-off-and-retry signal
            return "transient"
    return "hard"


async def send_with_retry(sender, device_token: str, payload: dict,
                          *, max_retries: int = 2, backoff_base: float = 0.5) -> str:
    """Send a push with a bounded retry for TRANSIENT failures (5xx / raised exceptions).

    Hard rejections (4xx, e.g. 410 Unregistered) are returned immediately with no retry.
    Returns the final sender result string; total attempts are at most ``max_retries + 1``.
    """
    result = ""
    for attempt in range(max_retries + 1):
        try:
            result = await sender.send(device_token, payload)
        except Exception as exc:  # network timeout etc. — treat as transient
            result = f"error:exception:{exc}"
        if _classify(result) != "transient":
            return result
        if attempt < max_retries:
            await asyncio.sleep(backoff_base * (attempt + 1))
    log.warning("push to %s exhausted retries: %s", payload.get("request_id"), result)
    return result

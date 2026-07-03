import httpx

PRIORITY = {"low": "2", "medium": "3", "high": "4", "critical": "5"}

class NtfyNotifier:
    def __init__(self, cfg, transport=None):
        self.cfg, self.transport = cfg, transport

    async def send(self, req: dict) -> None:
        headers = {
            "title": f"[{req['severity'].upper()}] {req['title']}",
            "priority": PRIORITY.get(req["severity"], "3"),
            "click": f"holdmyagent://request/{req['id']}",
            "tags": "shield",
        }
        if self.cfg.token:
            headers["authorization"] = f"Bearer {self.cfg.token}"
        body = req.get("description") or req.get("target") or "Approval requested"
        async with httpx.AsyncClient(transport=self.transport, timeout=10) as c:
            r = await c.post(f"{self.cfg.url.rstrip('/')}/{self.cfg.topic}",
                             headers=headers, content=body.encode())
            r.raise_for_status()

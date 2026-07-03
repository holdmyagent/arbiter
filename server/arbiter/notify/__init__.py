import logging
from .apns import APNsSender, build_payload, send_with_retry
from .ntfy import NtfyNotifier
from .webhook import WebhookNotifier
from ..models import severity_rank

log = logging.getLogger("arbiter.notify")

class Dispatcher:
    def __init__(self, cfg, db, sender=None, transport=None):
        self.cfg, self.db = cfg, db
        self.sender = sender or APNsSender(cfg)
        self.ntfy = NtfyNotifier(cfg.ntfy, transport) if cfg.ntfy.enabled else None
        self.webhook = WebhookNotifier(cfg.webhook, transport)

    async def _guard(self, name: str, rid: str, coro):
        try:
            await coro
        except Exception as exc:
            log.warning("notifier %s failed for %s: %s", name, rid, exc)
            try:
                self.db.add_audit(rid, "notify_failed", {"notifier": name, "error": str(exc)[:200]})
            except Exception as audit_exc:
                log.warning("audit write for notify_failed failed: %s", audit_exc)

    async def request_created(self, req: dict) -> None:
        rank = severity_rank(req["severity"])
        for dev in self.db.list_devices():
            if dev["notifications_enabled"] and severity_rank(dev["min_severity"]) <= rank:
                payload = build_payload(req, sound=bool(dev["sound"]))
                await self._guard("apns", req["id"],
                                  send_with_retry(self.sender, dev["apns_token"], payload))
        if self.ntfy:
            await self._guard("ntfy", req["id"], self.ntfy.send(req))
        if self.cfg.webhook.enabled:
            await self._guard("webhook", req["id"],
                              self._deliver_checked(self.cfg.webhook.url, "request.created", req))

    async def request_decided(self, req: dict) -> None:
        event = "request.expired" if req["status"] == "expired" else "request.decided"
        if self.cfg.webhook.enabled:
            await self._guard("webhook", req["id"],
                              self._deliver_checked(self.cfg.webhook.url, event, req))
        if req.get("callback_url"):
            await self._guard("callback", req["id"],
                              self._deliver_checked(req["callback_url"], event, req))

    async def _deliver_checked(self, url: str, event: str, req: dict):
        if not await self.webhook.deliver(url, event, req):
            raise RuntimeError(f"delivery to {url} failed after retries")

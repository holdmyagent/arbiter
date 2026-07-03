import logging
from .apns import APNsSender, build_payload, send_with_retry
from .ntfy import NtfyNotifier
from .webhook import WebhookNotifier
from ..models import severity_rank

log = logging.getLogger("arbiter.notify")

def _wants(dev: dict, req: dict) -> bool:
    """Decide whether a device should receive a push for this request.

    A per-severity map beats the threshold: when ``severities`` is present the
    map's value for this request's severity governs (missing → no push). When
    the map is absent, fall back to the ``min_severity`` threshold. The
    ``notifications_enabled`` master switch gates both.
    """
    if not dev["notifications_enabled"]:
        return False
    severities = dev["severities"]
    if severities is not None:
        return bool(severities.get(req["severity"], False))
    return severity_rank(dev["min_severity"]) <= severity_rank(req["severity"])

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
        pending = None
        for dev in self.db.list_devices():
            if _wants(dev, req):
                badge = None
                if dev["badge"]:
                    if pending is None:
                        pending = len(self.db.list_requests("pending"))
                    badge = pending
                payload = build_payload(req, sound=bool(dev["sound"]), badge=badge)
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

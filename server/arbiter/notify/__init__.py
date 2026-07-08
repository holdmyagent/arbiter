import fnmatch
import ipaddress
import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .apns import APNsSender, build_payload, send_with_retry
from .ntfy import NtfyNotifier
from .webhook import WebhookNotifier
from ..config import WebhookCfg, NtfyCfg, SEVERITIES
from ..models import severity_rank

log = logging.getLogger("arbiter.notify")

@dataclass
class CellDelivery:
    """Per-cell egress config. Exposes exactly the attributes Dispatcher reads
    off its first arg (.webhook/.ntfy/.callback_allowlist/.notify_severities),
    so build_cell_dispatcher can hand it straight to the shipped Dispatcher."""
    webhook: WebhookCfg = field(default_factory=WebhookCfg)
    ntfy: NtfyCfg = field(default_factory=NtfyCfg)
    callback_allowlist: list[str] = field(default_factory=list)
    notify_severities: dict[str, bool] = field(
        default_factory=lambda: {s: True for s in SEVERITIES})

    @classmethod
    def from_process(cls, cfg) -> "CellDelivery":
        return cls(webhook=cfg.webhook, ntfy=cfg.ntfy,
                   callback_allowlist=list(cfg.callback_allowlist),
                   notify_severities=dict(cfg.notify_severities))

def cell_delivery(process_cfg, tenant_id: str, cell_dir) -> "CellDelivery":
    """default cell inherits the process delivery config (back-compat, §14);
    every other tenant reads ONLY <cell_dir>/notify.toml — the process cfg's
    sinks NEVER leak into another tenant (§9). Absent file = no egress."""
    if tenant_id == "default":
        return CellDelivery.from_process(process_cfg)
    d = CellDelivery()
    p = Path(cell_dir) / "notify.toml"
    if p.is_file():
        doc = tomllib.loads(p.read_text())
        wh = doc.get("webhook", {})
        if "url" in wh: d.webhook.url = str(wh["url"])
        if "secret" in wh: d.webhook.secret = str(wh["secret"])
        nt = doc.get("ntfy", {})
        for k in ("url", "topic", "token"):
            if k in nt: setattr(d.ntfy, k, str(nt[k]))
        n = doc.get("notify", {})
        if "callback_allowlist" in n:
            d.callback_allowlist = [str(x) for x in n["callback_allowlist"]]
        for k, v in n.get("severities", {}).items():
            if k in d.notify_severities and isinstance(v, bool):
                d.notify_severities[k] = v
    return d

def build_cell_dispatcher(delivery: "CellDelivery", db, sender, transport=None) -> "Dispatcher":
    """The cell's own Dispatcher: shipped Dispatcher fed the per-cell delivery
    config + the shared APNs sender + the cell db. sender is ALWAYS passed so
    Dispatcher never falls back to APNsSender(delivery)."""
    return Dispatcher(delivery, db, sender=sender, transport=transport)

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

def _split_pattern_entry(entry: str) -> tuple[str, str, str]:
    """Split a "scheme://host[:port][/path]" allowlist entry.

    Returns (scheme.lower(), authority, path_glob). authority is the literal
    "host" or "host:port" text between "://" and the first "/"; path_glob is
    everything from that "/" onward, defaulting to "/*" when the entry has
    no path segment.
    """
    scheme, _, rest = entry.partition("://")
    slash = rest.find("/")
    if slash == -1:
        authority, path_glob = rest, "/*"
    else:
        authority, path_glob = rest[:slash], rest[slash:]
    return scheme.lower(), authority, path_glob


def _authority_matches(entry_authority: str, host: str, port: int | None) -> bool:
    """Match a candidate's PARSED hostname/port against a literal authority.

    A leading "*." on the entry's host matches one-or-more subdomain labels
    (so "*.hooks.example.com" matches "a.hooks.example.com" and
    "deep.a.hooks.example.com") but never the bare parent domain itself and
    never a mere string suffix like "hooks.example.com.evil.com". Every
    other host is compared as an exact literal. Because ``host`` comes from
    ``urlparse().hostname`` it can never contain a "/", which is what
    prevents a path from ever being mistaken for (part of) the host.
    """
    entry_host, sep, entry_port_s = entry_authority.rpartition(":")
    if sep and entry_port_s.isdigit():
        if port is None or int(entry_port_s) != port:
            return False
    else:
        entry_host = entry_authority
    if not host:
        return False
    host, entry_host = host.lower(), entry_host.lower()
    if entry_host.startswith("*."):
        suffix = entry_host[1:]  # keep the leading "."
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == entry_host


def callback_allowed(allowlist: list[str], url: str) -> bool:
    """Check a callback_url against [notify] callback_allowlist.

    Empty allowlist = legacy allow-all (the dispatcher logs a one-time warning).

    Entries containing "://" are scheme+host+path patterns
    ("https://hooks.example.com/*"). Scheme and host are matched as LITERAL
    values against the URL's *parsed* scheme/hostname — never against the
    raw URL string — except a host beginning "*." matches any non-empty
    subdomain of the rest (see ``_authority_matches``). Only the path
    component is fnmatch-glob ("/*" by default). Matching parsed components
    instead of the raw string is what stops "*" in a host-wildcard rule from
    ever crossing a "/" onto a path segment, and stops URL userinfo
    ("user@host") from being mistaken for the host.

    Entries NOT containing "://" are CIDRs matched against IP-literal hosts
    ONLY — hostnames are never DNS-resolved, so a CIDR entry cannot be
    bypassed via DNS.
    """
    if not allowlist:
        return True
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return False
    for entry in allowlist:
        if "://" in entry:
            entry_scheme, entry_authority, path_glob = _split_pattern_entry(entry)
            if parsed.scheme.lower() != entry_scheme:
                continue
            if not _authority_matches(entry_authority, host, port):
                continue
            if fnmatch.fnmatch(parsed.path or "/", path_glob):
                return True
        else:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if host and ipaddress.ip_address(host) in net:
                    return True
            except ValueError:
                continue
    return False

class Dispatcher:
    def __init__(self, cfg, db, sender=None, transport=None):
        self.cfg, self.db = cfg, db
        self.sender = sender or APNsSender(cfg)
        self.ntfy = NtfyNotifier(cfg.ntfy, transport) if cfg.ntfy.enabled else None
        self.webhook = WebhookNotifier(cfg.webhook, transport)
        self._warned_open_callbacks = False

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
        # Server-wide severity policy gates pushes to paired devices; each
        # device's own opt-in still applies below (both must allow it).
        if self.cfg.notify_severities.get(req["severity"], True):
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
            if not callback_allowed(self.cfg.callback_allowlist, req["callback_url"]):
                log.warning("callback_url %s blocked by allowlist for %s",
                            req["callback_url"], req["id"])
                try:
                    self.db.add_audit(req["id"], "notify_failed",
                                      {"notifier": "callback",
                                       "error": "callback_url not in allowlist"})
                except Exception as audit_exc:
                    log.warning("audit write for blocked callback failed: %s", audit_exc)
                return
            if not self.cfg.callback_allowlist and not self._warned_open_callbacks:
                self._warned_open_callbacks = True
                log.warning("callback_url in use with no [notify] callback_allowlist "
                            "configured — all destinations allowed (legacy); set "
                            "callback_allowlist to restrict")
            await self._guard("callback", req["id"],
                              self._deliver_checked(req["callback_url"], event, req))

    async def _deliver_checked(self, url: str, event: str, req: dict):
        if not await self.webhook.deliver(url, event, req):
            raise RuntimeError(f"delivery to {url} failed after retries")

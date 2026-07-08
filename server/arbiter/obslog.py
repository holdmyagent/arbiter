"""Per-tenant scoped operational logging (§11).

Shared sinks are cross-tenant channels, so tenant operational events go to a
per-tenant logger (`arbiter.tenant.<tenant_id>`) and NEVER carry request PII or
schema internals. scoped_log drops any field on PII_KEYS before formatting, so a
caller cannot accidentally log a title/description/payload/dir/DB error text.
"""
import logging

# Field names that may carry tenant PII, request payload, filesystem layout, or
# schema internals — never logged.
PII_KEYS = frozenset({
    "title", "description", "payload", "body", "dir", "path",
    "error", "detail", "canonical_action", "apns_token", "callback_url",
})


def tenant_logger(tenant_id: str) -> logging.Logger:
    return logging.getLogger(f"arbiter.tenant.{tenant_id}")


def scoped_log(tenant_id: str, event: str, level: int = logging.INFO, **fields) -> None:
    safe = {k: v for k, v in fields.items() if k not in PII_KEYS}
    extras = " ".join(f"{k}={v}" for k, v in sorted(safe.items()))
    msg = f"{event} {extras}".rstrip()
    tenant_logger(tenant_id).log(level, msg)

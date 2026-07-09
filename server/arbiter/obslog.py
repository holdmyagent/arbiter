"""Per-tenant scoped operational logging (§11).

Shared sinks are cross-tenant channels, so tenant operational events go to a
per-tenant logger (`arbiter.tenant.<tenant_id>`) and NEVER carry request PII or
schema internals. scoped_log is ALLOWLIST-based: only field names on SAFE_KEYS
are ever emitted, and any allowlisted value that is itself a structured
container (dict/list/tuple — where PII likes to hide) is redacted rather than
stringified. Everything else — unlisted keys, unknown future fields, nested
payloads — is dropped by default. This is a §11-critical control: prefer
silently dropping a field over silently leaking one.
"""
import logging

# The ONLY field names scoped_log will ever emit. Fixed, known-safe,
# non-PII operational metadata — nothing else. Adding a new field here is a
# deliberate, reviewed decision, not something a caller can opt into by
# passing a new kwarg.
SAFE_KEYS = frozenset({
    "request_id", "event", "count", "status", "severity", "role",
    "epoch", "attempt", "outcome", "reason_code", "duration_ms", "code",
})

# Structured values can smuggle PII inside an otherwise-safe key
# (e.g. extra={"title": "Wire $50k"}). Never stringify these — redact.
_STRUCTURED_TYPES = (dict, list, tuple)
_REDACTED = "<redacted:structured>"


def tenant_logger(tenant_id: str) -> logging.Logger:
    return logging.getLogger(f"arbiter.tenant.{tenant_id}")


def scoped_log(tenant_id: str, event: str, level: int = logging.INFO, **fields) -> None:
    """Log an operational event to the tenant-scoped logger.

    `event` is interpolated directly into the log message and is NOT run
    through SAFE_KEYS filtering — it is a positional label, not a field.
    Callers MUST pass a static/pre-formatted operational label (e.g.
    "device_registered") and must NEVER interpolate tenant data (titles,
    descriptions, error text, IDs from request bodies, etc.) into it.

    Every keyword field is checked against SAFE_KEYS (by
    ``k.strip().lower()``, so case/whitespace variants can't bypass the
    filter) and dropped if not present. Allowlisted fields whose value is a
    dict/list/tuple are redacted rather than emitted, since a structured
    value under a safe-looking key can still carry PII.
    """
    safe = {}
    for k, v in fields.items():
        if k.strip().lower() not in SAFE_KEYS:
            continue
        if isinstance(v, _STRUCTURED_TYPES):
            v = _REDACTED
        safe[k] = v
    extras = " ".join(f"{k}={v}" for k, v in sorted(safe.items()))
    msg = f"{event} {extras}".rstrip()
    tenant_logger(tenant_id).log(level, msg)

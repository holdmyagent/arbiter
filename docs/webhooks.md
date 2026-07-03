# Webhooks

Point Arbiter at any HTTP endpoint and it'll POST a signed JSON payload
whenever a request is created or decided — wire it into Slack, PagerDuty,
your own notifier, or a second copy of an approval queue.

## Enable it

```toml
[notify.webhook]
url = "https://example.com/hooks/arbiter"
secret = "a-long-random-string"   # optional but strongly recommended — see below
```

or via environment variables:

```bash
export HMA_WEBHOOK_URL="https://example.com/hooks/arbiter"
export HMA_WEBHOOK_SECRET="a-long-random-string"
```

A non-empty `url` is what turns webhooks on (`hma status` shows
`webhook=on`/`off`). Every event below fires while it's set.

## Events and payload shape

```json
{
  "event": "request.created",
  "request": {
    "id": "b3f8c1a2-...",
    "created_at": "2026-07-03T18:04:11.203Z",
    "title": "Drop the production table?",
    "description": "DROP TABLE events;",
    "action_type": "generic",
    "payload": {},
    "severity": "critical",
    "status": "pending",
    "ttl_seconds": 300,
    "expires_at": "2026-07-03T18:09:11.203Z",
    "decided_at": null,
    "decided_by": null,
    "target": "prod-db",
    "callback_url": null
  }
}
```

`event` is one of:

- `request.created` — a new request was created (`status` is `pending`).
- `request.decided` — a human approved or denied it (`status` is
  `approved` or `denied`, `decided_at`/`decided_by` are set).
- `request.expired` — its TTL ran out before anyone decided
  (`status` is `expired`).

Delivery target: the global `[notify.webhook] url` above receives all
three event types. If an individual request also set a `callback_url`
when it was created (the `hold_sdk`/API `callback_url` field), that URL
additionally receives `request.decided`/`request.expired` — but not
`request.created` — for that one request. Both deliveries use the same
`[notify.webhook] secret` for signing.

## Verifying the signature

If `secret` is set, every delivery carries an `X-HMA-Signature` header:
`sha256=<hex-encoded HMAC-SHA256 of the raw request body, keyed by secret>`.
Verify it against the **raw bytes** of the body — not a re-serialized
version of the parsed JSON, which can differ in whitespace/key order and
will not match.

```python
import hashlib
import hmac

def verify_signature(secret: str, body: bytes, header_value: str | None) -> bool:
    if not header_value:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value)
```

A minimal receiver (Flask-style, but the logic is framework-agnostic —
grab the raw body before any JSON parsing):

```python
from flask import Flask, request, abort

app = Flask(__name__)
WEBHOOK_SECRET = "a-long-random-string"   # match [notify.webhook].secret

@app.post("/hooks/arbiter")
def arbiter_webhook():
    body = request.get_data()  # raw bytes, before Flask parses JSON
    if not verify_signature(WEBHOOK_SECRET, body, request.headers.get("X-HMA-Signature")):
        abort(401)
    payload = request.get_json()
    event, req = payload["event"], payload["request"]
    if event == "request.decided" and req["status"] == "approved":
        ...  # do something
    return "", 204
```

## Retries and failure handling

Arbiter retries a delivery up to 3 times with backoff (roughly 1s, then
5s between attempts) when your endpoint times out or returns a `5xx`. A
`4xx` response is treated as a hard failure and is **not** retried — fix
whatever the `4xx` indicates (usually a bad signature check on your end,
or a URL that's since moved) rather than expecting Arbiter to keep
banging on it.

If every attempt fails, Arbiter doesn't raise or crash the request
lifecycle — it logs a warning and records a `notify_failed` entry in the
audit log (`/dashboard/audit`, and `GET /v1/requests/{id}` doesn't
reflect webhook delivery status at all, since a request's own status is
independent of whether anyone got told about it). Design your receiver to
be idempotent on `(event, request.id)` — a retry that lands after your
handler already processed the first attempt's timeout should be a no-op.

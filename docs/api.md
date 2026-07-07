# Arbiter REST API reference (`/v1`)

Everything the server speaks over HTTP, in one place. Base URL is wherever you
run the server (default `http://127.0.0.1:8000`). All request and response
bodies are JSON unless noted; errors are always `{"detail": "<message>"}` with
a meaningful status code.

Compatibility contract: `/v1` changes are **additive**. The request `status`
enum is unchanged since 0.2.0 (`pending | approved | denied | expired`) —
post-approval consumption is expressed by the `consumed_at` field, not a new
status. Clients must ignore unknown fields.

## Authentication and roles

Send `Authorization: Bearer <token>` on every `/v1` route except `GET /health`
and `GET /v1/keys`.

Two credential systems are accepted:

1. **Per-identity DB tokens** (0.4.0+, recommended). Minted with
   `hma token create NAME --role agent|warden|app` (printed once, format
   `hma_<role>_<48 hex chars>`, stored as a SHA-256 hash). Tokens can carry
   scopes (`--action-types`, `--max-severity`), an expiry (`--expires-days`),
   and can be revoked (`hma token revoke NAME`). Requests created by a DB
   token are stamped `requested_by = <token name>`.
2. **Legacy static tokens** (deprecated but working): `[auth] agent_token` and
   `app_token` from `config.toml`. `hma serve` logs a deprecation warning when
   a legacy token is used. The legacy agent token sees legacy-created requests
   (`requested_by` null) plus its own; per-identity tokens are strictly scoped.

| Role | Capabilities |
|---|---|
| `agent` | Create requests; read **own** requests (`requested_by` == token name, 404 otherwise); read own verdicts. |
| `warden` | Everything `agent` can, plus: send `canonical_action`/`action_hash` at create, and `POST .../consume` an approval (single-use, **any** warden identity — not scoped to the request's creator). |
| `app` | List all requests, decide, register/list devices, read notify policy, `/v1/stream`, audit export. Held by the paired iOS app. |
| admin session | Dashboard (view-only) + `GET /v1/audit/export`. Cookie minted at `/dashboard/login`. |

Rate limits: repeated **auth failures** are throttled per client IP (429).
Separately, each authenticated identity is limited to
`[policy] rate_limit_per_minute` request creations per minute (default 30) —
exceeding it returns 429 with `{"detail": "rate limited"}`.

## Health and keys

### `GET /health` — no auth

Real readiness: the server runs `SELECT 1` against SQLite.

- `200 {"ok": true, "db": true}`
- `503 {"ok": false, "db": false}` when the DB ping fails.

### `GET /v1/keys` — no auth

The Ed25519 verdict-verification public key set, JWKS-shaped. Pin the
`kid`/`x` pair in the warden at `hma-warden init` time.

```json
{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "1a2b3c4d", "x": "<base64url raw public key>"}]}
```

## Requests

### `POST /v1/requests` — roles: `agent`, `warden`

Create an approval request. Body fields:

| Field | Type / default | Notes |
|---|---|---|
| `title` | string, required | Short summary shown on the phone/dashboard. |
| `description` | string, `""` | Longer detail; push notification body. |
| `action_type` | string, `"generic"` | Policy key: `[policy.severity_floors]` and `deny_action_types` match on it. |
| `payload` | object, `{}` | Free-form context, rendered on the detail page. |
| `severity` | `low\|medium\|high\|critical`, `medium` | Floor-raised server-side per `[policy.severity_floors]`; capped by the token's `max_severity` scope (403 if exceeded). |
| `ttl_seconds` | int, `300` | **Clamped** server-side into `[policy] ttl_min_seconds..ttl_max_seconds` (default 30..86400) — out-of-range values are adjusted, not rejected. |
| `target` | string or null | What is being acted on (host, table, PR). |
| `callback_url` | string or null | Server POSTs the decision/expiry event here. Checked against `[notify] callback_allowlist` — 422 if not allowed. |
| `canonical_action` | string or null | Warden tier: the exact canonical action document (opaque bytes to the server). |
| `action_hash` | string or null | Warden tier: hex SHA-256 of `canonical_action`. The server recomputes the hash over the received bytes and returns 422 on mismatch. Requests without it get `action_hash: null` — a verifiably **unbound** verdict. |
| `idempotency_key` | string or null, max 128 | Unique per identity. Retrying a create with the same key returns the **existing** request (200), not a duplicate. |

Responses:

- `200` — full request object (fresh create, idempotent replay, or
  duplicate-collapse: an identical `(requested_by, action_hash)` — or title,
  for unbound requests — already `pending` returns the existing row).
- `403 {"detail": "policy: <reason>"}` — `deny_action_types` match or token
  scope violation (`action_types` allowlist / `max_severity` cap).
- `422` — validation failure, canonical-hash mismatch, or `callback_url`
  rejected by the allowlist.
- `429` — per-identity create rate limit.

Example:

```bash
curl -X POST localhost:8000/v1/requests \
  -H "Authorization: Bearer $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"title": "Restart nginx on hermes", "action_type": "restart_service",
       "severity": "high", "ttl_seconds": 300, "target": "hermes",
       "idempotency_key": "restart-nginx-2026-07-07T01"}'
```

```json
{
  "id": "6f0c9a2e-…", "created_at": "2026-07-07T01:02:03.456789+00:00",
  "title": "Restart nginx on hermes", "description": "",
  "action_type": "restart_service", "payload": {},
  "severity": "high", "status": "pending",
  "ttl_seconds": 300, "expires_at": "2026-07-07T01:07:03.456789+00:00",
  "decided_at": null, "decided_by": null,
  "target": "hermes", "callback_url": null,
  "action_hash": null, "requested_by": "knossos-agent",
  "consumed_at": null, "idempotency_key": "restart-nginx-2026-07-07T01"
}
```

### `GET /v1/requests?status=<s>` — role: `app`

List requests, newest first; optional `status` filter
(`pending|approved|denied|expired`). Returns an array of request objects.

### `GET /v1/requests/{id}` — roles: `agent`, `warden`, `app`

Fetch one request — the agent's decision-polling channel. **Scoped reads:**
a DB-token `agent`/`warden` sees only requests where `requested_by` equals its
own token name (404 otherwise); the `app` role sees everything; the legacy
agent token sees legacy-created requests plus its own (deprecated behavior).

- `200` request object | `404 {"detail": "not found"}`.

### `POST /v1/requests/{id}/decision` — role: `app`

Body: `{"decision": "approve"}` or `{"decision": "deny"}`.

The write is atomic (`… WHERE id=? AND status='pending'` + rowcount check):
exactly one decision ever wins, concurrent approve/deny cannot both land, and
a decision on a request whose `expires_at` has already passed is refused. On
success the server signs and stores the verdict JWS (see below) and fires the
webhook/callback path.

- `200` updated request object
- `404 {"detail": "not found"}`
- `409 {"detail": "not pending (status=…)"}` — already decided, expired, or
  lost the race.

### `GET /v1/requests/{id}/verdict` — roles: `agent`, `warden`, `app`

The cryptographic decision artifact. Available once the request is decided or
expired (expiry also signs a verdict).

- `200 {"verdict": "<compact JWS>", "kid": "1a2b3c4d"}`
- `404 {"detail": "no verdict yet"}` while pending.

The verdict is a JWT signed with EdDSA (Ed25519), `kid` in the JOSE header,
and this payload:

```json
{
  "iss": "hma", "aud": "hma-verdict",
  "jti": "<request_id>", "iat": 1780000000,
  "hma": {
    "request_id": "<request_id>",
    "action_hash": "<hex sha256 or null>",
    "decision": "approved",
    "decided_at": "2026-07-07T01:03:04.…+00:00",
    "approval_ttl_seconds": 600
  }
}
```

Verify against `GET /v1/keys` (or your pinned copy). `action_hash: null`
means the request was created without a canonical action — the verdict proves
a human decision happened but is **not bound to action bytes**.

### `POST /v1/requests/{id}/consume` — role: `warden` only

Atomically marks an approval as used (single-use enforcement):
`UPDATE … SET consumed_at=? WHERE id=? AND status='approved' AND consumed_at IS NULL`.
Any identity with the `warden` role may consume any approved request — consume
is **not** scoped to the warden that created it (unlike the scoped reads on
`GET /v1/requests/{id}` above).

- `200 {"consumed_at": "2026-07-07T01:03:05.…+00:00"}`
- `409` — not approved, or already consumed (replay).
- `410` — stale: `decided_at + approval_ttl_seconds` (config, default 600) has
  passed; the sweeper flips such approvals to `expired`.

## Audit

### `GET /v1/audit/export?format=jsonl` — role: `app` or admin session

Streams the full audit table as `text/plain` JSON Lines — one event object
per line: `{"id", "request_id", "event", "at", "detail"}`. Events include
`created`, `approved`, `denied`, `expired`, `consumed`, `verdict_issued`,
`policy_denied`, `rate_limited`, `notify_failed`, `token_rotated`,
`notify_policy_changed`. Same data as `hma audit export`. Auth failures on
this route are throttled by the same per-IP limiter as every other route
(429 on repeated bad bearer tokens or missing session).

## Devices and notifications

### `POST /v1/devices` — role: `app`

Register/refresh a paired device (upsert by `apns_token`). Body:
`{"apns_token", "name", "min_severity", "notifications_enabled", "sound",
"severities": {"low": false, …} | null, "badge"}`. Returns the device object.

### `GET /v1/devices` — role: `app`

List registered devices.

### `GET /v1/notify/policy` — role: `app`

The server-wide per-severity push policy (see `[notify.severities]` in
[`config.md`](config.md)): `{"low": true, "medium": true, "high": true,
"critical": true}`. A push is sent only when the server-wide policy AND the
device's own opt-in both allow that severity.

## Live events

### `WebSocket /v1/stream` — legacy `[auth] app_token` (Bearer header) or dashboard session cookie

Pushes `{"event": "<name>", "request"|"device"|"data": <payload>}` messages:
`request.created`, `request.decided`, `request.expired`, `device.updated`,
`ping` (heartbeat). No replay or resume — reconcile via `GET /v1/requests`
after a reconnect. Bad credentials close with code 4401.

**Note:** unlike every other `/v1` route, the stream currently checks the
Bearer value directly against `[auth] app_token` — it does not resolve
per-identity DB tokens. A `hma token create NAME --role app` token will not
open this connection; use the legacy static `app_token` (or the dashboard
session cookie) until DB-token support lands here.

## Status code summary

| Code | Meaning here |
|---|---|
| 200 | Success (create also returns 200 — including idempotent replay and duplicate-collapse). |
| 401 | Missing or malformed `Authorization` header. |
| 403 | Invalid/revoked/expired token, wrong role, or policy deny (`policy: <reason>`, incl. token scope violations). |
| 404 | Not found — including another identity's request (scoped reads) and "no verdict yet". |
| 409 | Decision/consume conflict: not pending, already decided, already consumed, lost a race. |
| 410 | Stale approval at consume time (past `approval_ttl_seconds`). |
| 422 | Validation, canonical-hash mismatch, callback_url not allowlisted. |
| 429 | Auth-failure throttling (per IP) or create rate limit (per identity). |
| 503 | `/health` with a failing DB ping. |

See also: [`config.md`](config.md) for every knob referenced above,
[`cli.md`](cli.md) for the `hma` / `hma-warden` commands, and
[`warden.md`](warden.md) for the warden's own (separate) agent-facing API.

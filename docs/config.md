# `config.toml` reference (arbiter server)

The server reads one TOML file — default `~/.config/holdmyagent/config.toml`,
overridable with the `HMA_CONFIG` environment variable or `--config` on most
`hma` subcommands. `hma init` writes it with fresh random credentials and mode
`0600`; treat it as sensitive (it holds every static token). Every setting
below can also be overridden by an `HMA_*` environment variable (last column).

A complete annotated file:

```toml
[server]
host = "127.0.0.1"        # bind address; "0.0.0.0" (or `hma serve --lan`) for phones on the LAN
port = 8000
db_path = "~/.local/share/holdmyagent/arbiter.sqlite3"

[auth]                     # legacy static tokens — deprecated in favor of `hma token` (0.4.0)
agent_token = "…"          # agents create requests
app_token = "…"            # the paired phone app lists/decides
admin_password = "…"       # dashboard login
session_secret = "…"       # signs the dashboard session cookie

[policy]                   # create-time policy layer (0.4.0)
ttl_min_seconds = 30       # ttl_seconds clamp floor
ttl_max_seconds = 86400    # ttl_seconds clamp ceiling
approval_ttl_seconds = 600 # approval freshness: consume refuses (410) older approvals;
                           # the sweeper flips stale unconsumed approvals to expired
rate_limit_per_minute = 30 # per-identity request-creation limit (429 beyond it)
deny_action_types = []     # e.g. ["db.drop"] — auto-deny at create (403 "policy: …")

[policy.severity_floors]   # per-action_type minimum severity;
                           # effective severity = max(agent-claimed, floor)
# "deploy" = "high"
# "db.migrate" = "critical"

[notify]
callback_allowlist = []    # allowed callback_url destinations: CIDRs and/or URL prefixes,
                           # e.g. ["10.0.0.0/8", "https://hooks.internal/*"].
                           # [] (unset) = legacy allow-all, with a loud one-time startup
                           # warning the first time a callback_url is used.

[notify.severities]        # server-wide push policy (default: all true).
                           # A push needs BOTH this AND the device's own opt-in.
                           # Editable live from the dashboard (Settings -> Alert severities);
                           # readable by apps at GET /v1/notify/policy.
low = true
medium = true
high = true
critical = true

[notify.apns]              # optional — bring your own Apple Developer key (docs/apns.md)
key_path = ""              # path to the .p8 key
key_id = ""
team_id = ""
bundle_id = "com.holdmyagent.HoldMyAgent"
sandbox = false            # true for development builds

[notify.ntfy]              # optional — topic push, no Apple account (docs/ntfy.md)
url = "https://ntfy.sh"    # or your self-hosted ntfy
topic = ""                 # unguessable random string
token = ""                 # ntfy access token, if your server needs one

[notify.webhook]           # optional — generic integration (docs/webhooks.md)
url = ""                   # POSTed on created/decided/expired
secret = ""                # HMAC-SHA256 signing key for X-HMA-Signature
                           # (also signs per-request callback_url deliveries)
```

## Section notes

### `[server]`

`db_path` is expanded (`~` allowed) and its parent directory is created on
startup. The SQLite schema migrates itself forward via `PRAGMA user_version` —
upgrading in place needs no manual steps.

### `[auth]` — legacy static tokens (deprecated)

Still fully supported, but 0.4.0's per-identity tokens
(`hma token create NAME --role agent|warden|app`) are the recommended way to
credential every agent and warden: hashed at rest, scoped, expirable,
revocable one-by-one, and requests are attributed to the token name
(`requested_by`). `hma serve` logs a deprecation warning whenever a legacy
token authenticates. `hma serve` refuses to start on empty or default-dev
tokens, and requires `agent_token != app_token`.

### `[policy]`

Enforced at request creation, in this order: identity resolution ->
`deny_action_types` (403) -> severity floor raise -> token scope check
(allowed `action_types`, `max_severity` cap -> 403) -> rate limit (429) ->
TTL clamp -> idempotency replay / duplicate-collapse (200 with the existing
row). `approval_ttl_seconds` bounds how long an approval stays consumable —
the single-use consume returns 410 past it.

### `[notify]` and `callback_allowlist`

`callback_url` lets an agent point a decision webhook at an arbitrary URL —
which makes the server an outbound-request capability from its network
position. `callback_allowlist` closes that: entries are IP networks in CIDR
form or `scheme://…` URL patterns (glob-style, e.g. ending in `*`). A CIDR
entry matches only when the URL's host is a **literal IP address** — the
server never DNS-resolves hostnames, so a CIDR entry cannot be satisfied (or
bypassed) via DNS, and a bare-hostname entry matches nothing (fail-closed).
Checked at create time (422) and re-checked at dispatch; redirects on
callback POSTs are disabled. Leaving it empty preserves the old allow-all
behavior but logs a loud startup warning the first time a callback fires.

### `[notify.severities]`

Server-wide push gate introduced in 0.3.0 (previously documented only in the
changelog). Gates APNs pushes to paired devices by request severity before
each device's own preferences are consulted. Does not affect ntfy/webhook
delivery.

## Environment variable overrides

| Variable | Overrides |
|---|---|
| `HMA_CONFIG` | Which config file to load. |
| `HMA_HOST`, `HMA_PORT`, `HMA_DB_PATH` | `[server]` host / port / db_path. |
| `HMA_AGENT_TOKEN`, `HMA_APP_TOKEN` | `[auth]` legacy tokens. |
| `HMA_ADMIN_PASSWORD`, `HMA_SESSION_SECRET` | `[auth]` dashboard credentials. |
| `HMA_APNS_KEY_PATH`, `HMA_APNS_KEY_ID`, `HMA_APNS_TEAM_ID`, `HMA_APNS_BUNDLE_ID`, `HMA_APNS_SANDBOX` | `[notify.apns]`. |
| `HMA_NTFY_URL`, `HMA_NTFY_TOPIC`, `HMA_NTFY_TOKEN` | `[notify.ntfy]`. |
| `HMA_WEBHOOK_URL`, `HMA_WEBHOOK_SECRET` | `[notify.webhook]`. |
| `HMA_URL` | Client-side only: where `hma ask` / `hma status` reach the server (see [`cli.md`](cli.md)). |

The verdict signing key is **not** in this file: it is an Ed25519 private key
at `verdict_signing_key.pem` (mode 0600) in the config directory, created at
init/first-serve. Its public half is served at `GET /v1/keys`.

The warden has its own separate config (`warden.toml`) — see
[`warden.md`](warden.md) and [`cli.md`](cli.md).

# Changelog

## Unreleased

## [0.3.0] - 2026-07-06

### Added

- **Server-wide per-severity push policy.** `[notify.severities]` in config.toml
  (default: all enabled) gates which severities push to paired devices at all;
  each device's own opt-ins still apply — a push needs both. Editable live from
  the dashboard's Settings page; readable by paired apps via `GET /v1/notify/policy`.
- **Operator console dashboard.** The web dashboard was redesigned into an
  operator-console language across every page, in dark and a designed light
  theme: approval cards, ledger views with column headers and severity pills,
  a device-aware audit "Decided via" column, an always-scannable pairing QR,
  copyable tokens/commands, and theme + typeface toggles.

### Fixed

- Ledger severity pills no longer overlap the action column; audit rows expose
  event detail as a tooltip; live refresh keeps the header counts current;
  the server version is shown only after login; multi-word audit status verbs
  are abbreviated to fit the ledger column.

## [0.2.1] - 2026-07-03

### Added

- **Per-severity notification preferences.** A device can now register a
  `severities` map (`low`/`medium`/`high`/`critical` → on/off) that decides
  push delivery per severity. When present, the map governs; when absent,
  the existing `min_severity` threshold still applies, so devices registered
  by earlier clients behave exactly as before.
- **Badge preference.** A device that registers with `badge` enabled gets the
  count of pending requests in the push payload's `aps.badge`, so the app
  icon can mirror the outstanding-approval count. Devices without it receive
  payloads with no badge key, unchanged.

## [0.2.0] - 2026-07-03

> Republished as 0.2.0 (previously tagged 2.0.0): version lines stay below 1.0 until the 1.0 launch.

The first public release. It rebuilds configuration, security, and
notifications on top of the original approve/deny flow, adds a full web
dashboard, and ships an SDK for agent integrations plus ready-to-run
deploy assets.

### Added

- **TOML configuration.** `hma init` writes a `config.toml` (mode `0600`)
  with freshly generated tokens; every setting can be overridden with an
  `HMA_*` environment variable. `hma serve` validates the config up front
  and refuses to start on missing secrets or default dev tokens.
- **`hma` CLI.** `init`, `serve`, `pair`, `status`, and `ask` — including
  `hma ask`, which creates an approval request and blocks until it's
  decided, exiting `0` (approved), `1` (denied/expired), or `2` (error).
  Every non-approved outcome is a non-zero exit, so a broken or
  unreachable server fails closed instead of letting the guarded action
  through.
- **Web dashboard.** A view-only dashboard (session-cookie auth, CSRF on
  every state-changing form) for watching live requests, viewing a
  request's authorization slip, managing paired devices, browsing the
  audit log, and rotating tokens from the settings page.
- **`/v1/stream` WebSocket.** Live push of request/device lifecycle events
  to the dashboard, with a heartbeat to keep idle connections alive.
- **Notifier layer.** Pluggable outbound notifiers — ntfy (topic-based
  push, no Apple account required) and generic webhooks — alongside the
  existing APNs push. Webhook deliveries are HMAC-SHA256 signed
  (`X-Hma-Signature`) and retried with backoff on transient (5xx/timeout)
  failures; 4xx responses are treated as a hard stop with no retry.
  Per-device `min_severity`, notification-enabled, and sound preferences
  are honored per notification.
- **`hold-sdk`.** A small Python client (`hold_sdk.request_approval`) for
  agents to request approval over HTTP without hand-rolling the polling
  loop; configured via environment variables and fail-closed by default
  (network errors, timeouts, and malformed responses all resolve to
  "denied").
- **Deploy assets.** A `Dockerfile` and Compose file
  (`ghcr.io/holdmyagent/arbiter`), a systemd unit, and a launchd plist for
  running Arbiter as a long-lived service, plus `scripts/smoke.sh` for an
  end-to-end create → approve smoke test and `scripts/demo-seed.py` for
  populating a demo instance.
- **`target` and `callback_url` fields** on approval requests, so an agent
  can indicate what it's asking permission for and receive a webhook
  callback when the decision is made.

### Changed

- **Security hardening.** All `/v1/*` routes now require a bearer token,
  including request-detail lookups (previously unauthenticated). Auth
  failures are throttled with a per-IP sliding-window rate limiter (both
  the API and the dashboard login form return `429` after repeated bad
  credentials). Responses carry `X-Content-Type-Options`,
  `X-Frame-Options`, and a `Content-Security-Policy` header. `/health` was
  trimmed to a minimal `{"ok": true}` payload.
- **Database migrations.** SQLite now tracks a schema version
  (`PRAGMA user_version`) and applies migrations in order on startup,
  including the move to WAL journal mode — upgrading in place no longer
  requires a manual schema change.
- The old token-in-URL `/pair` page and the unauthenticated `/` landing
  page are gone; both now redirect into the session-gated dashboard.

### Security

- See `SECURITY.md` for the full threat model and how to report a
  vulnerability.

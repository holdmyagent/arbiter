# Changelog

## Unreleased

## [2.0.0] - 2026-07-03

The first public release. v2 rebuilds configuration, security, and
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

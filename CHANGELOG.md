# Changelog

## Unreleased

### Added

- Server-mediated **gate policy**: per-tenant presets + personal overlay + active
  selection, resolved fail-closed (`GET /v1/policy` always non-empty,
  most-restrictive default). New `/v1/policy*` endpoints, `policy:read-resolved` /
  `policy:read` / `policy:write` capabilities, TOTP step-up on writes, mutation
  audit, and a `policy.updated` stream event. (migration 11)

### Security

- `/v1/stream` now enforces the **app** role, matching the documented
  capability matrix and the #14 least-privilege model. Previously any
  resolvable credential — an agent- or warden-role DB token, or the legacy
  static `agent_token` — could open the live approval feed and watch every
  tenant request/decision. Such credentials are now rejected (the socket
  closes with 4401, indistinguishable from a bad credential); app-role
  tokens and the admin session cookie are unchanged (fixes #19).

## [0.5.0] - 2026-07-22

Ships `hold-warden` 0.1.1 alongside SDK and docs fixes; no `/v1` API surface
changes. The warden's command adapter gains per-action `cwd`, `env`
(secret-ref), and `exec_timeout_s` — needed for coder dispatch — see
`warden/CHANGELOG.md` for the details.

### Fixed

- The SDK's blocking poll no longer collapses a genuine server-observed
  `expired` (or a late decision) into `denied`: a final read at the local
  deadline reports the true terminal status, and a transient poll error
  (a network blip) no longer aborts the wait — only a failed request
  creation, or a genuinely unknown outcome at the deadline, still fail
  closed as `denied` (fixes #13).

### Docs

- `docs/api.md` documents why 403 responses are deliberately generic
  (they must not act as a capability or tenant oracle); `server/README.md`
  gains a role-capability matrix (closes #14).
- `CONTRIBUTING.md`'s pre-PR checklist now covers the warden package
  (lint + tests).
- New `RELEASING.md` — the release runbook (version bump order, CHANGELOG
  discipline, the tag-to-PyPI-to-ghcr pipeline, the Homebrew tap
  follow-up).
- README screenshots refreshed to the 0.4.1 UI (authorization slip), plus
  a new audit-log view screenshot.

## [0.4.1] - 2026-07-17

Consolidation patch after the 0.4.0 train — hardening and performance only;
no `/v1` API surface changes. Upgrading runs two quick schema migrations
(9: token-hash index; 10: duplicate-collapse indexes — pre-existing duplicate
pending rows, if any, are expired with an audit trail).

### Fixed

- Tenant-cell acquisition failures no longer escape as 500s or dropped
  sockets: an epoch race returns the same generic 403 as every other
  resolution failure, a capacity shed returns 503, and `/v1/stream` closes
  cleanly (4401 / 1013 Try Again Later).
- The dashboard login limiter now keys on the trusted client id (the
  forwarded client behind a configured trusted proxy), matching the API
  fleet limiter — one attacker behind a shared ingress IP can no longer
  lock the admin out.
- The create route checks its rate limit *before* policy evaluation, so a
  flood of policy-denied requests trips the limiter instead of bypassing it
  (policy-denied creates now count toward the window).
- Duplicate-collapse is enforced at the database level too (partial unique
  indexes): a concurrent identical create returns the surviving pending
  request instead of racing in a twin row.
- A second `hma serve` on the same data directory refuses to start
  (advisory lock) instead of silently double-serving one database.

### Changed

- `tokens.token_hash` is indexed — token auth no longer table-scans.
- `GET /v1/audit/export` streams the audit log in batches instead of
  materializing every row in memory.
- The release pipeline builds each package exactly once: publish jobs
  upload their dists and the GitHub release attaches those same files.
- Removed dead pre-multitenancy auth internals (`require_role`,
  `_resolve_identity_legacy`); no supported code path used them since the
  per-cell port in 0.4.0.

## [0.4.0] - 2026-07-17

The trust upgrade: approvals become verifiable artifacts, and a new
enforcement daemon can execute them outside the agent's reach. All `/v1`
changes are additive; iOS 0.5.0 and hold-sdk 0.2.1 keep working unchanged.

### Added

- **Signed verdicts.** Every decision (and expiry) now produces an Ed25519
  JWS over `{request_id, action_hash, decision, decided_at,
  approval_ttl_seconds}`, stored on the request and served at
  `GET /v1/requests/{id}/verdict`; the per-tenant key set is at `GET /v1/keys`
  (any authenticated role — agent, warden, or app; each tenant sees only its
  own keys). The signing key is minted at init/first-serve
  (`verdict_signing_key.pem`, 0600).
- **Action-hash binding.** `POST /v1/requests` accepts `canonical_action` +
  `action_hash`; the server recomputes the SHA-256 over the received bytes
  (422 on mismatch) and the hash rides inside the signed verdict. Requests
  without it get a verifiably *unbound* `action_hash: null` verdict.
- **Single-use consumption.** `POST /v1/requests/{id}/consume` (warden role)
  atomically marks an approval used — 409 on replay, 410 past the
  `approval_ttl_seconds` freshness window; the sweeper expires stale
  unconsumed approvals so the UI reflects reality.
- **Per-identity tokens.** A `tokens` table (hashed at rest, scopes, expiry,
  revocation) with `hma token create|list|revoke`; roles `agent`, `warden`,
  `app`. Requests stamp `requested_by`; agent reads are scoped to their own
  requests. Legacy `[auth]` static tokens still work with a deprecation
  warning.
- **Policy layer.** `[policy]` config: per-`action_type` severity floors,
  `deny_action_types` auto-deny, per-identity create rate limit (429),
  duplicate-collapse of identical pending requests, `idempotency_key`
  replay (retries return the existing request), and server-side
  `ttl_seconds` clamping.
- **`hold-warden` 0.1.0** — the enforcement daemon (new `warden/` package):
  action registry with constrained params, canonicalization + golden
  vectors, lazy secret resolvers (`env:`/`file:`/`cmd:` with tested
  Bitwarden/1Password/`pass`/Vault recipes), verdict verification against a
  pinned key, single-use consume, command/http/secret adapters, receipts,
  and the `hma-warden init|serve|doctor|hash` CLI. See
  `warden/CHANGELOG.md` and `docs/warden.md`.
- **Audit export + new events.** `GET /v1/audit/export?format=jsonl` and
  `hma audit export`; new audit events `consumed`, `verdict_issued`,
  `policy_denied`, `rate_limited`.
- **`callback_url` allowlist.** `[notify] callback_allowlist` (CIDRs / URL
  prefixes) checked at create and at dispatch, redirects disabled; empty
  list keeps legacy behavior with a loud startup warning on first use.
- **Notification outbox (stretch).** Dispatches are journaled in a single
  `outbox` table and drained on startup: rows already enqueued survive a
  crash or restart and are re-delivered instead of silently dropped. The
  enqueue is not co-committed with the request state change, so a crash in
  the instant between the state change committing and the outbox row
  committing can still lose that one notification (accepted v1 scope — no
  transactional outbox). Migration 8 adds a persisted `notify_sent`
  (request, event) reserve committed before dispatch, making outward
  delivery **at-most-once per (request, event) across restarts**: a crash
  after the reserve commits but before the send completes drops that one
  notification rather than double-firing it (the TTL sweeper still
  fail-closes the request itself). Max 3 attempts per row with retry gaps
  of 1s then 5s (ladder constants 1/5/25s; the third rung is unreachable
  at max 3 attempts); stale rows past the request's TTL are dropped;
  deliberately no dead-letter queue.
- **Ops promotions.** `/health` now does a real DB ping (200/503);
  `hma ask` / `hma status` accept `--url` / `HMA_URL` for remote arbiters.
- **Docs.** New consolidated references (`docs/api.md`, `docs/config.md`,
  `docs/cli.md`), the warden guide + secret-manager recipes, enforcement
  tiers (`docs/enforcement-models.md`), an agent pre-exec hook
  walkthrough, and the sandboxed-agent reference architecture.
  `SECURITY.md` gains a first-class malicious-agent analysis and an honest
  "what HMA does not protect against" table.

### Fixed

- **Decision TOCTOU.** Decisions are now a guarded atomic update
  (`WHERE id=? AND status='pending'` + rowcount): concurrent approve/deny
  can no longer both land, and deciding an already-expired request is
  refused (409).

### Security

- See the rewritten `SECURITY.md` — notably the malicious-agent analysis
  (self-reported severity, consent phishing, cross-agent reads,
  notification flooding) and which 0.4.0 feature closes each.
- Deliberately deferred (documented, not shipped): hash-chained audit rows,
  Prometheus `/metrics`, quorum approvals, mTLS.

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

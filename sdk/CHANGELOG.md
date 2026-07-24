# Changelog — hold-sdk

## [0.4.0] - 2026-07-24

### Added

- **Gate-facing policy methods on `ArbiterClient`.** Two typed methods over the
  server's `/v1/policy*` surface, both authorized by the ordinary agent token
  (`policy:read-resolved`):
  - `get_resolved_policy() -> dict` — `GET /v1/policy`, the resolved policy the
    gate consumes. Raises on non-2xx (does **not** fail-closed-return like
    `request_approval`) so the gate's sync process can fall back to its own
    local most-restrictive rather than act on a partial/missing policy.
  - `report_gate_status(version, etag, fetched_at, most_restrictive) -> dict` —
    `POST /v1/policy/gate-status`, the closed-loop telemetry the gate/sync uses
    to report what it is enforcing. Returns the stored record (the reported
    fields plus a server-stamped `reported_at`).

  The policy **write/admin** surface (presets, overlay, active preset, command
  test, gate-status readout) needs the app-role decision credential and has no
  Python consumer — it is served by the macOS app's ArbiterKit — so it is
  deliberately **not** added to this agent-side SDK. Accordingly, the
  `ArbiterClient(base_url, agent_token, verify=True)` signature is unchanged and
  0.3.0's removal of the `app_token` constructor parameter stands.

## [0.3.0] - 2026-07-17

### Added

- **`idempotency_key` passthrough.** Both `hold_sdk.request_approval(...)` and
  `ArbiterClient.request_approval(...)` accept `idempotency_key` (a client-chosen
  string, max 128 chars, sent in the `POST /v1/requests` body when set). Against
  an arbiter >= 0.4.0, retrying a create with the same key returns the original
  request instead of spawning a duplicate approval prompt. The key is omitted
  from the request body when unset, so 0.3.0 SDK clients remain compatible with
  older servers.
- **`callback_url` passthrough.** The same two entry points now expose the
  server's existing per-request `callback_url` field: the arbiter POSTs the
  decision/expiry event there (HMAC-signed when the global webhook secret is
  configured). Subject to the server's `[notify] callback_allowlist` on
  arbiter >= 0.4.0.
- **Loud warning on `verify=False`.** Constructing
  `ArbiterClient(..., verify=False)` now emits a `UserWarning`:
  "TLS verification disabled — vulnerable to MITM; add your CA to the trust
  store instead". Disabling verification is almost never the right fix — add
  your private CA to the trust store or front the server with a real
  certificate (Tailscale serve / reverse proxy).

### Removed

- **Breaking:** `ArbiterClient.__init__` no longer accepts the `app_token`
  parameter. It was accepted but never stored or used (a dead parameter since
  0.2.0); the SDK is an agent-side client and never needs the decision
  credential. Remove the argument from call sites — no behavior changes.

## [0.2.1] - 2026-07-03

- Per-severity device preference support on the server; no SDK code changes
  (version alignment release).

## [0.2.0] - 2026-07-03

- First public release: `hold_sdk.request_approval` (fail-closed, env-configured)
  and `hold_sdk.client.ArbiterClient`.

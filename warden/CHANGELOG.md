# Changelog — hold-warden

## [Unreleased]

### Added

- **Execution-outcome reporting**: after a `command` or `http` adapter runs to
  `"executed"`, the warden now best-effort reports what actually happened back
  to the arbiter via `ArbiterClient.report_execution` (`POST
  /v1/requests/{rid}/consume` with `{"mode": "exec_result", ...}`), so receipts
  stop saying "outcome not reported" forever. `command` reports `kind:
  "command"`, the joined argv as `ran`, `exit_code`, and stdout+stderr (tail-
  capped per stream at 8192 bytes, matching the adapters' own truncation
  semantics, then the combined output capped at 16384 bytes — tail, not head,
  so a failing command's stderr survives even when stdout alone is at the
  adapter's 4096-char cap). `http` reports `kind: "http"`, `method url` as
  `ran`, and the HTTP status as `exit_code` (the `kind` field is what stops a
  successful webhook's `200` from being misread as a failure under the
  universal "0 means success" convention). The `secret` adapter (and any
  unknown adapter) reports nothing — the resolved secret value is never sent
  to the arbiter. The report fires strictly after `set_status(..., "executed",
  ...)` and outside the execution `try:` block, and any reporting failure is
  swallowed with a warning log — it never changes the proposal's terminal
  status and never raises into `tick()`.

  **Known accepted limitation**: the report is best-effort and fires after
  `set_status`. If the warden dies in that exact window, the outcome is lost
  permanently — crash recovery only revisits rows still `executing`, not rows
  already marked `executed`. This is accepted; the client compensates by
  rendering "Outcome not reported" rather than "Not executed". No retry queue
  is planned — out of scope.

## [0.1.1] - 2026-07-18

### Added

- **Command adapter `cwd` + `env` + `exec_timeout_s`**: `[actions.*]` may now set
  `cwd = "/abs/path/{param}"` (any `{param}` used in `cwd` MUST be `type = "enum"` —
  a path-traversal guard; config load rejects free-form string/int params there),
  `env = { VAR = "secret:name" }` (or a literal value), resolved lazily like header
  values, and `exec_timeout_s = <int>` (per-action adapter-execution cap; unset falls
  back to the global 60 s `EXEC_TIMEOUT_S`). `resolve_template`'s `resolved` dict for
  `command` now includes `cwd` (hash-bound — a human approving a dispatch is bound to
  the exact working directory) and `env_names` (injected variable NAMES only, never
  resolved values, mirroring `header_names`). Motivation: coder dispatch — a real
  `claude -p` run takes minutes, needs a repo cwd, and needs its API key injected
  without the warden's own environment leaking into the subprocess.

## [0.1.0] - 2026-07-17

First release of the Warden — Hold My Agent's enforcement daemon. HMA is
the gate; the warden decides whether the agent walks through it or merely
promises to.

### Added

- **Action registry** (`warden.toml`): command / http / secret adapters;
  params are constrained-only (enum, pattern+max_len, int ranges), each
  `{param}` must occupy an entire argv element or bounded template segment —
  no shell, no flag splicing. Config load rejects violations.
- **Canonicalization** with golden vectors: deterministic JSON
  (`sort_keys`, compact separators, `ensure_ascii=False`) over
  `{action, adapter, params, resolved, v: 1, warden}`;
  `action_hash = sha256(bytes)`. Empty params serialize as `{}`, never
  key-dropped.
- **Verdict verification**: Ed25519 JWS checked against the key pinned at
  `hma-warden init`; request id, action hash, decision, and freshness all
  verified; any mismatch fails closed (proposal `failed`, never executes).
- **Single-use execution flow**: verdict -> verify -> re-canonicalize +
  compare -> consume on the arbiter (409/410 refused) -> adapter -> receipt
  `{request_id, action_hash, decision, decided_at, verdict_jws,
  executed_at}`.
- **Lazy secret resolvers** `env:` / `file:` / `cmd:` with CI-tested
  recipes for Bitwarden/Vaultwarden (`rbw`, `bw`), 1Password (`op`),
  `pass`, and HashiCorp Vault; `hma-warden doctor` dry-runs every resolver
  and never prints values (`ok (non-empty)` / `FAILED (exit N)`).
- **Agent-facing API** (hand-written ASGI, no framework): `POST
  /v1/propose` (idempotent per agent+key), `GET /v1/proposals/{id}`
  (proposer-only), blocking `POST /v1/execute` convenience wrapper,
  `GET /health`.
- **Persistence**: SQLite proposals/receipts (WAL); startup retention purge
  (`retention_days`, default 7). No config reload — restart on
  `warden.toml` changes (documented).
- **CLI**: `hma-warden init | serve | doctor | hash`.

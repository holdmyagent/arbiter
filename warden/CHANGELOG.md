# Changelog — hold-warden

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

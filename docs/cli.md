# CLI reference — `hma` and `hma-warden`

Two console scripts ship in two packages: `hma` (server package
`holdmyagent`) and `hma-warden` (enforcement daemon package `hold-warden`).

## `hma` — the arbiter server CLI

### `hma init [--force]`

Write a fresh `config.toml` (default `~/.config/holdmyagent/config.toml`,
honors `HMA_CONFIG`) with random credentials, mode 0600. Prints the agent
token, app token, and admin password **once**. `--force` overwrites an
existing file.

### `hma serve [--config PATH] [--lan] [--log-json]`

Run the server. `--lan` binds `0.0.0.0` and prints the LAN pairing URL;
`--log-json` emits JSON log lines. Refuses to start on missing/default
credentials. On first serve, mints the Ed25519 verdict signing key
(`verdict_signing_key.pem`, 0600, in the config directory). Logs a
deprecation warning when a legacy `[auth]` token is used by a client.

### `hma pair [--config PATH] [--host URL]`

Print the pairing QR (embeds the app token) in the terminal. `--host`
overrides the advertised base URL (default `http://<LAN-IP>:<port>`).

### `hma status [--config PATH] [--url URL]`

Show server health, notifier state, devices, and pending requests.
Server address resolution order: `--url`, then the `HMA_URL` environment
variable, then the default `http://127.0.0.1:<config port>` — so it works
against a remote arbiter without a local server config.

### `hma ask TITLE [options]`

Create an approval request and block until it is decided.

| Option | Default | Meaning |
|---|---|---|
| `--severity low\|medium\|high\|critical` | `medium` | Claimed severity (the server may raise it per `[policy.severity_floors]`). |
| `--target TEXT` | none | What is being acted on. |
| `--ttl N` | `300` | Request TTL in seconds (server-clamped to `[policy]` bounds). |
| `--description TEXT` | `""` | Longer detail / push body. |
| `--url URL` | `http://127.0.0.1:<port>` | Arbiter base URL; falls back to `HMA_URL` env, then the localhost default. |
| `--config PATH` | default config | Where to read the agent token (or set `HMA_AGENT_TOKEN`). |

Exit codes: `0` approved, `1` denied or expired, `2` error — **fail-closed**:
treat any nonzero as "no". With `--url`/`HMA_URL` plus `HMA_AGENT_TOKEN` in
the environment, `hma ask` needs no local config file at all.

### `hma token create NAME --role ROLE [options]` (0.4.0)

Mint a per-identity API token. The token is printed **once** (format
`hma_<role>_<48 hex chars>`) and stored only as a SHA-256 hash.

| Option | Meaning |
|---|---|
| `--role agent\|warden\|app` | Required. See the role table in [`api.md`](api.md). |
| `--action-types a,b` | Scope: the token may only create these `action_type`s. |
| `--max-severity S` | Scope: cap on the (effective) severity it may create. |
| `--expires-days N` | Token expiry; omit for non-expiring. |
| `--config PATH` | Which `config.toml` to load — the token store is the server database at its `db_path`, so all three `token` subcommands run on the arbiter host, not over HTTP. |

### `hma token list [--config PATH]`

Table of token names, roles, created/expires/last-used timestamps, and
revocation state. Never prints hashes or token values.

### `hma token revoke NAME [--config PATH]`

Immediately revokes the named token (sets `revoked_at`; auth refuses it from
then on).

### `hma audit export [--format jsonl] [--out PATH] [--url URL]`

Dump the append-only audit table as JSON Lines (the CLI twin of
`GET /v1/audit/export`; it calls that same endpoint over HTTP with the
configured app token, rather than reading the database directly). `--out`
writes to a file instead of stdout. `--url` follows the same resolution
order as `hma ask`/`hma status` (`--url`, then `HMA_URL`, then
`http://127.0.0.1:<port>`), so it can export from a remote arbiter.

## `hma-warden` — the enforcement daemon CLI

See [`warden.md`](warden.md) for concepts and `warden.toml` structure.

### `hma-warden init --arbiter-url URL --config PATH`

Pair with an arbiter and scaffold a config: fetches `GET /v1/keys`, **pins**
the signing key into `arbiter_pubkey = "<kid>:<base64url>"`, writes a
starter `warden.toml` (mode 0600), mints one agent-facing bearer token and
prints it **once**.

### `hma-warden serve --config PATH`

Run the warden: the agent-facing HTTP API (default bind `127.0.0.1`, port
from config) plus the 1-second poll loop that drives proposals through
verdict verification, consumption, and execution. On startup, deletes
proposals/receipts older than `retention_days` (default 7).

### `hma-warden doctor --config PATH`

Preflight, exit 0/1. Checks: config parses; **every** secret ref resolves,
reporting `ok (non-empty)` or `FAILED (<reason>)` per resolver — values are
never printed, but the reason varies by failure: `unset or empty` (env),
`unreadable` or `empty output` (file), `timeout`, `not runnable`,
`malformed reference`, `empty command`, or `exit N` (a `cmd:` ref that ran
but returned non-zero); arbiter `/health` reachable (`FAILED (unreachable or
not 200)` otherwise); arbiter `/v1/keys` matches the pinned key (`FAILED
(key mismatch)` otherwise).

### `hma-warden hash ACTION --config PATH [--param k=v]...`

Print the canonical action document and its SHA-256 for a registry action
with the given params — the operator's tool for verifying what a request's
`action_hash` actually commits to.

```bash
hma-warden hash restart_service --config warden.toml --param unit=nginx
```

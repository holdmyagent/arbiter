# Secret managers

The warden holds the credentials your agent must never see. This page covers how it
reads them, and gives tested recipes for the popular managers. The recipes are exercised
in CI against fake `rbw`/`bw`/`op`/`pass`/`vault` CLIs, so the exact invocations below
stay working.

## Reference schemes

Everywhere `warden.toml` takes a secret — `arbiter_token`, every `[agents.*] token`,
every `[secrets]` entry — it takes a **reference**, never a value:

| Scheme | Example | Behavior |
|---|---|---|
| `env:` | `env:HMA_WARDEN_TOKEN` | Read the environment variable. Unset or empty = resolution failure. |
| `file:` | `file:/etc/warden/deploy_key` | Read the file, strip surrounding whitespace. Should be mode 0600 (the warden warns otherwise). |
| `cmd:` | `cmd:rbw get api-bearer` | Run the command; stripped stdout is the secret. Non-zero exit = resolution failure. |

Notes:

- `cmd:` is split into argv and run **without a shell** — pipes, redirects, and `$VARS`
  do not work. If a tool needs post-processing, wrap it in a tiny script and reference
  the script.
- Resolution is **lazy**: references resolve at execution time, per approved action. A
  locked vault fails that one proposal closed (`failed`) — the daemon keeps serving and
  recovers as soon as the vault unlocks. Nothing is resolved at propose time, and
  resolved values never enter the canonical document, the arbiter payload, receipts, or
  logs.
- The value is `stdout.strip()` — inner newlines are preserved, so keep vault entries
  single-line unless you really mean a multi-line secret.

## Bitwarden / Vaultwarden — `rbw` (recommended)

`rbw` is the unofficial Bitwarden CLI with a background agent — the right shape for a
daemon: you unlock once, `rbw-agent` holds the unlocked vault, and the warden resolves
without interactive prompts.

```bash
rbw config set base_url https://vaultwarden.example.com   # your Vaultwarden
rbw config set email you@example.com
rbw register && rbw login
rbw unlock                  # interactive once; rbw-agent caches the unlocked vault
rbw get api-bearer          # sanity check (prints the value - do this once, privately)
```

```toml
[secrets]
api_bearer = "cmd:rbw get api-bearer"
```

Daemon notes:

- **Agent unlock**: the warden never prompts. After a host reboot or an agent lock
  timeout (`rbw config set lock_timeout 3600`, in seconds), run `rbw unlock` from any
  interactive shell as the same user; until then, affected actions fail closed and
  everything else keeps working.
- `rbw unlock` needs a pinentry; on headless hosts install `pinentry-tty` or
  `pinentry-curses` and unlock over SSH.

## Bitwarden official CLI — `bw`

```bash
bw config server https://vaultwarden.example.com
bw login
export BW_SESSION="$(bw unlock --raw)"
bw get password api-bearer          # sanity check
```

```toml
[secrets]
api_bearer = "cmd:bw get password api-bearer"
```

**The `BW_SESSION` caveat**: `bw` needs the session token in the *warden's* environment
— put `BW_SESSION=...` in the systemd unit's `EnvironmentFile` (mode 0600). Sessions die
on `bw lock`, `bw logout`, and vault timeouts, and there is no agent to refresh them:
when that happens, resolutions fail closed until you mint a new session and restart the
warden. Prefer `rbw` for daemons.

## 1Password — `op`

```bash
export OP_SERVICE_ACCOUNT_TOKEN=ops_...    # service accounts are the daemon-friendly auth
op read "op://Infra/api-bearer/credential"
```

```toml
[secrets]
api_bearer = "cmd:op read op://Infra/api-bearer/credential"
```

For daemons use a 1Password **service account** and put `OP_SERVICE_ACCOUNT_TOKEN` in
the `EnvironmentFile`. The desktop-app integration requires an unlocked GUI session and
is not daemon-friendly.

## pass

```bash
pass insert warden/api-bearer
pass show warden/api-bearer
```

```toml
[secrets]
api_bearer = "cmd:pass show warden/api-bearer"
```

Notes: `pass show` prints the **entire** entry, so keep warden secrets as single-line
entries (the value on line 1, nothing else). `gpg-agent` must be able to decrypt without
prompting — a cached passphrase with a generous `default-cache-ttl`, or a dedicated
passphrase-less key for this store.

## HashiCorp Vault

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs....                  # or run Vault Agent auto-auth
vault kv get -field=token secret/warden/api-bearer
```

```toml
[secrets]
api_bearer = "cmd:vault kv get -field=token secret/warden/api-bearer"
```

`-field=` prints the raw value with no table decoration — exactly what the `cmd:`
resolver wants. Put `VAULT_ADDR`/`VAULT_TOKEN` in the `EnvironmentFile`; for automatic
token renewal, run Vault Agent and reference its sink file with `file:` instead.

## `doctor` never prints values

`hma-warden doctor` dry-runs **every** reference in `warden.toml` — `arbiter_token`,
every `[agents.*]` token, every `[secrets]` entry — but keeps only whether resolution
succeeded and produced a non-empty value. Per resolver it reports exactly
`ok (non-empty)` or `FAILED (<reason>)`, where the reason is short and value-free:
`FAILED (exit 1)` for a non-zero `cmd:` exit, `FAILED (unset or empty)` for a missing
env var, `FAILED (unreadable)` for a file problem, `FAILED (malformed reference)` /
`FAILED (timeout)` / `FAILED (not runnable)` for a broken `cmd:` ref. The resolved value
never touches stdout, stderr, or logs — so troubleshooting on a live host never dumps
vault contents into a terminal, scrollback, or a pasted bug report.

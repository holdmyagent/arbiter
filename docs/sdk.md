# `hold-sdk` — Python SDK reference

```bash
pip install hold-sdk
```

Requires Python 3.11+, `httpx`. Importable as `hold_sdk`.

## `request_approval`

```python
from hold_sdk import request_approval

def request_approval(
    title,
    *,
    description="",
    severity="medium",
    target=None,
    ttl_seconds=300,
    payload=None,
    action_type="generic",
    server_url=None,
    token=None,
    poll_interval=2,
    timeout=None,
    idempotency_key=None,
    callback_url=None,
) -> str: ...
```

Creates an approval request and blocks (polling) until it's decided or a
timeout is hit. Returns one of `"approved"`, `"denied"`, `"expired"`.

| Parameter | Default | Meaning |
|---|---|---|
| `title` | *(required)* | Short summary shown in the dashboard and any push notification. |
| `description` | `""` | Longer detail — e.g. the actual command being gated. Rendered as a command block on the request's detail page (the authorization slip), and used as the body of APNs/ntfy push notifications. |
| `severity` | `"medium"` | One of `"low"`, `"medium"`, `"high"`, `"critical"`. Drives notification priority and which paired devices get notified (per-device `min_severity`). |
| `target` | `None` | Free-text identifier of what's being acted on — a hostname, table, PR, cluster. Shown as its own column/field in the dashboard. |
| `ttl_seconds` | `300` | How long the request stays `pending` before the server auto-expires it. |
| `payload` | `None` (→ `{}`) | Arbitrary JSON dict rendered on the request's detail page — attach structured context (a diff, a plan, affected row counts). |
| `action_type` | `"generic"` | Freeform label for what kind of caller is asking; shown as "Requested by" in the dashboard. |
| `server_url` | `None` | Arbiter base URL. Falls back to the `HMA_SERVER_URL` environment variable. |
| `token` | `None` | The server's `agent_token` (from `config.toml` / `hma init`'s printed output) — **not** `app_token`; request creation is agent-authenticated. Falls back to `HMA_AGENT_TOKEN`. |
| `poll_interval` | `2` | Seconds between status polls while waiting. |
| `timeout` | `None` | Local wait deadline in seconds. Defaults to `ttl_seconds + 5`, i.e. slightly longer than the server's own expiry, so the server (not a client-side race) decides when a request expires. |
| `idempotency_key` | `None` | Optional client-chosen key (max 128 chars). On arbiter >= 0.4.0, retrying a create with the same key returns the original request instead of creating a duplicate prompt. Omitted from the request body when `None`. |
| `callback_url` | `None` | Optional URL the server POSTs the decision/expiry event to (HMAC-signed when the global webhook secret is set). Checked against the server's `[notify] callback_allowlist` on arbiter >= 0.4.0. Omitted when `None`. |

### The fail-closed contract

**Only `"approved"` means yes.** Every other outcome — an explicit
`"denied"`, an explicit `"expired"`, an unconfigured client (no
`server_url`/`token` and no `HMA_SERVER_URL`/`HMA_AGENT_TOKEN`), any
network error, any non-2xx HTTP response, a malformed server response, or
hitting the local `timeout` — returns `"denied"`. `request_approval`
never raises for any of those cases; a caller that only checks `== "approved"`
gets fail-closed behavior for free, without a `try`/`except`:

```python
if request_approval("Deploy to prod?", severity="high") != "approved":
    raise SystemExit("blocked: not approved")
```

## `hold_sdk.client.ArbiterClient`

A thin class wrapping the same flow, useful when you're making many
requests and want to reuse one `httpx.Client` (connection pooling)
instead of opening a fresh one per call:

```python
from hold_sdk.client import ArbiterClient

client = ArbiterClient(
    base_url="http://127.0.0.1:8000",
    agent_token="<agent_token>",
)
decision = client.request_approval("Restart api service", severity="medium", target="hermes")
```

The method's actual signature:

```python
def request_approval(
    self,
    title,
    description="",
    action_type="generic",
    payload=None,
    severity="medium",
    ttl=300,
    target=None,
    poll_interval=2,
    timeout=None,
    idempotency_key=None,
    callback_url=None,
) -> str: ...
```

Same fail-closed contract (`"denied"` on any error) as the module-level
`request_approval` function, but note two differences before copy-pasting
between the two: the TTL parameter here is named **`ttl`, not
`ttl_seconds`**, and there is no environment-variable fallback — the
server URL and agent token are passed explicitly to the constructor
(`base_url`, `agent_token`). Construct the client once and call
`request_approval` on it repeatedly rather than reconstructing a client
per call.

The constructor is `ArbiterClient(base_url, agent_token, verify=True)`. As of
0.3.0 the dead `app_token` parameter is gone (it was never used), and passing
`verify=False` emits a loud `UserWarning` — if your server uses a private CA,
add that CA to your trust store (or use Tailscale serve / a reverse proxy with
a real certificate) instead of disabling TLS verification.

## Configuration

The module-level `request_approval` function reads the agent's credentials
from the environment by default; `ArbiterClient` takes them as explicit
constructor arguments (`base_url`, `agent_token`) instead. A typical
deployment using the module-level function just sets these once:

```bash
export HMA_SERVER_URL="http://127.0.0.1:8000"
export HMA_AGENT_TOKEN="<agent_token from hma init>"
```

`agent_token` is printed once by `hma init` and lives in `config.toml`'s
`[auth] agent_token`. It's distinct from `app_token` (which decides
requests) and `admin_password` (dashboard login) — an agent only ever
needs `agent_token`.

## Hook example: gate a shell command through `hma ask`

Most coding agents have some kind of hook or middleware system that runs
before a tool/command executes and can block it based on that command's
exit code. `hma ask` is built for exactly that seam — no SDK required,
since the hook is just running another CLI command:

```python
#!/usr/bin/env python3
"""Pre-command hook: gate risky shell commands through Hold My Agent
before your coding agent's tool-execution step actually runs them.
Wire this in as your agent's pre-tool-use / pre-command hook (or a
git pre-push hook, a CI gate step, etc.) — whatever mechanism your
agent's hook system uses to run a command before the real one and
check its exit code."""
import subprocess
import sys

# Patterns worth pausing for. Tune this list to your own risk tolerance.
DANGEROUS = ("drop table", "rm -rf", "git push --force", "terraform destroy", "kubectl delete")

def main() -> int:
    command = " ".join(sys.argv[1:])
    if not command or not any(p in command.lower() for p in DANGEROUS):
        return 0  # not on the watchlist — let it through untouched
    result = subprocess.run([
        "hma", "ask", f"Run: {command}",
        "--description", command,
        "--severity", "critical",
        "--ttl", "120",
    ])
    # hma ask exit codes: 0 approved, 1 denied/expired, 2 error.
    # Any non-zero should block the real command — that's the whole point.
    return 0 if result.returncode == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
```

Point your agent's hook configuration at this script (as the command that
must succeed before the real one runs) and it'll pause on anything
matching `DANGEROUS`, push an alert to your phone, and only let the real
command through once someone approves it from a paired device.

If your agent's hook system calls into Python directly instead of
shelling out, use `request_approval` the same way inside that hook
function instead of `subprocess.run(["hma", "ask", ...])` — same
contract, same exit-code-equivalent (`!= "approved"` is your "block it").

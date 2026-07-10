# Gate an agent through HMA (pre-exec hook)

A complete tier-1 integration (see
[`enforcement-models.md`](enforcement-models.md)): many agent runtimes run a
**pre-execution hook** before every tool/command call and block the call on
the hook's verdict. Point that hook at the script below and dangerous shell
commands pause behind a phone approval — even if the agent is running
unattended or with permissions bypassed. Fail-closed: denied, expired, or
server-unreachable all block.

The example targets a common hook contract — the pending call arrives as JSON
on stdin, and the hook signals **block** with a non-zero exit. Adapt the
input parsing and the decision output to your agent's hook format; the gate
logic (`hma ask` → allow on `0`, block otherwise) is the part that matters.

## 1. The gate script

Save it anywhere your hook config can point at it (e.g. `~/hooks/hma-gate.py`):

```python
#!/usr/bin/env python3
"""Pre-exec gate: pause dangerous shell commands for a human ruling via Hold
My Agent. Fail-closed: denied/expired/unreachable all block the command."""
import json
import os
import subprocess
import sys

# Patterns worth pausing for. Tune to your own risk tolerance.
DANGEROUS = ("rm -rf", "drop table", "git push --force", "terraform destroy",
             "kubectl delete", "dd if=", "mkfs")

def main() -> int:
    event = json.load(sys.stdin)                      # hook input arrives on stdin
    # Only gate shell/command calls; let everything else through. Adjust these
    # keys to match your agent's hook payload.
    if event.get("tool_name") not in ("Bash", "Shell", "exec"):
        return 0
    command = (event.get("tool_input") or {}).get("command", "")
    if not command or not any(p in command.lower() for p in DANGEROUS):
        return 0                                      # not on the watchlist
    result = subprocess.run(
        ["hma", "ask", f"the agent wants to run: {command[:80]}",
         "--description", command,
         "--severity", "critical",
         "--ttl", "120",
         "--url", os.environ.get("HMA_URL", "http://127.0.0.1:8000")],
        capture_output=True)
    # hma ask exit codes: 0 approved, 1 denied/expired, 2 error.
    if result.returncode != 0:
        # Block the call. Here we use a non-zero exit; if your harness reads a
        # structured allow/deny decision instead, emit it in that format.
        print("blocked: not approved via Hold My Agent (denied, expired, or "
              "server unreachable — fail-closed)", file=sys.stderr)
        return 1
    return 0                                           # approved — allow the call

if __name__ == "__main__":
    sys.exit(main())
```

Make it executable: `chmod +x ~/hooks/hma-gate.py`.

## 2. The hook configuration

Register the script as your agent runtime's **pre-execution / pre-tool** hook,
matched to shell/command calls, with a timeout comfortably above the script's
`--ttl` (below, 180s > 120s) so the server's expiry — not the hook timeout —
decides the outcome (an expiry is a clean deny; a hook timeout is a noisier
one). A typical JSON hook config looks like:

```json
{
  "hooks": {
    "pre-exec": [
      {
        "match": "shell",
        "run": "python3 ~/hooks/hma-gate.py",
        "timeout": 180
      }
    ]
  }
}
```

Use whatever field names and event name your runtime expects — the shape
above is illustrative. The requirement is only that the runtime runs the
script before the call and blocks the call when the script signals block.

## 3. Environment

The hook host needs the `holdmyagent` package (for the `hma` CLI) and two
environment variables — no local server config file required:

```bash
pip install holdmyagent
export HMA_URL="http://arbiter.tailnet.example:8000"   # where the arbiter runs
export HMA_AGENT_TOKEN="hma_agent_…"                   # hma token create my-agent --role agent
```

`hma ask` resolves the server from `--url`/`HMA_URL` and the agent token from
`HMA_AGENT_TOKEN` — mint a dedicated token per agent
(`hma token create my-agent --role agent`) so requests are attributed and
individually revocable.

## 4. Try it

```bash
# Have the agent run something on the watchlist, e.g.:
#   "run: rm -rf /tmp/scratch-dir"
# Your phone gets a critical push; the call blocks until you rule.
# Approve -> the command runs. Deny, ignore for 120s, or stop the server
# -> the command is blocked with the fail-closed reason.
```

## Notes and hardening

- **HTTP hook variant.** Some runtimes support an HTTP hook that POSTs the
  event JSON to a URL and reads the decision from the response body. Point one
  at a small relay that applies the same logic as the script above if you would
  rather keep the gate off the agent host. The command hook above is the
  simplest complete setup, so it is the primary example.
- **Lock the hook config.** An agent with write access to its own settings can
  remove the hook — that is the tier-1 boundary. Make the hook config
  read-only to the agent (managed/immutable settings) where you need the gate
  to be non-negotiable, or move to [tier 2](enforcement-models.md) where
  enforcement does not live on the agent's host at all.
- **Widen the matcher** to gate more tools (e.g. file writes), and extend the
  script's inspection of the event payload accordingly.
```

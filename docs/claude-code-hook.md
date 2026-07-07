# Gate Claude Code through HMA (PreToolUse hook)

A complete tier-1 integration (see
[`enforcement-models.md`](enforcement-models.md)): Claude Code's
`PreToolUse` hook runs before every tool call and can deny it — a deny
blocks the tool even in `bypassPermissions` mode. This page gates dangerous
`Bash` commands behind a phone approval.

## 1. The gate script

Save as `~/.claude/hooks/hma-gate.py` (any path works — the hook config
points at it):

```python
#!/usr/bin/env python3
"""Claude Code PreToolUse gate: pause dangerous Bash commands for a human
ruling via Hold My Agent. Fail-closed: denied/expired/unreachable all block."""
import json
import os
import subprocess
import sys

# Patterns worth pausing for. Tune to your own risk tolerance.
DANGEROUS = ("rm -rf", "drop table", "git push --force", "terraform destroy",
             "kubectl delete", "dd if=", "mkfs")

def main() -> int:
    event = json.load(sys.stdin)                      # hook input arrives on stdin
    if event.get("tool_name") != "Bash":
        return 0                                      # only gate Bash; allow the rest
    command = (event.get("tool_input") or {}).get("command", "")
    if not command or not any(p in command.lower() for p in DANGEROUS):
        return 0                                      # not on the watchlist
    result = subprocess.run(
        ["hma", "ask", f"Claude Code wants to run: {command[:80]}",
         "--description", command,
         "--severity", "critical",
         "--ttl", "120",
         "--url", os.environ.get("HMA_URL", "http://127.0.0.1:8000")],
        capture_output=True)
    # hma ask exit codes: 0 approved, 1 denied/expired, 2 error — nonzero blocks.
    decision = "allow" if result.returncode == 0 else "deny"
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": (
                "approved from a paired device via Hold My Agent"
                if decision == "allow" else
                "not approved via Hold My Agent (denied, expired, or server "
                "unreachable — fail-closed)"),
        }
    }))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

Make it executable: `chmod +x ~/.claude/hooks/hma-gate.py`.

## 2. The hook configuration

Add to Claude Code settings (`~/.claude/settings.json` for the user, or a
project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/hma-gate.py",
            "timeout": 180
          }
        ]
      }
    ]
  }
}
```

The `timeout` (180s) must exceed the `--ttl 120` the script passes to
`hma ask`, so the server's expiry — not the hook timeout — decides the
outcome (an expiry is a clean deny; a hook timeout is a noisier one).

## 3. Environment

The hook host needs the `holdmyagent` package (for the `hma` CLI) and two
environment variables — no local server config file required:

```bash
pip install holdmyagent
export HMA_URL="http://arbiter.tailnet.example:8000"   # where the arbiter runs
export HMA_AGENT_TOKEN="hma_agent_…"                   # hma token create claude-code --role agent
```

`hma ask` resolves the server from `--url`/`HMA_URL` and the agent token
from `HMA_AGENT_TOKEN` — mint a dedicated token per agent
(`hma token create claude-code --role agent`) so requests are attributed and
individually revocable.

## 4. Try it

```bash
# In a Claude Code session, ask it to run something on the watchlist:
#   "run: rm -rf /tmp/scratch-dir"
# Your phone gets a critical push; the tool call blocks until you rule.
# Approve -> the command runs. Deny, ignore for 120s, or stop the server
# -> the command is blocked with the fail-closed reason.
```

## Notes and hardening

- **HTTP hook variant.** Claude Code also supports `{"type": "http", "url":
  "http://127.0.0.1:8765/hook"}` hooks that POST the event JSON to a URL and
  read the decision from the response body. Point one at a small relay that
  applies the same logic as the script above if you would rather keep the
  gate off the agent host. The command hook above is the simplest complete
  setup, so it is the primary example.
- **Lock the hook config.** An agent with write access to its own settings
  can remove the hook — that is the tier-1 boundary. Use managed settings
  (`allowManagedHooksOnly`) to block user/project/plugin hooks where you
  need the gate to be non-negotiable, or move to
  [tier 2](enforcement-models.md) where enforcement does not live on the
  agent's host at all.
- **Widen the matcher** to gate more tools (e.g. `"matcher": "Bash|Write"`),
  and extend the script's inspection of `tool_input` accordingly.

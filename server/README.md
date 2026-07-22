# Hold My Agent — Arbiter

Self-hosted, fail-closed approval server for AI agents. Before your agent
does something irreversible, it asks a human — Arbiter holds the request,
pushes an alert to your phone (APNs, ntfy, or a webhook), and waits for a
real decision. If the server is unreachable or the request times out, the
answer defaults to **no**.

```bash
pip install holdmyagent
hma init
hma serve
```

## Roles & capabilities

Four kinds of caller talk to the API, each scoped to a different slice:

| Role | Can do |
|---|---|
| `agent` | Create requests; read its own requests and verdicts. |
| `warden` | Everything `agent` can, plus send `canonical_action`/`action_hash` at create and consume an approved verdict (single-use, any warden identity). |
| `app` | List and decide all requests, manage devices, read notify policy, open the live stream, export the audit log. |
| admin session | View-only dashboard, plus audit export. |

Full capability matrix (exact routes and status codes):
[`docs/api.md`](../docs/api.md#authentication-and-roles).

- Homepage: https://holdmyagent.com
- Source / issues: https://github.com/holdmyagent/arbiter

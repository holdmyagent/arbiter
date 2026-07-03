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

- Homepage: https://holdmyagent.com
- Source / issues: https://github.com/holdmyagent/arbiter

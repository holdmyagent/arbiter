# `hold-sdk`

Python client for Hold My Agent's Arbiter server — gate an agent action
behind a human approval with one call:

```python
from hold_sdk import request_approval

if request_approval("Deploy to prod?", severity="high") != "approved":
    raise SystemExit("blocked: not approved")
```

Fail-closed: any timeout, network error, or unconfigured client returns
`"denied"`, never raises.

Making many requests? `ArbiterClient` reuses one connection:

```python
from hold_sdk import ArbiterClient

client = ArbiterClient(base_url="http://127.0.0.1:8000", agent_token="<agent_token>")
decision = client.request_approval("Restart api service", severity="medium")
```

- Homepage: https://holdmyagent.com
- Source / issues: https://github.com/holdmyagent/arbiter

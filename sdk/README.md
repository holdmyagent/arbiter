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

- Homepage: https://holdmyagent.com
- Source / issues: https://github.com/holdmyagent/arbiter

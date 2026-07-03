#!/usr/bin/env python3
"""Seed demo requests for screenshots: hma must be serving; reads HMA_CONFIG."""
import httpx
from arbiter.config import Config

cfg = Config.load()
base = f"http://127.0.0.1:{cfg.server.port}"
agent = {"Authorization": f"Bearer {cfg.auth.agent_token}"}
app = {"Authorization": f"Bearer {cfg.auth.app_token}"}
samples = [
    ("Deploy to production", "kubectl apply -f prod/", "critical", "prod-cluster", 300),
    ("Drop table events", "DROP TABLE events;", "critical", "analytics-db", 240),
    ("Merge release PR", "gh pr merge 481", "high", "holdmyagent/arbiter", 600),
    ("Restart api service", "systemctl restart api", "medium", "hermes", 600),
    ("Clear build cache", "rm -rf ~/.cache/build", "low", "ci-runner", 900),
]
for title, cmd, sev, target, ttl in samples:
    httpx.post(f"{base}/v1/requests", headers=agent, json={
        "title": title, "description": cmd, "severity": sev,
        "target": target, "ttl_seconds": ttl})
reqs = httpx.get(f"{base}/v1/requests", headers=app).json()
httpx.post(f"{base}/v1/requests/{reqs[-1]['id']}/decision", headers=app,
           json={"decision": "approve"})
print(f"seeded {len(samples)} requests (last one approved)")

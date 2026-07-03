# Quickstart

This walks through installing Arbiter, starting the server, and gating
your first command — entirely on one machine, no phone required.

## Install

```bash
pip install holdmyagent
```

This installs the `hma` CLI and the `arbiter` package (`holdmyagent` is
the PyPI distribution name; `arbiter` is what you `import`). Python 3.11+
is required.

## Initialize a config

```bash
hma init
```

This writes `~/.config/holdmyagent/config.toml` (mode `0600`) with four
freshly generated secrets and prints the three you'll actually handle
once (the fourth, `session_secret`, stays in the file — the server uses
it internally to sign dashboard session cookies):

```
Wrote /home/you/.config/holdmyagent/config.toml
  agent token:    3f9c...   (agents/scripts use this to create requests)
  app token:      7ab1...   (the app/dashboard-decision API uses this)
  admin password: k3nA...   (dashboard login)
Shown once — they live in the config file from now on.
```

Everything after this is in `config.toml` — there's no separate secrets
store. If you lose a token, either read it back out of the file or rotate
it from `/dashboard/settings` (which rewrites the file for you).

Use `HMA_CONFIG=/path/to/config.toml` to point at a config anywhere other
than the default path — useful for running more than one instance, or for
the throwaway config this guide's examples use.

## Start the server

```bash
hma serve
```

By default this binds `127.0.0.1:8000` — reachable only from the same
machine. The dashboard is at `http://127.0.0.1:8000/dashboard`; log in
with the admin password `hma init` printed.

To make it reachable from your phone on the same LAN, use `--lan` (binds
`0.0.0.0` and prints a pairing URL):

```bash
hma serve --lan
```

For anything beyond "reachable on my LAN" — a real deployment, a reverse
proxy, running as a background service — see the deploy guides linked
from the [README](../README.md#deploying).

## Gate your first command

In one terminal, ask for approval:

```bash
hma ask "Drop the production table?" --severity critical --ttl 120
```

This blocks — `hma ask` doesn't print anything until the request is
decided. In a second terminal, approve it using the `app_token` from
`hma init`; the curl sequence below looks the request back up itself
(no id from the first command needed):

```bash
APP_TOKEN=<app_token from hma init>
RID=$(curl -s localhost:8000/v1/requests -H "Authorization: Bearer $APP_TOKEN" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
curl -X POST "localhost:8000/v1/requests/$RID/decision" \
  -H "Authorization: Bearer $APP_TOKEN" -H 'content-type: application/json' \
  -d '{"decision":"approve"}'
```

The first terminal exits `0` and prints the decided request as JSON. Deny
it instead (`{"decision":"deny"}`), or just let the `--ttl` run out, and
it exits non-zero — see the [README](../README.md) for the exit-code
contract that `hold_sdk.request_approval` shares.

In real use, that decision step is a tap in the paired iOS app (with
biometric step-up) or a push through ntfy/webhook, not a hand-rolled curl
call — see [`docs/apns.md`](apns.md) and [`docs/ntfy.md`](ntfy.md).

## Next steps

- Wire an agent up with [`docs/sdk.md`](sdk.md) instead of shelling out to `hma ask`.
- Run it as a real service: [Docker](deploy-docker.md), [systemd](deploy-systemd.md), or [launchd](deploy-launchd.md).
- Put it behind a reverse proxy or your tailnet: [nginx](deploy-nginx.md), [Tailscale](deploy-tailscale.md).

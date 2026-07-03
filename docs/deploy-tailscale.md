# Deploying over Tailscale

If you already run [Tailscale](https://tailscale.com/), it's the fastest
way to get Arbiter reachable from your phone with real TLS and no public
exposure at all — no certificates to manage, no reverse proxy to write.

## Setup

1. Leave Arbiter on its default bind — `127.0.0.1:8000`. Tailscale's
   `serve` feature reverse-proxies from the tailnet interface to
   localhost, so you don't need `--lan` or `HMA_HOST=0.0.0.0` here:

   ```bash
   hma serve
   ```

2. In another terminal, tell Tailscale to serve port 8000 over HTTPS on
   your tailnet, in the background:

   ```bash
   sudo tailscale serve --bg 8000
   ```

   Tailscale provisions a certificate automatically and prints the URL,
   something like `https://your-machine.your-tailnet.ts.net`. Check it
   any time with:

   ```bash
   tailscale serve status
   ```

3. Point the iOS app (or your browser, for the dashboard) at that
   `https://...ts.net` URL instead of a bare IP. `/v1/stream`'s WebSocket
   upgrade works through `tailscale serve` without any extra config — it's
   a normal HTTPS reverse proxy from Tailscale's point of view.

## The funnel caveat — don't

Tailscale also has `tailscale funnel`, which exposes a served port to the
**public internet**, not just your tailnet. Arbiter is designed to be
reachable only by people you trust with a bearer token or the admin
password — bearer tokens and rate-limited login are defense in depth, not
a reason to put the login form in front of the whole internet. Don't run:

```bash
sudo tailscale funnel 8000   # do NOT do this for Arbiter
```

Use `tailscale serve` (tailnet-only) as shown above, not `funnel`. If you
genuinely need approvals to work from a device that isn't on your
tailnet, put a real reverse proxy with its own access control in front
instead — see [`docs/deploy-nginx.md`](deploy-nginx.md) — rather than
funneling Arbiter itself to the public internet.

## Stopping

```bash
sudo tailscale serve --bg --https=443 off
# or, to remove all serve config for this machine:
sudo tailscale serve reset
```

## Verifying

```bash
tailscale serve status
curl -fsS https://your-machine.your-tailnet.ts.net/health
```

# Docs index

Everything in `docs/`, grouped by what you're trying to do.

## Start here

- [quickstart.md](quickstart.md) — install, `hma init`, `hma serve`, gate
  your first command; entirely on one machine, no phone required.
- [architecture.md](architecture.md) — how it all fits together: system
  map, request lifecycle, the warden's enforcement chain, tenant cells.

## Integrate an agent

- [sdk.md](sdk.md) — `hold-sdk` reference: `request_approval`,
  `ArbiterClient`, the fail-closed contract, a hook example.
- [agent-hook.md](agent-hook.md) — gate an agent's shell/tool calls
  through HMA with a pre-exec hook.
- [api.md](api.md) — consolidated REST API reference: every `/v1`
  endpoint, auth roles, status codes.

## Deploy

- [deploy-docker.md](deploy-docker.md) — Docker / Compose
  (`ghcr.io/holdmyagent/arbiter`).
- [deploy-systemd.md](deploy-systemd.md) — systemd unit (Linux).
- [deploy-launchd.md](deploy-launchd.md) — launchd (macOS).
- [deploy-nginx.md](deploy-nginx.md) — reverse proxy with WebSocket
  upgrade for `/v1/stream`.
- [deploy-tailscale.md](deploy-tailscale.md) — expose it over your
  tailnet only.

## Operate

- [config.md](config.md) — full `config.toml` reference, every `HMA_*`
  override.
- [cli.md](cli.md) — `hma` and `hma-warden` command reference.
- [apns.md](apns.md) — native iOS push: bring your own Apple Developer
  key.
- [ntfy.md](ntfy.md) — topic-based phone alerts, no Apple account;
  self-hosted option.
- [webhooks.md](webhooks.md) — outbound webhook payloads and HMAC
  verification.

## Trust & security

- [enforcement-models.md](enforcement-models.md) — tier 0/1/2, and what
  each one does NOT protect against.
- [warden.md](warden.md) — the Warden: verified, credential-holding
  enforcement outside the agent's sandbox.
- [secret-managers.md](secret-managers.md) — `env:`/`file:`/`cmd:` secret
  refs with Bitwarden/`rbw`, 1Password `op`, `pass`, and Vault recipes.
- [reference-sandboxed-agent.md](reference-sandboxed-agent.md) —
  reference architecture for a sandboxed agent (egress allowlist, warden
  placement).
- [../SECURITY.md](../SECURITY.md) — the threat model, the
  malicious-agent analysis, and how to report a vulnerability.

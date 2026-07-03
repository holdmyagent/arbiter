# Security Policy

## Threat model

Arbiter is designed to be **self-hosted by a single owner**, not operated as a
multi-tenant service. The assumptions below shape every default in the
codebase — read them before you deploy.

- **Single owner, shared tokens.** There is one admin (dashboard login) and a
  small number of bearer tokens: `agent_token` (agents create requests),
  `app_token` (the phone app/dashboard lists and decides requests), and
  `admin_password` (dashboard login, which mints a signed session cookie).
  These are shared secrets, not per-user credentials — anyone holding a
  token has that token's full authority. Treat `config.toml` as sensitive:
  it is written with `0600` permissions by `hma init` and should stay that way.
- **Expected network placement.** Arbiter has no built-in TLS. It is meant to
  run on a LAN, behind a private overlay network (e.g. Tailscale), or behind
  a reverse proxy that terminates TLS. Do not expose the raw server directly
  to the public internet without a proxy in front of it.
- **Fail-closed by default.** Every integration point is built to deny rather
  than silently allow when something goes wrong. `hma ask` and
  `hold_sdk.request_approval` return a non-approved result (and a non-zero
  process exit code from `hma ask`) on timeout, network failure, malformed
  server responses, or an unreachable server — never on success by default.
  A misconfigured or dead server blocks the guarded action instead of letting
  it through.
- **Auth on every data-bearing route.** All `/v1/*` API routes require a
  bearer token; the dashboard requires a signed, revocable session cookie.
  Per-IP sliding-window rate limiting throttles repeated auth failures on
  both the API (`429` after repeated bad tokens) and the dashboard login
  form. Dashboard state-changing routes (logout, device rename/delete, token
  rotation) require a CSRF token scoped to the active session.
- **Webhook integrity.** Outbound webhook notifications are HMAC-SHA256
  signed with the configured `webhook.secret`; receivers should verify the
  `X-Hma-Signature` header before trusting a payload.

## Supported versions

Only the latest released minor version receives security fixes. Upgrade
before filing a report if you're running an older release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do not open a public
issue. Email **kevin@holdmyagent.com** with:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal repro is very helpful).
- The version/commit you tested against.

You should get an acknowledgment within a few days. Once a fix is ready,
we'll coordinate on disclosure timing with you before it's made public.

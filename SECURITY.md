# Security Policy

## Threat model

Arbiter is designed to be **self-hosted by a single owner**, not operated as a
multi-tenant service. The assumptions below shape every default in the
codebase — read them before you deploy.

- **Single owner; per-identity tokens (0.4.0) or shared legacy tokens.**
  0.4.0 adds a token table: `hma token create NAME --role agent|warden|app`
  mints per-identity credentials, hashed at rest, with optional scopes
  (allowed `action_type`s, a severity cap), expiry, and one-command
  revocation. Requests are stamped with the creating identity
  (`requested_by`), and agents can read only their own requests. The legacy
  static `agent_token`/`app_token` in `config.toml` still work (deprecation
  warning at serve time) but are shared secrets: anyone holding one has its
  full authority. There is also an `admin_password` (dashboard login, mints a
  signed session cookie). Treat `config.toml` as sensitive: it is written
  with `0600` permissions by `hma init` and should stay that way.
- **Expected network placement.** Arbiter has no built-in TLS. It is meant to
  run on a LAN, behind a private overlay network (e.g. Tailscale), or behind
  a reverse proxy that terminates TLS. Do not expose the raw server directly
  to the public internet without a proxy in front of it.
- **Fail-closed by default.** Every integration point is built to deny rather
  than silently allow when something goes wrong. `hma ask` and
  `hold_sdk.request_approval` return a non-approved result (and a non-zero
  process exit code from `hma ask`) on timeout, network failure, malformed
  server responses, or an unreachable server. A misconfigured or dead server
  blocks the guarded action instead of letting it through.
- **Verified enforcement is available, not assumed.** Decisions are signed
  (Ed25519) and hash-bound to the exact action, and the warden tier executes
  them outside the agent's reach — but only if you deploy that tier. See
  [`docs/enforcement-models.md`](docs/enforcement-models.md) for what each
  tier does and does not enforce.
- **Auth on every data-bearing route.** All `/v1/*` API routes require a
  bearer token except `GET /health` and the public verdict keys at
  `GET /v1/keys`; the dashboard requires a signed, revocable session cookie.
  Per-IP sliding-window rate limiting throttles repeated auth failures on
  both the API and the dashboard login form; per-identity request-creation is
  rate limited (`[policy] rate_limit_per_minute`). Dashboard state-changing
  routes require a CSRF token scoped to the active session.
- **Webhook integrity.** Outbound webhook notifications are HMAC-SHA256
  signed with the configured `webhook.secret`; receivers should verify the
  `X-HMA-Signature` header before trusting a payload.
- **`callback_url` is an outbound-request capability — now allowlistable.**
  An agent-token holder can direct decision webhooks to URLs via
  `callback_url`. As of 0.4.0, `[notify] callback_allowlist` restricts the
  destinations (checked at create time and again at dispatch; redirects
  disabled). An empty allowlist preserves the legacy allow-all behavior and
  logs a loud startup warning the first time a callback is used — set the
  allowlist on any network you do not fully trust.
- **The dashboard session, not just the tokens, grants full authority.** An
  admin dashboard session can read both legacy tokens on the Settings page —
  an admin session transitively grants full agent and decision capability.
  Protect the admin password and session cookie accordingly.
- **Tenant isolation (0.4.0+).** Each tenant's state lives in an isolated
  per-tenant cell (own SQLite DB, own Ed25519 signing key, own notification
  egress config). Bearer→tenant routing rows are individually MAC'd (tamper
  fails closed), verdicts are audience-bound to their tenant, and
  cross-tenant reads/writes/streams are rejected by construction — enforced
  by a dedicated isolation test suite (`server/tests/isolation/`).

## The malicious-agent analysis

The agent is the adversary this design assumes — that is the point of an
approval gate. Four concrete attacks by a compromised or prompt-injected
agent, and what closes each as of 0.4.0:

| Attack | What it looks like | What closes it (0.4.0) |
|---|---|---|
| **Self-reported severity** | The agent labels a destructive action `low` so it slips into a muted notification band and expires quietly, or under-alerts the human. | `[policy.severity_floors]` raises the *effective* severity per `action_type` regardless of the claim; per-token `max_severity` scopes cap what an identity may even request; `deny_action_types` auto-denies whole categories. |
| **Consent phishing** | The request says "read config file"; the action performed is `rm -rf`. The human approves prose, not bytes. | Action-hash binding: the warden canonicalizes the exact action (final argv / URL+method+body hash / secret name), the server verifies and stores the SHA-256, and the human's decision returns as an **Ed25519-signed verdict bound to that hash**. The warden re-canonicalizes at execute time and refuses on drift; approvals are single-use (`consume`) and expire after `approval_ttl_seconds`. Requests created without a canonical action carry `action_hash: null` — verifiably **unbound**, so an executor can and should treat them as prose-only. |
| **Cross-agent reads** | One compromised sandbox reads every other agent's request payloads (commands, targets, context) through the shared token. | Per-identity tokens: requests are stamped `requested_by`, and DB-token agents/wardens can read only their own requests (404 otherwise). Revoke one identity without rotating the fleet. Legacy shared tokens keep the old visibility — one more reason they are deprecated. |
| **Notification flooding** | The agent spams creates to bury the one request that matters, train the human to rubber-stamp, or drain attention (approval fatigue). | Per-identity create rate limit (default 30/min, HTTP 429) plus duplicate-collapse (an identical pending request from the same identity returns the existing row instead of a new push). Flooding attempts are visible in the audit log as `rate_limited` events. |

## What HMA does NOT protect against

Honesty table — deploy accordingly:

| Not protected | Why / what to do instead |
|---|---|
| A compromised **arbiter host** | It signs the verdicts; whoever owns it owns the gate. Keep it patched, off the public internet, and outside the agent's trust domain. |
| A compromised **warden host** or a careless `warden.toml` | The warden holds the action credentials; its registry defines the action space. An over-broad action (e.g. a shell-through param) is arbitrary execution with a nicer UI. Params must stay enum/pattern-constrained. |
| **Agent colocated with the server config** | An agent running as the same user can read `config.toml` (0600 does not stop the same user), take both tokens, and approve its own requests. Never colocate — see [`docs/reference-sandboxed-agent.md`](docs/reference-sandboxed-agent.md). |
| **Cooperative tiers being skipped** | Tier 0/1 integrations (prompt convention, harness hooks) rely on the agent's runtime asking. Only the warden tier (2) makes approval physically enforced. |
| An **app-token / phone holder** | Whoever holds the decision credential can approve anything. The pairing QR embeds it — pair over trusted networks, guard the phone. |
| A human approving a **harmful but accurately displayed** action | HMA proves what was approved, by whom, bound to which bytes. It does not make the decision correct. |
| A **released secret** | The `secret` adapter hands the value to the agent once approved (single retrieval, receipted). Release is auditable, not reversible — scope such secrets tightly. |
| **Cleartext transport you chose** | No built-in TLS; bearer tokens transit however you deploy. Use a tailnet or TLS-terminating proxy (see deploy guides), and never `verify=False` in clients. |
| **DB-file tampering** | The audit table is append-only by convention; anyone with filesystem access to the SQLite file can rewrite history. Hash-chained audit is deliberately deferred (see CHANGELOG); restrict file access meanwhile. |

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

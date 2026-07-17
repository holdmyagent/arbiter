# Roadmap

Direction, not promises. [Issues](https://github.com/holdmyagent/arbiter/issues)
are the source of truth for status, and [`CHANGELOG.md`](CHANGELOG.md) is the
record of what actually shipped.
1.0 = the public launch; version lines converge there (server / sdk / warden /
iOS all 1.0.0).

## Now (0.4.x)

- **Token-hash index** — index the hashed-token lookup so bearer resolution
  stays O(log n) as the per-identity token table grows.
- **Rate-limit-before-policy ordering** — check the per-identity create rate
  limit before running policy evaluation, so a flooding identity is throttled
  up front instead of burning policy work and audit rows first.
- **Streaming audit export** — cursor the `/v1/audit/export` read instead of
  materializing every audit row in memory before the response starts.
- **Homebrew tap bump to 0.4.0** — update the tap formula once PyPI's
  new-release cooldown passes, and add a formula for `hold-warden`.

## Next (0.5)

- **Dashboard: cross-tenant admin views** — one operator console across every
  tenant cell (today the dashboard binds to the `default` tenant only).
- **Approval escalation** — a request nobody answers re-notifies on a
  secondary channel before its TTL runs out, instead of silently expiring.
- **Slack / SMS channels** — join APNs, ntfy, and webhooks as first-class
  notification channels.
- **iOS 0.6 train** — receipts and executed-state UI, multi-server pairing
  via pair-codes, and the decoded canonical action rendered on the
  authorization slip.

## Later

- **Multi-approver / quorum** — require N-of-M humans for the highest
  severities instead of a single decision.
- **Passkey (WebAuthn) browser approvals** — decide from a browser with a
  passkey ceremony, for people without the paired phone at hand.
- **Stream-consumer menu-bar app (macOS)** — a menu-bar client driven by
  `/v1/stream` for glanceable pending-request state on the desktop.
- **Android** — bring the paired-device experience beyond iOS.
- **Hash-chained audit rows** — make the audit log tamper-evident, not just
  append-only.
- **Authenticated Prometheus `/metrics`** — first-class scrape endpoint for
  request/decision/notifier metrics.
- **mTLS** — mutual TLS between agents, wardens, and the server for
  deployments that want more than bearer tokens.
- **Warden: Go static-binary port** — a single-binary warden with no Python
  runtime on the trusted host.
- **Warden: MCP adapter** — expose the propose/execute surface as MCP tools
  so MCP-native agents can use the warden directly.
- **Warden: Postgres backend** — an alternative to SQLite for teams running
  several wardens against shared infrastructure.
- **homebrew-core submission** — once there's enough traction to clear
  homebrew-core's notability bar.

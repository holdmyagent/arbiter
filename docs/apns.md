# Native push via APNs (bring your own key)

Arbiter can push straight to a paired iOS device through Apple's APNs,
giving you a lock-screen alert instead of relying on the ntfy app. This
needs your own Apple Developer Program membership and your own APNs key
— Arbiter is self-hosted per owner, and Apple's push service is scoped to
a specific app bundle ID and Team ID, so there's no shared credential
that would let one server push to everyone's copy of the client app. If
you don't want to deal with any of that, [`docs/ntfy.md`](ntfy.md) gets
you phone alerts with no Apple account at all.

**This also means: to use native APNs push, you need a client app built
under your own bundle ID and signed with your own Apple Developer
account** — a copy of the App Store app published under someone else's
bundle ID can't receive pushes signed with your key, because
`apns-topic` (the bundle ID) has to match the app that's actually
installed. If you're building your own client (or extending the existing
one), the wire contract it needs to speak is at the bottom of this page.

## 1. Create an APNs key

1. In the [Apple Developer portal](https://developer.apple.com/account/resources/authkeys/list),
   go to **Certificates, Identifiers & Profiles → Keys → +**.
2. Name it (e.g. "Arbiter push"), check **Apple Push Notifications
   service (APNs)**, and register it.
3. Download the `.p8` file **immediately** — Apple only lets you download
   it once. Note the **Key ID** shown on the key's detail page.
4. Note your **Team ID** — top-right of the Developer portal, under your
   name/organization, or on the key's detail page.

## 2. Configure Arbiter

Store the `.p8` file somewhere Arbiter's process can read but nothing
else can (`chmod 600`), then fill in `[notify.apns]` in `config.toml`:

```toml
[notify.apns]
key_path = "/etc/holdmyagent/AuthKey_ABCD123456.p8"
key_id = "ABCD123456"
team_id = "TEAMID1234"
bundle_id = "com.example.myholdmyagentbuild"   # your build's bundle ID
sandbox = false   # true for a Debug/Xcode build, false for TestFlight/App Store
```

Or set it via environment variables (handy for Docker/systemd, and takes
priority over `config.toml`):

```bash
export HMA_APNS_KEY_PATH=/etc/holdmyagent/AuthKey_ABCD123456.p8
export HMA_APNS_KEY_ID=ABCD123456
export HMA_APNS_TEAM_ID=TEAMID1234
export HMA_APNS_BUNDLE_ID=com.example.myholdmyagentbuild
export HMA_APNS_SANDBOX=false
```

Arbiter treats APNs as configured once `key_path`, `key_id`, and
`team_id` are all non-empty (`hma status` shows `apns=on`/`off`). Until
then, push sends are silently skipped — no error, just a log line — so
ntfy/webhook notifiers keep working on their own.

### `sandbox` — which one do I need?

Apple runs two separate push environments, and a device token from one
is meaningless in the other:

- **`sandbox = true`** — `api.sandbox.push.apple.com`. Use this while
  running the app from Xcode with a Development provisioning profile.
- **`sandbox = false`** — `api.push.apple.com` (production). Use this for
  a TestFlight or App Store build.

If pushes silently fail (device pairs fine, but no notification
arrives), this is the first thing to check — it's the most common APNs
misconfiguration.

## 3. Pair a device

Once APNs is configured, pairing works the same way it does without it:
run `hma pair` (prints a QR in the terminal) or open `/dashboard/pair`,
and scan it with the client app. The client registers itself with
`POST /v1/devices`, which is what makes it a push target.

## 4. Test it

```bash
hma ask "APNs test" --severity high --ttl 60
```

If the paired device doesn't get a push, check the server log —
`send_with_retry` logs a warning with the raw APNs error after it
exhausts its retries (2 by default, backing off `0.5s`/`1s`), and
`arbiter.apns` is the logger name to grep for. Common causes: a `400`
(topic/bundle ID mismatch — check `bundle_id` matches your build
exactly), a `403` (bad key/key ID/team ID), or a `410` (the device
token is stale — re-pair).

## Wire contract, for building your own client

This repo doesn't ship iOS app source — a client just needs to speak this
API:

- **Pair**: read `host`/`token` out of the `holdmyagent://pair?host=<url>&token=<app_token>`
  deep link (from the QR/`hma pair`), then `POST {host}/v1/devices` with
  `Authorization: Bearer <app_token>` and a JSON body:
  `{"apns_token": "<device push token, hex>", "name": "My iPhone",
  "min_severity": "low", "notifications_enabled": true, "sound": true}`.
- **Receive a push**: the APNs payload's `aps.alert` has `title`/`body`;
  the top-level payload also carries `request_id` and `severity`. A
  push's `click` action (via ntfy) or your own notification handling (via
  APNs) should open `holdmyagent://request/<request_id>` in the app.
- **Decide**: after your own in-app auth step (Face ID/Touch ID — this is
  what actually makes a decision trustworthy; there's no server-side
  enforcement of "a human approved this," only whatever your client
  requires before it calls this endpoint), `POST {host}/v1/requests/{id}/decision`
  with `Authorization: Bearer <app_token>` and `{"decision": "approve"}`
  or `{"decision": "deny"}`.
- **List/poll**: `GET {host}/v1/requests?status=pending` (app token) to
  show a live queue; `GET {host}/v1/requests/{id}` (app or agent token)
  for a single request's current state.

The dashboard's `/v1/stream` WebSocket (bearer token or session cookie)
broadcasts `request.created`/`request.decided`/`request.expired`/`device.updated`
events if you'd rather push-update a client UI than poll.

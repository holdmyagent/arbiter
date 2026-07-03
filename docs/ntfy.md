# Phone alerts via ntfy

[ntfy](https://ntfy.sh/) is the easiest way to get a push notification on
your phone when an agent asks for approval — no Apple Developer account,
no APNs key, works on Android and iOS. Arbiter posts a message to a topic
you choose; you subscribe to that topic in the ntfy app.

## Why topic naming matters

ntfy topics on the public `ntfy.sh` server are **unauthenticated by
default**: anyone who knows (or guesses) your topic name can subscribe
and read every message sent to it, and can publish their own messages to
it too. A request's ntfy notification includes its title, target, and
description — exactly the kind of thing you don't want a stranger
reading, and a forged message on a guessable topic could trick you into
thinking an approval request exists when it doesn't (or hide a real one
in noise).

**Use a long, random, unguessable topic name** — not something like
`kevin-arbiter` or `my-approvals`. Generate one instead of picking one:

```bash
python3 -c "import secrets; print('hma-' + secrets.token_hex(16))"
# hma-7a2f9c1e4b8d03a6f5e21c9047b8d3ac
```

Treat that string like a credential: don't post it in a public issue,
screenshot, or chat log. Anyone who has it can read (and inject) your
approval notifications for as long as you keep using it — if it ever
leaks, generate a new one and update `config.toml`.

## Configure Arbiter

```toml
[notify.ntfy]
url = "https://ntfy.sh"
topic = "hma-7a2f9c1e4b8d03a6f5e21c9047b8d3ac"
token = ""   # optional — see "self-hosting" below
```

Or via environment variables:

```bash
export HMA_NTFY_TOPIC="hma-7a2f9c1e4b8d03a6f5e21c9047b8d3ac"
```

Setting a non-empty `topic` is what turns ntfy on — `hma status` will
show `ntfy=on` once it is. Restart `hma serve` (or reload the config) to
pick it up.

## Subscribe on your phone

Install the ntfy app ([iOS](https://apps.apple.com/app/ntfy/id1625396347),
[Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy)),
add your server (`https://ntfy.sh` unless self-hosting), and subscribe to
your topic. Notifications carry:

- **priority** mapped from the request's severity (`low`→2 through
  `critical`→5), so critical requests interrupt more insistently than
  low-severity ones.
- **title** in the form `[SEVERITY] <request title>`.
- a **click** action of `holdmyagent://request/<request-id>` — if
  **Hold My Agent for iOS** is installed and paired, tapping the
  notification deep-links straight into that request's detail page. If
  it isn't installed, the tap just does nothing special (no crash — it's
  an unrecognized URL scheme to the OS) and you can still see the request
  in the dashboard.

## Test it without waiting on an agent

```bash
curl -d "just testing" https://ntfy.sh/hma-7a2f9c1e4b8d03a6f5e21c9047b8d3ac
```

If that shows up on your phone, your subscription is correct and any
delivery failure you see afterward is on the Arbiter/config side, not
ntfy. Then trigger a real one:

```bash
hma ask "ntfy test" --severity critical --ttl 60
```

## Self-hosting ntfy

If you'd rather not depend on the public `ntfy.sh` server (or want real
auth instead of a secret topic name), [self-host
ntfy](https://docs.ntfy.sh/install/) — it's a single static Go binary or
a Docker image:

```bash
docker run -d --name ntfy -p 8080:80 -v /var/lib/ntfy:/var/cache/ntfy \
  binwiederhier/ntfy serve --cache-file /var/cache/ntfy/cache.db
```

Point Arbiter at it and, since it's now a server you control, you can
require a token to publish/subscribe instead of relying on topic secrecy:

```bash
# on the ntfy server: create a user + topic-scoped ACL, then an access token
ntfy user add --role=user hma-bot
ntfy access hma-bot 'hma-*' rw
ntfy token add hma-bot
```

```toml
[notify.ntfy]
url = "https://ntfy.example.com"
topic = "hma-alerts"      # can be a normal name now — the token is what protects it
token = "tk_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Arbiter sends `token` as an `Authorization: Bearer` header on every
publish; configure your ntfy server's ACLs so only that token (and
whichever accounts you trust) can read the topic.

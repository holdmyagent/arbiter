# Enforcement models: how strong is your "no"?

**HMA is the gate; the warden decides whether the agent walks through it or merely promises to.**

Hold My Agent can be wired into an agent at three tiers. They share the same
server, phone app, and audit log — what changes is *who has to cooperate* for
a denial to actually stop the action. Pick the weakest tier that matches how
much you trust the agent; be honest with yourself about what each one does
not do.

| | Tier 0 — prompt convention | Tier 1 — harness hook | Tier 2 — warden |
|---|---|---|---|
| Who enforces | The model's goodwill | The agent harness (hooks) | A separate trusted daemon |
| Agent must cooperate? | Entirely | Only until it can touch its own config | No |
| Verdict artifact | None read | Exit code / status string | Ed25519-signed, action-hash-bound, single-use |
| Right for | Demos, trusted scripts | Day-to-day coding agents | Sandboxed / untrusted / internet-facing agents |

## Tier 0 — prompt convention

You tell the agent (in its system prompt or instructions): *before any
irreversible action, run `hma ask` and proceed only on approval.* Nothing
else changes. This is better than nothing — a well-behaved model will
comply, you get pushes, decisions, and an audit trail.

```text
Before any destructive or irreversible action (deploys, deletions, sends,
payments), run: hma ask "<what you are about to do>" --severity high
and proceed only if it exits 0.
```

**What tier 0 does NOT protect against:**

- A prompt-injected, confused, or misaligned agent simply not asking.
- Asking about one thing and doing another (nothing binds the approval to
  the action).
- Acting before the human answers, or ignoring a denial.
- Anything at all if the instructions get truncated, overridden, or jailbroken.

## Tier 1 — harness hook

The agent's runtime (not the model) runs a hook before executing a tool call
and blocks on the hook's verdict: agent pre-exec / pre-tool hooks, git
`pre-push`, CI gate steps, MCP middleware. The hook shells out to `hma ask`
(exit `0` approved / `1` denied-expired / `2` error — every nonzero blocks)
or calls `hold_sdk.request_approval`. See
[`agent-hook.md`](agent-hook.md) for a complete worked example.

This is *host-enforced*: the model cannot skip the hook, because the harness
runs it unconditionally.

**What tier 1 does NOT protect against:**

- An agent with write access to its own hook configuration or settings
  files (it can remove or neuter the hook — lock hook config with managed
  settings where the harness supports it).
- An agent that can execute outside the hooked surface (a raw shell, a
  different tool, a subprocess the hook does not see).
- Approval of a *misdescribed* action: the hook gates the command string it
  saw, but nothing cryptographically binds the human's "yes" to the bytes
  that later run.
- A compromised host: whoever owns the machine owns the harness and its
  hooks.

## Tier 2 — the warden (verified enforcement)

[`hold-warden`](warden.md) is a small trusted daemon *outside* the agent's
sandbox. The agent holds no action credentials at all — it can only
*propose* an action from a registry you wrote (`warden.toml`), with
constrained, validated parameters. The warden:

1. canonicalizes the exact action (final argv / URL+method+body hash /
   secret name) and creates the arbiter request with its SHA-256;
2. waits for the human's decision, which comes back as an **Ed25519-signed
   verdict bound to that action hash**;
3. verifies the signature against the pinned server key, **re-canonicalizes
   what it is about to execute**, and refuses on any drift;
4. **consumes** the approval atomically on the server (single-use; stale
   approvals are refused past a freshness window);
5. executes via a command/http/secret adapter and records a receipt.

A fully compromised agent can still: propose registry actions with valid
constrained params, and spam proposals (rate-limited, deduplicated). It can
never: execute anything unapproved, alter an action after approval, replay
an approval, read other agents' requests, or see the warden's credentials.

**What tier 2 does NOT protect against:**

- A compromised **warden host** or **arbiter host** — they are the trust
  domain. Keep them outside the sandbox and away from the agent's user (see
  [`reference-sandboxed-agent.md`](reference-sandboxed-agent.md)).
- A bad **registry**: if `warden.toml` defines an over-broad action (say,
  `argv = ["bash", "-c", "{cmd}"]` — do not do this), approval-gated
  arbitrary execution is still arbitrary execution. Registry authorship is
  part of your TCB; keep params enum/pattern-constrained.
- A human approving a harmful action that was **accurately displayed**.
  HMA proves the human saw and approved exactly these bytes — it does not
  make the human right.
- Actions the agent can perform **without** the warden: the sandbox's own
  egress/exec policy has to force all privileged paths through the warden,
  or the gate is beside the point.
- Whoever holds the **app token** (the phone credential) can approve
  anything. Guard the phone and the pairing QR.
- A released secret (the `secret` adapter) is in the agent's hands after
  approval — release is single-use and receipted, but not un-ringable.

## Choosing

Start at tier 1 for any real agent — it is one hook and one `hma ask`. Move
to tier 2 when the agent is sandboxed, internet-exposed, handles credentials
you care about, or when "the agent promised" stops being a sentence you can
say with a straight face. Tier 0 is for kicking the tires.

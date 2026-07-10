# Design — Multi-tenant Arbiter: cell-per-tenant structural isolation (V1)

Status: **reviewed & locked** (2026-07-07; §18 decisions resolved). Produced by a design brainstorm + a five-vector adversarial
red-team (cross-tenant leak / eviction+stream races / routing+auth / key-confusion / backup+availability)
plus a completeness critic. The red-team's verdict: the design **survives** as a structural-isolation
architecture, but only with the hardening in §5–§14 folded in — several holes were concrete cross-tenant
breaks in the *shipped* single-tenant code that a naive port would inherit. This spec is the source of
truth for the implementation plan. Do not re-scope without re-running the isolation red-team.

## 1. Goal & positioning

Let one arbiter *process* safely broker high-stakes, irreversible actions for **many client businesses at
once**, so a small agents-as-a-service operator can run the client-approves-on-their-phone model without
one VM per client. The product promise is **structural isolation**: cross-tenant read / approve / push /
verdict / audit is *impossible by construction*, not merely forbidden by a query filter. That promise is
the thing being sold, so it is enforced by design invariants (§15) and proven by a merge-gating adversarial
test suite (§16).

The V1 build is the **isolation core** + fleet backup + the minimal secure warden key-rotation needed so a
per-tenant key change does not brick a client. Deferred (do not build here): cross-tenant admin dashboard,
approval no-show escalation, non-iOS (Slack/SMS) approval channel, billing aggregation, quorum/maker-checker.

## 2. Threat model

**Defended against:** a tenant holding valid credentials trying to reach another tenant's data/approvals; a
compromised or prompt-injected agent token; a malicious tenant *operator* crafting verdicts/rotation
records; a network MITM of the warden↔arbiter path; a client device trying to receive another tenant's
pushes; resource-exhaustion used to *force* an isolation-breaking race.

**Explicitly NOT defended (documented, out of scope):** a compromised arbiter host or a compromised
control-plane admin credential — whoever can write `control.db` or read every tenant's on-disk key
directory owns the fleet. Custody concentration (the operator holds every client's action credentials) is a
business risk mitigated operationally (client-held vaults via `cmd:` resolvers, per-tenant host hardening,
insurance), not by this design.

## 3. Architecture — "cell per tenant"

One arbiter process serves N tenants. Each tenant is an isolated **cell**. **No process-global object is
authoritative for any tenant-scoped surface** — this is the master invariant the red-team's two criticals
both reduce to. A cell **owns**, and is the *only* path to:

- its **`Database`** (one SQLite file, one connection, one `threading.RLock`);
- its **Ed25519 signer** (private key + `kid`);
- its **`Hub`** (the WebSocket event bus — *not* on `app.state`);
- its **`Dispatcher`**, including that dispatcher's **webhook / ntfy / callback-allowlist config** (not the
  process `cfg`);
- its **rate limiters** (create + login);
- its **device set**.

`app.state` holds nothing per-tenant. The `ExpiryScheduler` (§6) is process-wide but binds a cell's own
signer/db *per firing*. Every request handler is handed exactly one cell (resolved from the caller's
credential, §4) and can reach no other; because there is no shared row store, a forgotten `WHERE` clause has
nothing to leak from.

## 4. Tenant = token, and the `control.db` router

Every token is minted into exactly one tenant. `resolve_identity(bearer)`:

1. `sha256(bearer)` → look up **`control.db` `token_route(token_hash → tenant_id)`** (full 64-hex key only);
2. read `tenants.disabled_at` **on this same resolution** (never cached on the cell);
3. `acquire(tenant_id)` the cell (§5);
4. **re-run full validation inside the cell** — `get_token_by_hash(full-64-hex)` against the cell's *own*
   `tokens` table, deriving role/expiry/revocation **only** from that cell row;
5. return `Identity(tenant_id, name, role, scopes)`.

**No endpoint accepts a tenant as a path segment, query param, header, or any caller-supplied hint.** Tenant
is always derived from the credential.

`control.db` is a **router only**. It holds `tenants(tenant_id, dir, disabled_at, epoch)` and
`token_route(token_hash, tenant_id)` — nothing else: no scopes, verdicts, policies, requests, devices, or
scheduling state. Read-only on the hot path; written only at mint/revoke/tenant-lifecycle.

Router hardening (red-team):
- Store **only** `(full-64-hex token_hash, tenant_id)`. Never role/name/scopes; never route or shard on a
  truncated hash (birthday-collision → cross-tenant role grant). A route hit with **no matching cell token**
  is a hard, generic 403 — the router is a hint, the cell is the authority.
- **Row integrity:** each `token_route` / `tenants` row carries a MAC over `(token_hash, tenant_id, epoch)`
  verified at resolve, so a tampered or rolled-back registry fails closed rather than silently re-pointing a
  cell.
- **Write authorization:** `control.db` is writable *only* via the admin-credentialed provisioning CLI (its
  own admin credential, **never** the app token). A single unauthorized `token_route` insert = total
  cross-tenant compromise, so this boundary is load-bearing.
- **`tenant_id` charset** is strictly `[a-z0-9-]`, never string-interpolated into SQL or path joins
  (parameterized queries; realpath-under-a-fixed-root assertion for `dir`).

## 5. Cell lifecycle (the sharpest correctness surface)

`TenantRegistry` is a **bounded LRU** of open cells, cap `max_hot_cells`. A cell opens lazily on the first
request resolving to it; its connection is WAL-checkpointed and closed on eviction.

- **Single-flight `acquire(tenant_id)`.** Atomically install a Future/opening-sentinel in the map **before
  any `await`**; all concurrent callers await the *same* future and receive the *same* object. The future
  resolves **only** after the cell is fully initialized (WAL set + every migration committed + signer +
  dispatcher + hub built). Construct off to the side and swap the completed object in atomically. **Exactly
  one `Database` (one connection, one RLock) per tenant dir at any instant** — a non-single-flight port
  yields two WAL writers on one file, the exact `sqlite3.InterfaceError`/corruption the shipped consume path
  already fought. No caller ever observes a half-migrated cell.
- **Refcount — exactly-once, bind-by-object, background-inclusive.** A live stream / HTTP request / scheduler
  pass / spawned background task (outbox publish+retry, expiry sign) pins its cell (`refcount++`) for its
  entire lifetime and **binds the cell by object** (so a reopened twin can never be substituted under a live
  holder). The pin is released **exactly once** on every exit path via a single idempotent `finally` — no
  separate decrement on a disconnect branch. Eviction is gated on `refcount == 0` and **never** closes a
  connection any live holder or background task holds; eviction and shutdown await those tasks.
- **Never block a request on eviction.** At cap with all cells pinned, go temporarily over-cap and log
  (an ops signal to raise the cap), but subject to the FD budget below.
- **FD budget is a runtime invariant, not just a startup check.** Startup asserts
  `max_hot_cells*3 + headroom < RLIMIT_NOFILE`; at runtime, concurrent open cells (hot **plus** transient
  scheduler expiry-opens) plus a **per-tenant stream cap** keep `open_cells*3 + headroom < RLIMIT_NOFILE` at
  all times. Over-budget **sheds/queues rather than failing another tenant's cell open** (otherwise tenant
  A's leaked streams deny tenant B its cell — a cross-tenant DoS). **Defaults (sized to a 1024
  `RLIMIT_NOFILE`):** `max_hot_cells = 64`, per-tenant `stream_cap = 5` → ≤8 FDs per hot cell (3 SQLite +
  ≤5 streams), so ~512 FDs at full cap against a ~874-FD usable budget (after reserving ~150 for listeners/
  logging/background tasks) — a ~109-cell ceiling, leaving large headroom while supporting *hundreds* of
  provisioned tenants given the low-frequency nature of approvals.
- **Lock hierarchy (deadlock/DoS defense).** One process serves the whole fleet, so a single held-lock stall
  is a fleet-wide outage. Publish a strict order: **registry map lock is always outer; the per-cell DB RLock
  is inner and is NEVER held across an `await`, across `acquire()`/`evict()`, or across a
  migration/checkpoint.** Open/close are serialized by the single-flight future, not by the DB RLock. All
  lock acquisitions are timeout-bounded so a stuck holder degrades one tenant rather than deadlocking the
  process.
- **Immutable tenant epoch + snapshot-consistent resolution (TOCTOU).** Every `tenants` record carries a
  monotonic, never-reused `epoch`; **delete is a tombstone** (epoch and dir are never recycled).
  `resolve_identity` captures `(tenant_id, epoch)`; route-lookup + disabled-check + cell-bind run against one
  consistent `control.db` read; the bound cell asserts `cell.epoch == resolved.epoch` before serving, so a
  delete+recreate or dir-rebind racing a live resolution fails closed instead of inheriting stale authority.

## 6. ExpiryScheduler (one heap replaces N per-cell sweepers)

Holds **only** `(expires_at, tenant_id, request_id)` — never a cell/db/key reference. Handlers push on
request-create. When the earliest fires, the scheduler `acquire()`s + pins the current cell and uses **that
cell's** signer (`cell.kid`/`cell.signing_key`) and `cell.db` exclusively for `set_verdict`/`add_audit`/
`outbox`; it pins across the whole pass and releases only after commit. **Never sign with a captured/global
key** (a shared "scheduler key" is a cross-tenant forgery oracle; the default/A key on B's expiry is an
availability break).

Durability (edge-triggered heaps lose events, so add level-triggering):
- Seed the heap at startup with a bounded transient scan (open each cell, `SELECT` pending expiries, close),
  **and** keep a bounded **level-triggered rescan** (rolling over tenants with pending rows) so a dropped
  heap-push cannot leave a request un-expired forever.
- On decision, push a **second** heap entry at `decided_at + approval_ttl` and have the seed/rescan also
  select `approved AND unconsumed` rows, so a cold cell's approval-staleness deadline still flips.
- Make the pending→expired flip and the expiry-verdict sign **atomic** (single transaction) — or have
  recovery re-scan `status='expired' AND verdict_jws IS NULL` — so a SIGTERM/eviction between two commits
  cannot leave a permanent verdict 404.
- **Fairness + FD accounting:** bound per-tick work per tenant (round-robin) so one tenant's large short-TTL
  batch cannot starve another's due expiries; count scheduler cold-opens against the FD budget.

## 7. Per-tenant crypto, verdict tenant-binding, warden rotation

- **Per-tenant signing key.** Each cell has its own Ed25519 key; `GET /v1/keys` returns **that tenant's**
  JWKS, derived from the **refcount-pinned cell bound to the request for the handler's full lifetime**, with
  `assert identity.tenant == cell.tenant_id` before serving. `acquire()` must not return a cell
  mid-eviction/reopen. (A pairing fetch handed a neighbor's JWKS pins the wrong key → A's verdicts fail
  forever, and a later MITM of the neighbor's verdicts would verify.)
- **Bind tenant into the verdict itself (defense-in-depth — do not rest on key distinctness).** Today a
  verdict carries zero tenant identity (`aud="hma-verdict"`, `iss="hma"` are global constants), so cross-
  tenant crypto is rejected *only* because raw keys differ — any accidental key coincidence (restore into
  the wrong dir, a clone-tenant helper, the shared-dir bug in §5/provisioning) is a *silent* cross-tenant
  forgery. Fix: `aud = "hma-verdict:{tenant_id}"` **plus** an `hma.tenant_id` claim, and a **tenant-
  namespaced kid** (`kid = "{tenant_id}:{hash}"`, widening the 32-bit kid against grind-collision). The
  warden checks audience/tenant_id against its **own paired tenant**, turning a silent breach into a loud
  rejection.
- **Warden trust anchor = the LOCAL pin (root-of-trust, not the served set).** Rotation publishes the new
  key into the tenant's `/v1/keys` set alongside the old for a grace window, plus a **rotation record signed
  by the OLD key**. The warden verifies rotation records and verdicts **only against locally pinned key
  bytes** (from `hma-warden init`); the served set is **candidate material only**. A new kid is adopted iff
  the record (a) verifies under the **local** pin, (b) carries `tenant_id == paired tenant`, (c) has a
  **strictly monotonic rotation seq > last-adopted** within a short **expiry**. Reject: a record verified
  against a *served* key, a replayed/older-seq/expired record, and "old key absent from the served set" as a
  reason to accept the new one (old-key retirement is driven by a signed event recorded locally, never
  inferred from absence). Reject any served entry whose kid matches a pinned kid but whose bytes differ.
  Manual `hma-warden init` re-pair is the lapsed-grace-window fallback.

## 8. Streams and long-lived sessions

- **`/v1/stream` resolves tenant via `resolve_identity(bearer)` — the identical router path as HTTP — and
  binds the socket to that cell's `Hub` (by object) and pins the cell BEFORE `ws.accept()`.** It subscribes
  ONLY to `identity.tenant`'s `cell.hub`. Every publish site (create/decide/expiry) publishes to the
  *acquired* cell's hub. There is no global hub and no caller-supplied tenant hint.
- **Liveness / half-open defense.** Bound every socket send with `asyncio.wait_for` and an application-level
  ping/pong deadline that hard-closes a dead peer; the refcount release runs on **every** exit path via a
  context-manager `finally` a stuck send cannot skip. **Per-tenant concurrent-stream cap** so blackholed
  sockets cannot pin cells past the FD budget.
- **Disable/revoke actively tears down live sessions.** `tenants.disabled_at` is read on every resolution
  (never cached on the cell). Disable/token-revoke pushes a close sentinel to the cell's hub (or bumps a
  cell/token generation the stream re-checks each heartbeat) so open streams `ws.close()` and long-polls
  drop; a pinned cell does **not** exempt its sessions from disable.

## 9. Notify / egress isolation

Each cell constructs its **own** `Dispatcher(db=cell.db)` **and** takes `webhook.url` / `ntfy` /
`callback_allowlist` from **per-cell config**, never the process `cfg` (otherwise every tenant's request/
decision bodies egress through one operator/tenant-A sink). Every outward action (callback/ntfy/webhook) is
**idempotent under a per-`(tenant, request, event)` dedupe key**, and the at-least-once outbox re-drain is
bounded to **process-restart only — never triggered by cell-open** (cells cycle hot constantly; a cell-open
re-drain re-fires a payment callback on every churn).

## 10. Device enrollment binding (the phone surface)

Governing *how a device row enters a cell* is a first-class cross-tenant target (its pushes carry request
titles/payloads). Device/APNs-token registration requires a **tenant-bound, single-use, short-expiry pairing
credential minted inside the tenant's cell**; the device row is written **only** to the acquired cell's db;
push tokens are namespaced per tenant; **no global device table**. The enrollment endpoint derives tenant
from the pairing credential, never a caller-supplied hint; replayed or cross-tenant pairing codes are
rejected. *(The iOS app is out-of-tree; the arbiter-side enrollment contract is specified here, the app
change is a coupled iOS work item flagged in §17.)*

## 11. Observability isolation

The process serves all tenants, so shared sinks are cross-tenant channels. **No tenant PII/payload** (title,
description, request body, dir path, `no such column`-style schema internals) ever enters a shared log or a
**client-visible error body** — client errors are generic and constant, and route-miss / in-cell-invalid /
disabled-tenant all return an **identical generic 403 with equalized timing** (defeats the cold-open "is
this a real route key" oracle and the tenant-existence oracle). Per-tenant operational logs go to a
tenant-scoped, access-controlled sink. `/metrics` is not shipped today; **if/when added it must be
authenticated and expose only fleet-aggregate counters or enforce per-tenant authz on label reads** (per-
tenant rids/queue-depth/429/hot-gauge labels on a public scrape = a live cross-tenant topology map).

## 12. Backup / restore — fail-closed for credentials AND consumption

`hma admin backup` snapshots each cell online (SQLite backup API / `VACUUM INTO`, internally consistent,
zero-downtime) then `control.db` **last**. Ordering makes the anomaly fail-*closed*:

- **Credentials:** a token is valid only if **present-and-unrevoked in BOTH** the router and cell snapshots.
  Mint writes cell-row first then router-row (a ghost fails closed). Revoke writes the in-cell `revoked_at`
  **and** removes/flags the router row so the last-captured snapshot sees it. A startup **reconciler** drops
  router rows lacking a live cell token; restoring a cell invalidates any router route newer than the cell
  snapshot. *(Guards against restore resurrecting a deliberately-killed leaked token.)*
- **Consumption (replay):** a consumed+executed approval must **never re-execute after a rollback**. The
  cells-first/router-last smear can otherwise restore an `approved+unconsumed` snapshot of an action that
  already moved money, and the time+status consume guard re-passes if `decided_at+ttl` is still future.
  **Chosen mechanism (V1): any cell restore forces re-mint / invalidation of that tenant's in-flight
  approvals** (all `pending` and `approved`-unconsumed rows) — the agent must re-propose, pushing the
  restore-replay complexity to its retry loop where it belongs. This is fail-closed by construction and
  avoids the state-coordination of a router-captured consumption watermark (deferred to a later version).
  The invalidation and its replay window are stated explicitly in ops docs.

## 13. Rate limiters

Key the create/login limiter by **`(tenant_id, name)`** (never bare `name` — `tokens.name` is unique only
per-cell, so two tenants' `agent` tokens would share one bucket → cross-tenant budget exhaustion + a 429
activity oracle), or make them per-cell objects. The **auth limiter** keys on a **trusted** identifier
(validated XFF from a known proxy, or the resolved `tenant_id` post-routing) — **never** a shared-ingress
source IP as the sole key (behind one ingress, 10 bad tokens would 429 the whole fleet's auth).

## 14. Provisioning, back-compat, CLI

- `hma tenant create <name>` (admin-credentialed): realpath-canonical, unique, **non-overlapping** dir (no
  prefix/symlink/`..` of another — enforced at mint AND re-validated at cell open, because a shared dir hands
  two cells the same key → silent cross-tenant forgery); fresh cell DB migrated; own signing key minted;
  registered with a fresh monotonic epoch; first app token + warden token printed. `hma tenant list`,
  `hma tenant disable` (flip `disabled_at`, actively drop live sessions), `hma tenant delete` (**tombstone**
  — epoch/dir never recycled). `hma token create` becomes tenant-scoped.
- **Back-compat:** a single-tenant install is a registry with one cell named `default`; the legacy
  `cfg.auth.app_token` resolves **strictly** to `default` and nothing else; existing devices map to
  `default`; migration wraps today's single DB as the `default` cell. iOS 0.5.0 / hold-sdk 0.2.1 keep working
  unchanged.

## 15. Load-bearing invariants (the spec's assertions; each has a test in §16)

1. No process-global object is authoritative for any tenant-scoped surface (Database, signer/kid, Hub,
   Dispatcher+egress config, rate limiters, scheduler per-firing binding are cell-owned; `app.state` holds
   nothing per-tenant).
2. Tenant is derived from the credential on **every** authenticated surface (`/v1/stream`, `/v1/audit/export`,
   dashboard sessions included); legacy app_token → strictly `default`; no endpoint names or accepts a tenant.
3. `acquire()` is true single-flight: exactly one `Database` per tenant dir at any instant; the cell is never
   observable until fully initialized.
4. Every live holder (stream/request/scheduler/background task) binds its cell **by object** and pins it for
   its lifetime; released exactly once on every exit path; evicted only at `refcount==0`; a reopened twin is
   never substituted under a live holder.
5. `disabled_at` is read on every resolution and never cached; disable/revoke actively closes live streams
   and long-polls; a pinned cell does not exempt its sessions.
6. The router stores only `(full-64-hex hash, tenant_id)` (+MAC over `(hash,tenant_id,epoch)`); the cell is
   the sole authority for role/expiry/revocation; a route hit with no matching cell row is a hard 403;
   nothing routes/shards on a truncated hash; `control.db` is writable only via the admin CLI.
7. Every tenant dir is absolute, realpath-canonical, unique, non-overlapping; each cell's key is distinct —
   enforced at mint AND at open.
8. Verdict verification is kid+audience bound per-tenant (`aud=hma-verdict:{tenant_id}` + `hma.tenant_id`
   claim + tenant-namespaced kid); the warden checks both against its paired tenant; isolation never rests on
   key distinctness alone.
9. The warden's trust anchor is its LOCAL pin; the served `/v1/keys` set is non-authoritative; new-kid
   adoption requires local-pin verification AND `tenant_id==paired` AND strictly-monotonic seq within expiry.
10. The `ExpiryScheduler` holds only `(expires_at, tenant_id, request_id)`; every firing signs with the
    acquired cell's own signer against its own db.
11. Every outward action is idempotent under a `(tenant, request, event)` dedupe key; re-drain is bounded to
    process-restart, never cell-open.
12. Restore is fail-closed for credentials (present-and-unrevoked in BOTH snapshots) and consumption
    (no re-execute after rollback).
13. The FD budget is a runtime invariant (`open_cells*3 + headroom < RLIMIT_NOFILE` incl. transient expiry
    opens + per-tenant stream cap); over-budget sheds/queues rather than failing another tenant's open. A
    strict lock hierarchy (registry-outer, DB-RLock-inner, never across `await`/open/checkpoint, all
    timeout-bounded) prevents a fleet-wide deadlock. Every tenant record carries an immutable monotonic epoch;
    resolution is snapshot-consistent and the bound cell asserts its epoch equals the resolved epoch.

## 16. CI isolation test suite (merge gate)

Isolation is the product, so these are a hard gate. Cross-tenant stream leak (an event on cell A's hub never
reaches any socket on cell B); cookie/token cross-cell read (an A admin session → 404 on B's rids and B's
audit export; app_token reaches only `default`); WS handshake routing (bearer → its cell; no-route rejected
before `accept()`); single-flight acquire (K concurrent acquires → one Database/connection/RLock, no second
WAL writer, no half-migrated read); refcount exactly-once / no use-after-free (normal close, disconnect,
stuck send all return refcount to baseline; background retry keeps the cell pinned); half-open pin cap
(bounded sends, dead-socket reap, per-tenant cap, RLIMIT headroom held); disable/revoke tears down sessions
(socket closes, next HTTP 403s immediately on a hot busy cell); scheduler per-cell signing (B's expiry
verifies under B's key, fails under A's, hits B's db); router-trust forged route (route row → cell lacking
the token ⇒ 403); shared-dir/key-distinctness (duplicate/symlink/`..`/prefix dir rejected at mint AND open;
no two live cells load identical key bytes); cross-tenant verdict rejection with keys FORCED identical (still
fails on aud/tenant_id); rotation trust anchor (adopt iff record verifies under local pin AND tenant matches
AND seq>last within expiry; replay/older-seq/expired/old-key-absent all rejected); `keys()` under
eviction race (always the pinned tenant's JWKS); rate-limiter isolation (A's `agent` burst never throttles
B's `agent`; shared-proxy bad tokens don't 429 the fleet); webhook/ntfy egress isolation (B's body only to
B's sink); backup/restore fail-closed (restore pre-revoke snapshot keeps token invalid; restore pre-consume
snapshot ⇒ consume fails closed, no second execution); outbox idempotency (crash between dispatch and delete
+ cell churn ⇒ callback fires at most once per dedupe key, re-drain only on restart); scheduler durability
(dropped heap-push still expires via rescan; cold-cell stale-approval flips; SIGTERM between the two commits
recovers a signed terminal verdict); scheduler fairness / FD budget (A's large batch doesn't starve or
FD-starve B).

## 17. Out of scope / coupled work items

Deferred (not this build): cross-tenant admin dashboard, approval no-show escalation, non-iOS approval
channel, billing, quorum. **Coupled iOS work item** (out-of-tree, flag to the 0.6.0 iOS train): the app must
support multi-server/per-tenant pairing via the §10 pairing-credential flow and should surface the decoded
canonical action/params on the approval screen (the consent-comprehension gap — hash-binding guarantees
integrity, not that the human understood). Not defended (§2): compromised host / control-plane admin;
custody concentration.

## 18. Decisions locked (review, 2026-07-07)

- **Router integrity MAC: kept.** `control.db` mutations (tenant/token lifecycle) are rare admin actions off
  the hot path; `resolve_identity` only *reads*, so an in-memory MAC verify per resolution is
  computationally negligible — a trivial price to guarantee a tampered or rolled-back registry fails closed
  rather than silently re-pointing a cell.
- **FD sizing:** `max_hot_cells = 64`, per-tenant `stream_cap = 5` (see §5 for the derivation), sized against
  a 1024 `RLIMIT_NOFILE` with large headroom; comfortably supports hundreds of *provisioned* tenants given
  low-frequency approvals (the hot set ≈ tenants with an approval in flight, not the roster).
- **Consumption-replay-on-restore:** force re-mint / invalidation of in-flight approvals after any cell
  restore (§12) — simplest, fail-closed, complexity pushed to the agent's retry loop. The router-captured
  consumption watermark is deferred.
- **Router mechanism:** control-plane index (not tenant-in-token-prefix), for log hygiene and tenant
  remap/portability.

# Multi-tenant Arbiter Isolation — Autonomous Run Report (2026-07-08)

Executed the 86-task cell-per-tenant isolation plan
(`docs/specs/2026-07-07-multitenant-arbiter-isolation-plan.md`) end-to-end with
subagent-driven development: a fresh implementer per task, an independent adversarial reviewer per task
(gate tests were **mutation-verified** — the reviewer broke the guarded invariant in the SUT and confirmed
the test went red, then reverted), fix loops until each gate came back clean, and a final whole-branch
review. Branch `feat/multitenant-isolation` off `master` (@ 463b1b4). **Not merged** — this ends at an open,
green PR awaiting review, per the design's promise that isolation is *proven*, then reviewed.

## Definition of done — met

The product promise is **structural tenant isolation**: cross-tenant read / approve / push / verdict / audit
is impossible by construction. That promise is the §16 merge-gate suite, now green:

- **All 13 §15 invariants** are each covered by at least one shipped §16 gate test and enforced in code
  (mapping verified by the final whole-branch review).
- **§16 isolation suite: 19 gate tests + a manifest** (`server/tests/isolation/`), wired into
  `.github/workflows/ci.yml` as a hard step alongside `scripts/smoke-multitenant.sh`. The manifest asserts
  all 19 gate files exist and each collects ≥1 test (keyed on pytest returncode, so a future refactor can't
  silently gut a gate).

## Final gate counts (all green)

| Suite / check | Result |
|---|---|
| `server` pytest | **467 passed, 16 xfailed** |
| `warden` pytest | **194 passed** |
| `sdk` pytest | **14 passed** |
| `ruff check server sdk warden` | **0 errors** |
| `scripts/smoke.sh` | OK |
| `scripts/smoke-warden.sh` | OK (all 7 legs, incl. expiry) |
| `scripts/smoke-multitenant.sh` | OK (7 curl-proven isolation + adversarial legs) |

The 16 xfails are **all** the deferred §17 admin-dashboard `build_router` port (15 `test_dashboard.py`
cases + 1 `test_security.py` non-ascii-login), including the cookie-authenticated `/v1/stream` case. They are
dashboard-deferred, **not** an isolation gap (confirmed by reading every xfail reason string).

## What shipped, by group

- **A — Cell + TenantRegistry lifecycle (foundation).** `Cell` (owns db/signer/hub/dispatcher/limiters,
  `eq=False`), single-flight `acquire` (one Database/connection/RLock per tenant dir, never a half-migrated
  read), by-object exactly-once `release`/`hold`, bounded-LRU eviction (gated on refcount==0, checkpoint
  outside the map lock, over-cap ops-warning), lock hierarchy proof (map-outer/DB-RLock-inner, timeout-bounded),
  FD budget (startup RLIMIT check + runtime shed + per-tenant stream slots).
- **B — control.db router + identity.** MAC-integrity `ControlPlane` (full-64-hex only, epoch-bound MAC,
  fail-closed `resolve`/`is_disabled`), monotonic-never-reused epoch (tombstone), `resolve_identity` (router
  hint → cell is authority → epoch assert → generic 403 on every failure).
- **C — per-cell /v1 surface.** New `create_app(cfg, registry, control, *, sender, scheduler, ...)`, app.state
  holds only process-globals (§15.1), `require_cell` (pin-for-handler-lifetime, exactly-once release, fleet
  auth-failure limiter keyed on a trusted id), every /v1 route per-cell, `/v1/audit/export` streams only the
  caller's cell, verdicts signed by the cell's own tenant-namespaced key.
- **D — per-tenant crypto + warden rotation.** Per-cell Ed25519 signer, tenant-bound verdicts
  (`aud=hma-verdict:{tenant}` + `hma.tenant_id` + `kid={tenant}:{hash8}`), rotation record signed by the old
  key, `rotate_signing_key` with a grace window, warden `VerdictVerifier(pinned, tenant_id)` anchored to the
  **local pin** (served set is candidate-only), `adopt_rotation` (local-pin + tenant + strictly-monotonic-seq
  + expiry), warden wiring (pin-set + paired tenant + persisted rotation state).
- **E — cell-owned Hub + streams.** Per-instance `Hub` (sync `publish(dict)`), `run_stream` (pin before
  accept, subscribe by object, exactly-once release, blackholed-send reap, per-tenant stream cap via the
  registry slot API — FD-budget-aware and TOCTOU-closed), cross-tenant stream leak proven impossible, disable
  actively tears down live sessions.
- **F — process-wide ExpiryScheduler.** Heap holds only `(deadline, tenant_id, request_id)`, each firing signs
  with the acquired cell's own key against its own db, round-robin per-tenant fairness, level-triggered rescan
  (recovers a dropped heap-push), atomic expire+verdict, SIGTERM-between-commits recovery, wired into the
  lifespan (replacing the old per-cell sweeper).
- **G — device enrollment + observability + notify idempotency.** Cell-owned single-use pairing credential,
  `(request_id,event)` notify dedupe, idempotent outbox (reserve-before-dispatch, at-most-once across crash +
  churn), process-restart-only re-drain (never cell-open), constant generic-403 + equalized-timing floor,
  allowlist-based PII-stripping per-tenant log sink, `resolve_pairing` + `POST /v1/devices/enroll`
  (device row written only to the credential's cell), `hma tenant pair-code`.
- **H — provisioning / backup / CLI.** Dir-isolation guard, `provision_tenant` (key-distinct cell),
  `mint_cell_token`/`revoke_cell_token` (§12 cell-first/router-second ordering), backup primitives, fleet
  backup (cells-first/control-last) + `reconcile_routes`, fail-closed restore (credentials + consumption
  replay), `hma tenant create|list|disable|delete`, tenant-scoped `hma token create|list|revoke`,
  single-tenant back-compat migration + startup auto-migration.
- **I — the §16 gate.** Two-tenant harness + 19 mutation-verified gate tests + `smoke-multitenant.sh` + CI
  wiring + gate manifest.

## Notable review-loop fixes (gates that exposed real gaps in earlier groups)

The §16 suite did its job — three gates surfaced genuine defects that were fixed under review:

1. **I8 — disable→teardown was unwired.** `control.disable_tenant` was a pure DB flag; nothing closed a live
   stream. Added a `run_stream` heartbeat re-check of `is_disabled` → `cell.hub.close()` (§8 heartbeat-recheck
   option). Teardown latency is bounded by `ws_heartbeat` (30s prod default) — §8-sanctioned.
2. **I15 — auth-limiter fleet-DoS.** `require_cell` pre-checked the auth-failure limiter before resolve, so a
   burst of bad tokens from a shared ingress IP could 429 a *different* tenant's valid traffic. Reordered so a
   successfully-authenticating bearer bypasses the failure limiter; attackers are still throttled.
3. **H9 — back-compat break.** A `serve`-before-`migrate` ordering (or a device-only iOS 0.5.0 install with
   zero DB token rows) would strand a legacy install's data behind an empty `default` cell. Added
   `ensure_default_cell` startup auto-migration keyed on `legacy_db.exists()`; migrate is now dir-aware and
   fails loud on a mis-registered default.

Other review-driven fixes: A3 unconditional connection close on checkpoint failure; A6 over-cap ops warning;
C4/C7 background-publish and audit-export hardening; D5 `-O`-proof tenant guard on `/v1/keys`; D8
config-pin-wins-collision; G6 obslog denylist→allowlist; H5 single-sourced control/cells paths; H8 strip
control.db WAL sidecars on restore (a stale WAL would otherwise replay post-snapshot state); I13/I17 vacuous
assertions replaced with genuine ones.

## Deliberate deviations from the plan

- **Interface reconciliations** applied at the seams per the plan's reconciliation ledger (`ControlPlane.open`,
  `TenantRegistry(control, cfg=, sender=)`, `create_app(..., sender=)` keyword-only, `load_or_create_signer`
  tenant-first, `Cell` in `arbiter.registry`, `Hub.publish(dict)` sync). The A5 `acquire()` control flow in
  the plan was uncompilable Python (a `with`-block `else`/`continue`) and was relocated to a
  semantically-equivalent form (adjudicated path-by-path).
- **Test/ops seams added additively** (production `run()`/`acquire`/lifespan behavior unchanged, verified):
  `app.state.scheduler_tick`/`evict_tick`, scheduler `tick`/`rescan`/`recover(now=)`, registry
  `refcount`/`try_evict_idle`/`open_cell_count`/`fd_headroom`/`fd_budget`. These back the §16 gates
  (ledger #10) without altering production paths.
- Commit messages and this PR carry **no AI-authorship trailer** and specs use `<repo-root>` in place of
  machine-local paths (operator hygiene directive).

## Coupled iOS 0.6.0 work item (out of this run, §17)

The iOS app must support **multi-server / per-tenant pairing** via the §10 pairing-credential flow
(`hma tenant pair-code` → `POST /v1/devices/enroll` with the code) and should surface the decoded canonical
action/params on the approval screen (the consent-comprehension gap). This is a coupled iOS train, not built
here (arbiter-side enrollment contract is complete and E2E-proven by the smoke).

## Operator / release-note items (none block merge)

1. **`/v1/keys` now requires a bearer** (was unauthenticated) — §15.2. Breaking for any unauthenticated JWKS
   fetcher; the iOS 0.6.0 client and warden rotation flow must send a bearer.
2. **Warden config change** — `init` now needs `arbiter_tenant` + `HMA_WARDEN_TOKEN`; existing warden installs
   must update config. `scripts/smoke-warden.sh` was red between C6 and D8 by design (server emitted
   tenant-bound `aud` before the warden could verify it); it is green again.
3. **Deferred admin-dashboard port** — the multi-tenant dashboard `build_router` (still reads process-global
   `login_limiter`/`db`/`hub`) and its cookie-authenticated `/v1/stream` path are the 16 remaining xfails.
   A coupled deferred item; the dashboard is a §17 non-goal for V1.
4. **Migrated single-tenant install stays single-tenant** — `tenants_root` (`<db_parent>/cells`) nests under a
   migrated `default` cell's legacy dir, so `hma tenant create` on a migrated install is rejected. Fresh
   installs for multi-tenant fleets; per §1/§14 this is the intended V1 shape. Document in release notes.
5. **Hardening follow-ups** (not isolation breaks): rotation `seq` monotonicity has no server-side guard
   (the rotation caller must enforce it); a crash mid-`rotate_signing_key` needs a manual `hma-warden init`
   re-pair (the §7 documented fallback); a syntactically-valid-but-non-dict `verdict_rotation.json` would crash
   `/v1/keys` (add an `isinstance` guard); an empty per-cell `callback_allowlist` is legacy allow-all (tighten
   §9 policy if callbacks are enabled per-tenant); the lifespan does not checkpoint-close cells on shutdown
   (WAL-safe, no data loss); `reconcile_routes`' boot-time connection has no `busy_timeout` (safe for the
   offline/boot-only call sites); a real-`TenantRegistry` regression test for "cell-open never drains the
   outbox" would harden I18 (the property holds by inspection — `registry.py` never imports `Outbox`).
6. **release.yml** still has no `pypi-warden` job (carried from the prior warden train) — a future tag would
   omit `hold-warden` from PyPI.

## Confirmation

Zero pushes to `master`; zero publishing (no tags, no PyPI/brew/ghcr); zero changes outside the
`holdmyagent-arbiter` repo; zero iOS changes. The PR is opened and left **unmerged**. Nothing was silently
truncated — every deferred/hardening item is listed above.

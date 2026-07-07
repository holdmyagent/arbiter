# GOAL.md — Multi-tenant arbiter isolation (cell-per-tenant V1, autonomous build)

Paste the **Goal prompt** below into `/goal` in a fresh session. Self-contained: implements, tests, and
opens one reviewable PR for the cell-per-tenant multi-tenant isolation build, stopping only on genuine
blockers. The whole product promise is **structural tenant isolation** — the §16 isolation suite is the
definition of done.

## Read first (source of truth — do NOT re-scope)
1. `<repo-root>/docs/specs/2026-07-07-multitenant-arbiter-isolation-design.md`
   — the locked, red-teamed spec (18 sections, 13 load-bearing invariants in §15, the 19-test merge gate in
   §16). Its §18 decisions are locked; do not reopen them.
2. `<repo-root>/docs/specs/2026-07-07-multitenant-arbiter-isolation-plan.md`
   — 86 tasks (groups A–I + Z) with complete code, exact commands, TDD steps, per-group completion gates
   mapping to §16, and a **reconciliation ledger** (top of the plan) that pins the canonical cross-group
   interface names. When a task body and the reconciliation ledger disagree on a name/signature, **the
   ledger wins** (see the Goal prompt's interface-authority rule).

## Goal prompt

```
Execute the multi-tenant arbiter isolation implementation plan exactly as specified by
<repo-root>/docs/specs/2026-07-07-multitenant-arbiter-isolation-plan.md
(read it and its linked design spec first — source of truth; do not re-scope, do not reopen the design's
§18 locked decisions).

Standing authorization to run END-TO-END AUTONOMOUSLY: implement all 86 tasks with
superpowers:subagent-driven-development (fresh implementer per task, independent adversarial review per
task; the plan header requires it), committing per task, finishing with Group Z's push of
feat/multitenant-isolation and PR creation on github.com/holdmyagent/arbiter. No approval checkpoints.
Ask only on genuine blockers (a gate that stays red after honest fix attempts within the owning task's
scope, a missing credential, a contradiction between spec and plan the reconciliation ledger doesn't
resolve).

HARD CONSTRAINTS:
- Work ONLY in <repo-root> (path has
  spaces — quote it), on branch feat/multitenant-isolation created from design/multitenant-isolation
  (which is current main + the design/plan/GOAL docs, and already contains the arbiter 0.4.0 code this
  build extends). NEVER push to main, never merge the PR, no tags, no PyPI/brew/ghcr publishing, no iOS
  changes (the iOS multi-server/per-tenant pairing + decoded-action approval UI is a coupled 0.6.0 item,
  out of scope — the arbiter-side enrollment contract in §10 IS in scope), no homelab/VM/network changes.
- Group/task order: A (Cell + TenantRegistry lifecycle — the foundation) FIRST; B (control.db router +
  identity) before the router-dependent groups; C, D, E, F may interleave once A+B exist as the plan's
  Interfaces allow; G and H after; I (the isolation gate) integrates all groups; Z is last.
- INTERFACE AUTHORITY: where a task body and the plan's reconciliation ledger (top of the plan) disagree
  on a name or signature, the LEDGER / pinned contract wins. In particular use, verbatim:
  ControlPlane.open(control_dir, tenants_root); Hub.publish(event: dict) (SYNC, one dict, no await);
  sign_verdict(signer, *, request_id, action_hash, decision, decided_at, approval_ttl_seconds, tenant_id);
  TenantRegistry.acquire(tenant_id, epoch) / release(cell) / hold(tenant_id, epoch); resolve_identity(
  request, registry, control) -> (Identity, Cell). A few backup/restore TEST bodies still show the older
  1-arg ControlPlane(...) form — normalize them to ControlPlane.open(...) per the ledger.
- Gates are strict: every task ends green (its own tests + the existing server, warden, and sdk suites);
  the §16 isolation suite (Group I) and scripts/smoke-multitenant.sh are green before Z completes. A red
  gate stops forward progress until fixed — never comment out, skip, or weaken a test to pass.
- Isolation is the product. The 13 §15 invariants are load-bearing and the §16 19-test suite is the
  definition of "no tenant data mixing" — treat it as the done-check, not an afterthought. The
  concurrency spine (single-flight acquire; by-object, exactly-once refcount; the lock hierarchy —
  registry map lock OUTER, per-cell DB RLock INNER, never held across an await/acquire/checkpoint; the
  FD budget with max_hot_cells=64 and stream_cap=5) is where a subtle bug becomes a cross-tenant leak or
  a fleet-wide DoS. Hold that bar.
- No process-global object is authoritative for any tenant-scoped surface (§15.1): nothing tenant-scoped
  on app.state; the WebSocket Hub, signer, Dispatcher+egress config, rate limiters, and the scheduler's
  per-firing binding are all cell-owned.

SUCCESS CRITERIA (real evidence in the final report):
1. Cell-per-tenant isolation implemented per the design's 13 §15 invariants; one arbiter process serves
   many tenants with no cross-tenant read/approve/push/verdict/audit path (proven by the §16 suite +
   the smoke transcript).
2. Arbiter 0.4.0 back-compat intact: a single-tenant install runs as the 'default' cell; iOS 0.5.0 and
   hold-sdk 0.2.1 keep working unchanged (legacy config app_token resolves strictly to 'default').
3. All suites green: server (existing plus new), warden, sdk, the new isolation suite (§16), plus
   scripts/smoke.sh, scripts/smoke-warden.sh, and scripts/smoke-multitenant.sh. Paste final counts.
4. The §16 19-test isolation gate passes and is wired into .github/workflows/ci.yml.
5. PR open from feat/multitenant-isolation (URL in the report), NOT merged; morning report committed at
   docs/specs/2026-07-08-multitenant-isolation-run-report.md (what shipped per group with counts, notable
   review-loop fixes, deliberate deviations, and the coupled iOS 0.6.0 work item).
6. Explicit confirmation: zero pushes to main, zero publishing, zero changes outside the
   holdmyagent-arbiter repo, zero iOS changes, and anything sacrificed/deferred listed — no silent
   truncation.
```

## Prerequisites (all verified 2026-07-07, this session)
- PR #3 (warden 0.4.0 train) is **merged to main** (merge commit 463b1b4); `main` carries the arbiter
  0.4.0 surface this build extends (`/v1/keys`, per-identity `resolve_identity`, `consume_request`, the
  `Dispatcher`/outbox, the process-global Hub the design de-globalizes, per-cell `Database`+RLock).
- Branch `design/multitenant-isolation` exists on origin = current `main` + the design/plan/GOAL docs; it
  is based on the post-merge main, so `feat/multitenant-isolation` branched from it **already contains the
  0.4.0 code**. No rebase needed.
- gh CLI authenticated with repo+workflow scopes; origin = https://github.com/holdmyagent/arbiter.git.
- python3 ≥3.11 on PATH; the build uses the existing server/sdk/warden editable installs (Task A1
  establishes the multi-tenant dev fixtures).
- No external credentials needed: the isolation suite and smoke mint their own per-tenant tokens against
  throwaway local instances; the plan's §16/smoke build their own two-tenant setups.

## After the run (operator, morning)
1. Review the PR + docs/specs/2026-07-08-multitenant-isolation-run-report.md; merge when satisfied. The
   §16 isolation suite green is the go/no-go — read a couple of its cross-tenant assertions yourself.
2. Coupled follow-ups (deliberately NOT in this run): the iOS 0.6.0 change for multi-server/per-tenant
   pairing (the §10 pairing-credential flow) and surfacing the decoded canonical action/params on the
   approval screen (closes the consent-comprehension gap); the deferred operability layer (cross-tenant
   admin dashboard, approval no-show escalation, non-iOS approval channel, billing) and quorum/maker-checker
   for money-movement.
3. `/metrics` is not shipped; if you add it later, honor §11 (authenticated + fleet-aggregate or per-tenant
   authz) so it isn't a cross-tenant topology channel.

# GOAL.md — Warden verified enforcement, 0.4.0 train (overnight autonomous)

Paste the **Goal prompt** below into `/goal` in a fresh session. Self-contained: implements,
tests, documents, and publishes the Warden + arbiter trust upgrade as one reviewable PR,
stopping only on genuine blockers.

## Read first (source of truth — do NOT re-scope)
1. `<repo-root>/docs/specs/2026-07-06-warden-enforcement-design.md`
2. `<repo-root>/docs/specs/2026-07-06-warden-enforcement-plan.md`
   — 29 tasks (groups A–G) with complete code, exact commands, TDD steps, and pinned
   cross-task contracts. The plan's "Consciously accepted deviations" list is signed off —
   do not "fix" those.

## Goal prompt

```
Execute the Warden enforcement implementation plan exactly as specified by
<repo-root>/docs/specs/2026-07-06-warden-enforcement-plan.md
(read it and its linked design first — source of truth; do not re-scope, do not reopen the
plan's "Consciously accepted deviations").

Standing authorization to run END-TO-END AUTONOMOUSLY overnight: implement all 29 tasks with
superpowers:subagent-driven-development (fresh implementer per task, independent review per
task; the plan header requires it), committing per task, finishing with Task 29's push of
feat/warden-enforcement and PR creation on github.com/holdmyagent/arbiter. No approval
checkpoints. Ask only on genuine blockers (a gate that stays red after honest fix attempts
within the owning task's scope, a missing credential, a contradiction between spec and plan).

HARD CONSTRAINTS:
- Work ONLY in <repo-root>
  (path has spaces — quote it), on branch feat/warden-enforcement created from
  design/warden-enforcement. NEVER push to main, never merge the PR, no tags, no PyPI/brew/
  ghcr publishing, no iOS changes, no homelab/VM/network changes, no ASC/App Store calls.
- Task order: Groups A→B→C (warden) may interleave with D→E (arbiter) as the plan's
  Interfaces allow, but 15 before 17-22, 13 before 15, and 24-27 after both tracks;
  29 is last. 28 is STRETCH: only if 1-27 and both smokes are green.
- Gates are strict: every task ends green (its own tests + the existing server/sdk suites);
  scripts/smoke.sh and scripts/smoke-warden.sh green before Task 29 completes. A red gate
  stops forward progress until fixed — never comment out, skip, or weaken a test to pass.
- Secrets hygiene per the plan's Global Constraints (no values in logs/receipts/doctor).
- The request status enum stays pending|approved|denied|expired (consumed_at is a column).

SUCCESS CRITERIA (real evidence in the final report):
1. warden/ package exists and hma-warden init|serve|doctor|hash work end-to-end against a
   local arbiter (proven by the warden test suite + smoke-warden.sh transcript tail).
2. Arbiter 0.4.0 spec items §5.1-5.9 implemented with the migration chain intact
   (SCHEMA_VERSION advanced; fresh-db and upgrade paths both tested).
3. All suites green: server (existing 122+ plus new), warden, sdk — plus BOTH smokes.
   Paste final counts.
4. Docs shipped and linked from README: api, config, cli, warden, secret-managers,
   enforcement-models, reference-sandboxed-agent, claude-code-hook + SECURITY.md rewrite —
   zero TBD/TODO placeholders (Task 29 Step 2 gate output as evidence).
5. PR open from feat/warden-enforcement (URL in the report), NOT merged; morning report
   committed at docs/specs/2026-07-07-warden-run-report.md per Task 29 Step 3 (including
   the v0.3.0-never-tagged note and the supervised next steps).
6. Explicit confirmation: zero pushes to main, zero publishing, zero changes outside the
   holdmyagent-arbiter repo, and anything sacrificed (e.g. Task 28) listed — no silent
   truncation.
```

## Prerequisites (all verified 2026-07-06, this session)
- Repo clean on branch design/warden-enforcement with spec (f3962c7 + 1aabb77) and plan
  (7772692) committed; origin = https://github.com/holdmyagent/arbiter.git.
- gh CLI authenticated as kevinjclear with repo+workflow scopes (`gh auth status` green).
- python3 ≥3.11 on PATH (3.14.6); Task 1 creates the root .venv and editable-installs
  server/sdk/warden.
- No external credentials needed: the smokes mint their own tokens against throwaway local
  instances; secret-resolver tests use fake CLIs on PATH.

## After the run (operator, morning)
1. Review the PR + docs/specs/2026-07-07-warden-run-report.md; merge when satisfied.
2. Supervised follow-ups (deliberately NOT in the overnight run): Knossos staging deploy via
   knossos-staging-gates with the new G8-HMA gate (docs/reference-sandboxed-agent.md
   Appendix A); iOS 0.6.0 receipt/executed-state UI; release decision for 0.4.0 (fold in the
   never-tagged v0.3.0).

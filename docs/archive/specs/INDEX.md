# Archive — shipped specs

Executed design/plan/GOAL docs and run reports for shipped Hold My Agent server
work. Kept for reference. Operational reference docs (api, cli, config, deploy-*,
warden, enforcement-models, apns, webhooks, …) stay in `docs/`.

- **warden-enforcement** (2026-07-06) — design + plan + GOAL. Shipped as
  hold-warden 0.1.0 / arbiter 0.4.0 (merged, PR #3).
- **multitenant-arbiter-isolation** (2026-07-07) — design + plan + GOAL.
  Cell-per-tenant structural isolation; shipped (merged, PR #4).
- **run reports** — `2026-07-07-warden-run-report.md`,
  `2026-07-08-multitenant-isolation-run-report.md`.

No active spec lives in this repo now — current deployment work (SP1 arbiter VM)
lives in the `homelab` repo under `docs/superpowers/`. Nothing deleted; recover
via `git log --follow`.

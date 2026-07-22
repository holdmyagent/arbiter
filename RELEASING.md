# Releasing

How to cut a release of the three packages in this repo (`holdmyagent`,
`hold-sdk`, `hold-warden`). Only the tag and CHANGELOG discipline below are
required reading before you tag; everything else is reference.

## Versions are decoupled — the tag tracks the server only

`server`, `sdk`, and `warden` each carry their own `pyproject.toml` version
and can bump independently. Only `server`'s version is enforced against the
tag: the `pypi-server` job in `.github/workflows/release.yml` reads
`server/pyproject.toml`'s `[project].version` via `tomllib` and fails the
whole run if it doesn't match:

```
::error::tag $GITHUB_REF_NAME does not match holdmyagent version $v - refusing to publish
```

So: **the annotated tag is always `v<server-version>`**, e.g. `v0.5.0` for
server `0.5.0`. `sdk` and `warden` publish whatever their own
`pyproject.toml` says, tag or no tag — bump them in the same PR when they
have release-worthy changes, but don't invent a version bump just to keep
numbers in lockstep.

## Before tagging: CHANGELOG discipline

Move everything sitting under `## Unreleased` in `CHANGELOG.md` into a new
dated section — `## [<server-version>] - <date>` — before you tag. Leave
`## Unreleased` in place, empty, above it. `warden/CHANGELOG.md` is
maintained separately; reference its entry from the root CHANGELOG instead
of duplicating it.

## The pipeline

Pushing an annotated tag `v<server-version>` fires `.github/workflows/release.yml`:

1. `test` — the full CI matrix must pass (a red commit never publishes).
2. `pypi-server` / `pypi-sdk` / `pypi-warden` — three independent PyPI
   trusted-publisher environments (`pypi`, `pypi-sdk`, `pypi-warden`), OIDC,
   no stored secrets. Only `pypi-server` runs the tag guard above.
3. `github-release` — downloads the dists the PyPI jobs already built
   (never rebuilt) and creates the GitHub release with
   `generate_release_notes: true`.
4. `docker` — builds and pushes `ghcr.io/holdmyagent/arbiter:latest` and
   `:<tag>`.

## After: the Homebrew tap

`holdmyagent-homebrew-tap`'s `scripts/bump.sh` regenerates `Formula/hma.rb`
from the PyPI release. Homebrew's release-cooldown excludes PyPI releases
less than 24 hours old, so run the tap bump the morning after publishing,
not immediately.

## Never reuse 2.0.0

Both `holdmyagent` and `hold-sdk` have a **yanked** `2.0.0` on PyPI
(uploaded 2026-07-03 — a version-scheme mistake, republished as `0.2.0`).
Don't reuse `2.0.0` for either package.

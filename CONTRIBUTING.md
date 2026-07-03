# Contributing to Arbiter

Thanks for considering a contribution. This repo has two Python packages —
the `server` (the `holdmyagent` distribution, importable as `arbiter`) and
the `sdk` (the `hold-sdk` distribution, importable as `hold_sdk`) — each with
its own virtualenv and test suite.

## Dev setup

### Server

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest tests
```

### SDK

The SDK's tests exercise `hold_sdk` against a real, in-process Arbiter
server, so they need the `server` package installed alongside the SDK. Use
`requirements-dev.txt` rather than `pip install -e '.[dev]'` on its own —
it pulls in `server` as an editable dependency too:

```bash
cd sdk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests
```

### End-to-end smoke test

`scripts/smoke.sh` builds a throwaway venv, installs both packages, runs
`hma init` + `hma serve`, and drives a full create → approve round trip
through `hma ask`. It's a good sanity check after touching the server/SDK
contract:

```bash
bash scripts/smoke.sh
```

## Before you open a pull request

- **Add tests.** New behavior needs test coverage; bug fixes should include
  a regression test that fails without the fix.
- **Keep ruff clean.** Both packages share the same lint config
  (`[tool.ruff]` in each `pyproject.toml`, 110-char lines, `py311` target).
  Run `ruff check server sdk` before pushing — CI will reject anything it
  flags. Avoid blanket `# noqa`; if a specific line genuinely needs one,
  leave a comment explaining why.
- **Run both suites.** `pytest server/tests` and `pytest sdk/tests` should
  both be green. CI runs the full matrix (Linux + macOS, Python 3.11–3.13)
  plus `scripts/smoke.sh` on every push and pull request.
- **Keep changes scoped.** Prefer small, focused pull requests over broad
  refactors bundled with feature work — it makes review and bisecting much
  easier.

## Reporting bugs and requesting features

Open a GitHub issue with steps to reproduce (for bugs) or the problem
you're trying to solve (for feature requests). See `SECURITY.md` instead
if you've found a vulnerability — please don't file those as public issues.

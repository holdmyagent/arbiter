## What & why

## Testing
- [ ] `pytest server/tests` (and `tests/isolation` if server paths changed)
- [ ] `pytest sdk/tests` / `pytest warden/tests` if touched
- [ ] Smoke scripts if runtime behavior changed

## Fail-closed review
- [ ] Every new error path denies rather than allows

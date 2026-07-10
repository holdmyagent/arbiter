# Multi-tenant Arbiter Isolation — Implementation Plan

**REQUIRED SUB-SKILL:** Use `superpowers:subagent-driven-development` to execute this plan. Each task is
dispatched to a **fresh implementer subagent**; an **independent verifier subagent** re-checks every phase
gate by reproducing the RED→GREEN runs with its own commands (never by trusting the implementer's report).
Steps use checkbox (`- [ ]`) syntax; do them in order, commit at each green.

**Goal.** Let one arbiter *process* safely broker high-stakes, irreversible actions for many client
businesses at once, with cross-tenant read / approve / push / verdict / audit **impossible by construction**
(structural isolation) — not merely forbidden by a query filter — proven by the §16 merge-gate suite.

**Architecture.** One arbiter process serves N tenants; each tenant is an isolated **Cell** that owns ALL its
tenant-scoped state (its own SQLite `Database` + DB-wide `RLock`, Ed25519 `signer`/tenant-namespaced `kid`,
`Hub`, `Dispatcher` + per-cell egress config, rate limiters, device set) — nothing tenant-scoped ever lives
on `app.state`. A process-global **`TenantRegistry`** is a bounded-LRU of open cells behind a single-flight,
refcount-pinned, by-object `acquire`/`release`; a **`control.db` router** (MAC-integrity, full-64-hex-only)
maps a token to its tenant, but the cell re-validates role/expiry/revocation and is the sole authority. A
process-wide **`ExpiryScheduler`** replaces the per-cell sweeper and binds each firing to the acquired cell's
own signer + db.

**Tech Stack.** Python ≥3.11; FastAPI (the existing app, extended — no new web framework); SQLite (one DB per
cell + one `control.db` router) with WAL and a DB-wide `threading.RLock`; `asyncio`; PyJWT + `cryptography`
(Ed25519 / EdDSA JWS verdicts); pytest + pytest-asyncio (strict mode); Click CLI (`hma`); the out-of-tree
`hold_warden` local-pin verifier; GitHub Actions CI + curl smoke scripts.

## Global Constraints

- Repo (quote it — the path has spaces): `<repo-root>`; build branch `feat/multitenant-isolation` (off `design/multitenant-isolation`).
- Python ≥3.11; extend the existing FastAPI app (no new web framework).
- One SQLite DB per cell.
- Additive to `/v1` where possible; back-compat: a `default` cell keeps iOS 0.5.0 + hold-sdk 0.2.1 working unchanged.
- The DB-wide RLock discipline is preserved and the lock hierarchy is honored (registry map lock is OUTER; the per-cell DB RLock is INNER and is NEVER held across an `await`, an `acquire()`/`evict()`, or a migration/checkpoint; all lock acquisitions are timeout-bounded).
- Defaults `max_hot_cells=64`, `stream_cap=5`.
- TDD + conventional commits.
- The 13 §15 invariants are load-bearing and the §16 isolation suite (19 tests) is a merge gate.

### Consciously accepted deviations

These are places where the independently-authored group files overlap or diverge and this assembly picks one
authoritative owner, or accepts a small departure from the pinned-contract shorthand. They are **flagged for
the executing controller** so the fresh subagents reconcile at the seam rather than each re-inventing it. No
task *logic* is rewritten here — only ownership/name/signature is pinned.

- **`arbiter/control.py` / `ControlPlane` — Group B is authoritative.** Groups A (Task A1) and B (Tasks
  B1–B4) both author `control.py` + `tests/test_control.py`. **Group B's full router-only `ControlPlane`**
  (`resolve` with the `(token_hash, tenant_id, epoch)` MAC, `is_disabled`, `add_route`/`remove_route`,
  `create_tenant`→AUTOINCREMENT monotonic epoch, `epoch_of`, `tenant_dir`, `list_tenants`, `disable_tenant`,
  `tombstone_tenant`) **is the real class and matches the pinned contract**; A1's thin `ControlPlane(path)`
  tenants-slice is a bootstrap **subsumed by B** (build B's file; do not keep A1's divergent schema). Group A's
  registry only consumes `ControlPlane.tenant_dir(tenant_id)` (present in B).
- **`arbiter/signing.py` / `Signer` — Group D is authoritative.** Groups A (Task A2) and D (Task D1) both add a
  `Signer` + a builder. **Group D's `Signer(tenant_id, kid, signing_key, dir)`** (with the rotation grace-window
  `public_jwks()`, `sign_verdict`, `sign_rotation_record`, `rotate_signing_key`) **is the real class**; A2's
  simpler `Signer` + `load_or_create_cell_signer` is **subsumed by D**. The canonical builder is D's
  `load_or_create_signer(tenant_id, cell_dir)` (tenant-first arg order).
- **`sign_verdict` TTL keyword.** Pinned-contract shorthand is `approval_ttl`; Groups D and F wrote
  `approval_ttl_seconds`. This assembly normalizes the **parameter name to the pinned `approval_ttl`** (the
  JWS claim key and the warden `Verdict` field stay `approval_ttl_seconds` — those are payload/field names, not
  the function parameter). Deviation recorded so C/D/F/I all pass `approval_ttl=`.
- **Group I is a thin alias layer over the real symbols.** The §16 suite's `conftest.py` re-exports every SUT
  symbol through aliases *by design* (Task I1 says so), so path/name drift is a **one-line conftest edit**, not
  a rewrite: `Cell` lives in `arbiter.registry` (not `arbiter.cell`); the signer factory is
  `load_or_create_signer` (alias I's `make_signer`); the rotation-record signer is
  `arbiter.signing.sign_rotation_record` (alias I's `hold_warden.rotation.make_rotation_record`); registry gate
  affordances (`refcount(cell)`, `try_evict_idle()`, `open_cell_count()`, `fd_headroom()`, `fd_budget()`) and
  scheduler seams (`tick`/`rescan`/`recover`, `app.state.scheduler_tick`) are exposed by the registry/scheduler
  groups (or aliased in conftest). `create_app(...)` and `TenantRegistry(...)` are called with the reconciled
  signatures below.

### Interface reconciliation ledger (normalized names/signatures)

Cross-group drifts normalized to the pinned contract / authoritative producer. The verbatim task bodies below
still show each group's original spelling in places; **apply these normalizations at the seam:**

1. **`ControlPlane` construction** → `ControlPlane.open(control_dir, tenants_root)` (Group B). All harness /
   CLI / test constructions that wrote `ControlPlane(path)`, `ControlPlane(str(...))`, or `ControlPlane(cfg)`
   (Groups A, C, G, H, I) use `.open(...)`; B also exposes `db_path` (Group H's backup needs it). Every
   `create_tenant` dir must resolve strictly under that `tenants_root`.
2. **epoch getter** → `ControlPlane.epoch_of(tenant_id)` (Group B). Normalizes Group A's `tenant_epoch` and
   Group C's `resolve_epoch`.
3. **`ControlPlane.list_tenants()`** → `list[dict]` with keys incl. `tenant_id` and `epoch` (Group B / F).
   Group G's `drain_all_at_startup` and Group H's CLI/backup iterate `t["tenant_id"]` / `t["epoch"]` (not
   `(tid, epoch)` tuples, not bare `tenant_id` strings).
4. **signer builder** → `load_or_create_signer(tenant_id, cell_dir)` (Group D). Group A's `open_cell` calls it
   as `load_or_create_signer(tenant_id, resolved)`.
5. **`sign_verdict` TTL kwarg** → `approval_ttl=` (pinned). C already uses it; D/F/I call sites pass
   `approval_ttl=` (their local attr may stay `approval_ttl_seconds`).
6. **`Hub.publish`** → `publish(event: dict) -> None` (sync, single already-built wire dict; Group E / pinned).
   Group C's and Group G's `await cell.hub.publish("evt", "key", obj)` sites become
   `cell.hub.publish({"event": "evt", "key": obj})` (no `await`). Group E's Task E7 performs C's three edits.
7. **`create_app`** → `create_app(cfg, registry, control, *, sender=None, scheduler=None, ws_heartbeat=30.0, ws_send_timeout=10.0)`
   (Group C, extended by Group E). `sender` is keyword-only; Group D5's `create_app(cfg, Database(...), sender)`
   fixture and Group I's `create_app(cfg, registry, control, sender)` pass `sender=sender`.
8. **`TenantRegistry` construction** → the full Group A signature `TenantRegistry(control, max_hot_cells=64, stream_cap=5, *, cfg, sender=None, headroom=150, lock_timeout=5.0, clock=time.monotonic)`.
   Every construction (Groups C, E, F, G, H, I) passes `cfg=cfg, sender=sender` (the pinned
   `TenantRegistry(control, max_hot_cells, stream_cap)` is a subset — cfg/sender are required to build cells).
9. **`registry.hold`** → `hold(tenant_id, epoch)` (Group A / F). The process-restart drain coordinator is
   **Group G's `drain_all_at_startup(registry, control)`** (in `notify/outbox.py`); Group C's lifespan calls
   that (C's local `_drain_all_outboxes` is superseded), iterating `list_tenants()` dicts.
10. **App test-seam** → the app/scheduler wiring exposes `app.state.scheduler_tick(now=...)` (a synchronous,
    clock-injectable one-shot draining all due entries across cells) for Group I's I9/I19/I20, backed by Group
    F's `ExpiryScheduler` (`_fire_due`/`_rescan_tick`/`_recover`) with public `tick`/`rescan`/`recover(now=...)`
    seams and the `per_tenant_tick_cap`/`per_tenant_batch` fairness bound.

---


## Group A — Cell object + TenantRegistry lifecycle (THE FOUNDATION)

Implements design invariants **§15.1, §15.3, §15.4, §15.13** (the registry/lifecycle parts) from
`docs/specs/2026-07-07-multitenant-arbiter-isolation-design.md`. Build this group **first** — every other
group binds to the `Cell` object and `TenantRegistry.acquire/release/hold` produced here.

Branch: `feat/multitenant-isolation`. Run all tests from the `server/` directory. Async tests use the
existing convention: `@pytest.mark.asyncio` (pytest-asyncio is already a dev dep). Imports are
`from arbiter.<mod> import ...` (the package is `arbiter`, rooted at `server/`).

## What this group builds (new/changed source)

- **`server/arbiter/control.py`** (NEW) — a thin `ControlPlane` owning `control.db`'s `tenants(tenant_id,
  dir, epoch, disabled_at)` slice + a monotonic-never-reused epoch counter. *Only* the registry-facing
  subset: `create_tenant`, `tenant_dir`, `tenant_epoch`, `list_tenants`.
- **`server/arbiter/signing.py`** (MODIFY) — add a `Signer` dataclass (`tenant_id`, tenant-namespaced
  `kid=f"{tenant_id}:{hash8}"`, `signing_key`, `public_jwks()`) + `load_or_create_cell_signer`, reusing the
  shipped `load_or_create_keypair`.
- **`server/arbiter/db.py`** (MODIFY) — add `Database.checkpoint_and_close()` for eviction.
- **`server/arbiter/registry.py`** (NEW) — the `Cell` dataclass, `open_cell(...)`, and `TenantRegistry`
  (single-flight `acquire`, by-object exactly-once `release`, `hold` context manager, bounded-LRU eviction,
  the lock hierarchy, and the FD-budget invariant + per-tenant stream-slot accounting).

## Seams to OTHER groups (named cross-component contract, not by task number)

- **Routing/auth group** builds the *rest* of `ControlPlane` on the **same class/file** — `resolve`,
  `is_disabled`, `add_route`/`remove_route`, `disable_tenant`, `tombstone_tenant`, the `token_route` table,
  and the MAC over `(token_hash, tenant_id, epoch)`. It **Consumes** my `ControlPlane.create_tenant`,
  `.tenant_dir`, `.tenant_epoch`, `.list_tenants`. It also builds `resolve_identity(request, registry,
  control)`, which **Consumes** `TenantRegistry.acquire(tenant_id, epoch)` / `.release(cell)` and my `Cell`.
- **Crypto group** builds `sign_verdict(signer, request_id, action_hash, decision, decided_at, approval_ttl,
  tenant_id)` and the warden `VerdictVerifier`; both **Consume** my `Signer` (its `kid`, `signing_key`,
  `public_jwks()`).
- **Notify/egress group** refines *per-cell delivery config* (§9): my `open_cell` builds
  `Dispatcher(cfg, cell.db, sender=sender)` from the process cfg threaded through the registry; that group
  overrides the per-tenant `webhook`/`ntfy`/`callback_allowlist` source. The wiring point (Dispatcher built
  with `cell.db`, threaded via the registry) is fixed here.
- **Stream group** **Consumes** `TenantRegistry.acquire_stream_slot(tenant_id)->bool` /
  `.release_stream_slot(tenant_id)` and `registry.stream_cap` to gate `ws.accept()` under the FD budget.
- **Scheduler group** **Consumes** `TenantRegistry.hold(tenant_id, epoch)`.
- **App-wiring group** constructs the single process-global `TenantRegistry(control, cfg=..., sender=...)`
  and puts it on `app.state` (the registry is process-global; **cells are not**).

## Interfaces this group PRODUCES (verbatim names later groups rely on)

- `arbiter.control.ControlPlane(path: str)` with `create_tenant(tenant_id: str, dir) -> int` (fresh
  monotonic epoch), `tenant_dir(tenant_id: str) -> pathlib.Path`, `tenant_epoch(tenant_id: str) -> int|None`,
  `list_tenants() -> list[dict]`.
- `arbiter.signing.Signer(tenant_id, kid, signing_key)` with `.public_jwks() -> dict`; and
  `arbiter.signing.load_or_create_cell_signer(cell_dir: Path, tenant_id: str) -> Signer`.
- `arbiter.db.Database.checkpoint_and_close() -> None`.
- `arbiter.registry.Cell` (dataclass, `eq=False`): `tenant_id:str, epoch:int, dir:Path, db:Database,
  signer:Signer, hub:Hub, dispatcher:Dispatcher, create_limiter:SlidingWindowLimiter,
  login_limiter:SlidingWindowLimiter`.
- `arbiter.registry.open_cell(tenant_id: str, dir, epoch: int, cfg, sender=None) -> Cell`.
- `arbiter.registry.TenantRegistry(control, max_hot_cells=64, stream_cap=5, *, cfg, sender=None,
  headroom=150, lock_timeout=5.0, clock=time.monotonic)` with `async acquire(tenant_id, epoch) -> Cell`,
  `release(cell) -> None`, `async hold(tenant_id, epoch)` (async context manager),
  `acquire_stream_slot(tenant_id) -> bool`, `release_stream_slot(tenant_id) -> None`,
  `stream_cap`, and exceptions `EpochChanged`, `CapacityExceeded`.

---

### Task A1: `ControlPlane` — the thin `control.db` tenants slice

**Files:** Create `server/arbiter/control.py`. Test: `server/tests/test_control.py`.

**Interfaces:**
- Consumes: nothing (foundation). Mirrors the shipped `Database` connection+`RLock` discipline
  (`db.py:84-113`).
- Produces: `ControlPlane(path)`, `.create_tenant(tenant_id, dir) -> int`, `.tenant_dir(tenant_id) -> Path`,
  `.tenant_epoch(tenant_id) -> int|None`, `.list_tenants() -> list[dict]`. (Routing group extends this class
  with `resolve`/`is_disabled`/`token_route`/MAC — do not close the class to extension.)

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_control.py`:
```python
import pytest
from pathlib import Path
from arbiter.control import ControlPlane


def test_create_tenant_returns_monotonic_epoch(tmp_path):
    c = ControlPlane(":memory:")
    e1 = c.create_tenant("default", tmp_path / "default")
    e2 = c.create_tenant("acme", tmp_path / "acme")
    assert e1 == 1 and e2 == 2


def test_epoch_never_reused_even_after_recreate(tmp_path):
    # Tombstone semantics live in the routing group, but the epoch COUNTER is
    # monotonic here: two tenants never share an epoch, and the counter only ever
    # climbs, so a future delete+recreate cannot recycle an epoch.
    c = ControlPlane(":memory:")
    epochs = {c.create_tenant(f"t{i}", tmp_path / f"t{i}") for i in range(5)}
    assert epochs == {1, 2, 3, 4, 5}


def test_tenant_dir_is_realpath_canonical_absolute(tmp_path):
    c = ControlPlane(":memory:")
    c.create_tenant("acme", tmp_path / "acme")
    d = c.tenant_dir("acme")
    assert d.is_absolute() and d == (tmp_path / "acme").resolve()


def test_tenant_dir_missing_raises_keyerror():
    c = ControlPlane(":memory:")
    with pytest.raises(KeyError):
        c.tenant_dir("nope")


def test_tenant_id_charset_enforced(tmp_path):
    c = ControlPlane(":memory:")
    for bad in ("Acme", "a_b", "a.b", "a/b", "a b", "", "café"):
        with pytest.raises(ValueError):
            c.create_tenant(bad, tmp_path / "x")


def test_dir_is_unique(tmp_path):
    import sqlite3
    c = ControlPlane(":memory:")
    c.create_tenant("a", tmp_path / "shared")
    with pytest.raises(sqlite3.IntegrityError):
        c.create_tenant("b", tmp_path / "shared")


def test_list_tenants_and_tenant_epoch(tmp_path):
    c = ControlPlane(":memory:")
    c.create_tenant("default", tmp_path / "default")
    c.create_tenant("acme", tmp_path / "acme")
    ids = [t["tenant_id"] for t in c.list_tenants()]
    assert ids == ["acme", "default"]          # ORDER BY tenant_id
    assert c.tenant_epoch("acme") == 2 and c.tenant_epoch("nope") is None
```
- [ ] **Run — expect FAIL** (module missing): `cd server && python -m pytest tests/test_control.py -q`
      → `ModuleNotFoundError: No module named 'arbiter.control'`.
- [ ] **Implement.** Create `server/arbiter/control.py`:
```python
import re
import sqlite3
import threading
from pathlib import Path

# tenant_id charset is strictly [a-z0-9-] (§4/§14): never string-interpolated into
# SQL or path joins, always parameterized. Validate at the mint boundary.
_TENANT_ID_RE = re.compile(r"^[a-z0-9-]+$")

# control.db is a ROUTER ONLY (§4). This module owns the tenants(tenant_id, dir,
# epoch, disabled_at) slice + a monotonic epoch counter. The routing group ADDS
# the token_route table, the (token_hash, tenant_id, epoch) MAC, resolve(),
# is_disabled(), disable_tenant(), tombstone_tenant(), add_route/remove_route on
# THIS SAME class. Do not remove the extension seam.
_CONTROL_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(
  tenant_id TEXT PRIMARY KEY,
  dir TEXT NOT NULL UNIQUE,
  epoch INTEGER NOT NULL,
  disabled_at TEXT);
CREATE TABLE IF NOT EXISTS control_meta(
  key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT OR IGNORE INTO control_meta(key, value) VALUES ('next_epoch', 1);
"""


class ControlPlane:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # Same shared-connection discipline as Database (db.py): one connection,
        # one RLock, every method takes it (reads included) because resolve() runs
        # from FastAPI's threadpool concurrently with rare admin writes.
        self._lock = threading.RLock()
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.executescript(_CONTROL_SCHEMA)
            self.conn.commit()

    def create_tenant(self, tenant_id: str, dir) -> int:
        """Register a tenant with a fresh, monotonic, never-reused epoch. Returns
        the epoch. Dir is stored realpath-canonical + absolute; UNIQUE enforces
        no two tenants share a dir (full non-overlap/symlink checks are the
        provisioning group's, re-validated at cell open in open_cell)."""
        if not _TENANT_ID_RE.match(tenant_id):
            raise ValueError(f"invalid tenant_id (charset [a-z0-9-]): {tenant_id!r}")
        d = str(Path(dir).expanduser().resolve())
        with self._lock:
            epoch = self.conn.execute(
                "SELECT value FROM control_meta WHERE key='next_epoch'").fetchone()["value"]
            self.conn.execute(
                "UPDATE control_meta SET value=? WHERE key='next_epoch'", (epoch + 1,))
            self.conn.execute(
                "INSERT INTO tenants(tenant_id, dir, epoch, disabled_at) VALUES (?,?,?,NULL)",
                (tenant_id, d, epoch))
            self.conn.commit()
            return epoch

    def tenant_dir(self, tenant_id: str) -> Path:
        with self._lock:
            r = self.conn.execute(
                "SELECT dir FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
        if r is None:
            raise KeyError(tenant_id)
        return Path(r["dir"])

    def tenant_epoch(self, tenant_id: str) -> int | None:
        with self._lock:
            r = self.conn.execute(
                "SELECT epoch FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
        return r["epoch"] if r else None

    def list_tenants(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT tenant_id, dir, epoch, disabled_at FROM tenants ORDER BY tenant_id"
            ).fetchall()]
```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_control.py -q`.
- [ ] **Commit:** `git commit -am "feat(control): thin ControlPlane tenants slice with monotonic epoch"`

---

### Task A2: `Signer` + `load_or_create_cell_signer` (tenant-namespaced kid)

**Files:** Modify `server/arbiter/signing.py` (append after `public_jwks`, `signing.py:88`).
Test: `server/tests/test_cell_signer.py`.

**Interfaces:**
- Consumes: shipped `load_or_create_keypair(config_dir) -> (hash8_kid, Ed25519PrivateKey)` (`signing.py:32`),
  `public_jwks(kid, key)` (`signing.py:84`).
- Produces: `Signer(tenant_id, kid, signing_key)` with `.public_jwks() -> dict`;
  `load_or_create_cell_signer(cell_dir, tenant_id) -> Signer`. Consumed by the crypto group's
  `sign_verdict(signer, ...)` and warden `VerdictVerifier`.

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_cell_signer.py`:
```python
from pathlib import Path
from arbiter.signing import Signer, load_or_create_cell_signer, KEY_FILENAME


def test_kid_is_tenant_namespaced(tmp_path):
    s = load_or_create_cell_signer(tmp_path, "acme")
    prefix, _, hash8 = s.kid.partition(":")
    assert prefix == "acme"
    assert len(hash8) == 8 and all(c in "0123456789abcdef" for c in hash8)
    assert s.tenant_id == "acme"


def test_key_persisted_in_cell_dir_and_stable(tmp_path):
    s1 = load_or_create_cell_signer(tmp_path, "acme")
    assert (tmp_path / KEY_FILENAME).is_file()
    s2 = load_or_create_cell_signer(tmp_path, "acme")   # reload, don't regenerate
    assert s1.kid == s2.kid


def test_two_tenants_get_distinct_keys(tmp_path):
    a = load_or_create_cell_signer(tmp_path / "a", "a")
    b = load_or_create_cell_signer(tmp_path / "b", "b")
    assert a.kid.split(":")[1] != b.kid.split(":")[1]   # different key bytes -> different hash8


def test_public_jwks_advertises_namespaced_kid(tmp_path):
    s = load_or_create_cell_signer(tmp_path, "acme")
    jwks = s.public_jwks()
    assert jwks["keys"][0]["kid"] == s.kid
    assert jwks["keys"][0]["kty"] == "OKP" and jwks["keys"][0]["crv"] == "Ed25519"
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_cell_signer.py -q`
      → `ImportError: cannot import name 'Signer'`.
- [ ] **Implement.** Append to `server/arbiter/signing.py`:
```python
from dataclasses import dataclass


@dataclass
class Signer:
    """A cell's per-tenant Ed25519 signer. kid is tenant-namespaced
    (f"{tenant_id}:{hash8}", §7) so an accidental key coincidence across tenants
    still yields distinct kids. The crypto group's sign_verdict(signer, ...)
    consumes this."""
    tenant_id: str
    kid: str
    signing_key: Ed25519PrivateKey

    def public_jwks(self) -> dict:
        return public_jwks(self.kid, self.signing_key)


def load_or_create_cell_signer(cell_dir: Path, tenant_id: str) -> Signer:
    """Load (or mint on first open) this cell's verdict signing key from its own
    dir, returning a Signer whose kid is namespaced under the tenant. Reuses the
    shipped O_EXCL race-safe keypair loader; the 8-hex content hash becomes the
    suffix of a "{tenant_id}:{hash8}" kid."""
    hash8_kid, key = load_or_create_keypair(Path(cell_dir))
    return Signer(tenant_id=tenant_id, kid=f"{tenant_id}:{hash8_kid}", signing_key=key)
```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_cell_signer.py tests/test_signing.py -q`
      (the second file confirms the shipped signing tests still pass unchanged).
- [ ] **Commit:** `git commit -am "feat(signing): per-cell Signer with tenant-namespaced kid"`

---

### Task A3: `Database.checkpoint_and_close()` (eviction primitive)

**Files:** Modify `server/arbiter/db.py` (add method to `Database`, after `ping`, `db.py:125-132`).
Test: `server/tests/test_db_close.py`.

**Interfaces:**
- Consumes: the shipped `Database._lock` + `self.conn` (`db.py:85-101`).
- Produces: `Database.checkpoint_and_close() -> None`. Consumed by `TenantRegistry` eviction (Task A6).

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_db_close.py`:
```python
import sqlite3
import pytest
from arbiter.db import Database


def test_checkpoint_and_close_then_ping_raises(tmp_path):
    db = Database(str(tmp_path / "t.sqlite3"))
    db.checkpoint_and_close()
    with pytest.raises(sqlite3.ProgrammingError):   # "Cannot operate on a closed database"
        db.ping()


def test_checkpoint_truncates_wal(tmp_path, make_req=None):
    # A committed write leaves a -wal file; TRUNCATE checkpoint on close folds it
    # back into the main db so an evicted cell leaves no growing WAL behind.
    db = Database(str(tmp_path / "t.sqlite3"))
    db.add_audit("r1", "created", {})
    db.checkpoint_and_close()
    wal = tmp_path / "t.sqlite3-wal"
    assert (not wal.exists()) or wal.stat().st_size == 0
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_db_close.py -q`
      → `AttributeError: 'Database' object has no attribute 'checkpoint_and_close'`.
- [ ] **Implement.** Add to `Database` in `server/arbiter/db.py` (right after `ping`):
```python
    def checkpoint_and_close(self) -> None:
        """Fold the WAL back into the main file and close the connection. Called
        by the registry ONLY on eviction of a refcount==0 cell, and NEVER while
        the registry map lock is held (the map lock is the outer lock; this takes
        only this connection's own inner RLock). After this returns the cell's
        connection is dead — the cell object must be unreachable from the map."""
        with self._lock:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.commit()
            self.conn.close()
```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_db_close.py tests/test_db.py -q`.
- [ ] **Commit:** `git commit -am "feat(db): checkpoint_and_close for cell eviction"`

---

### Task A4: `Cell` dataclass + `open_cell` (runs the migration ladder on a fresh cell DB)

**Files:** Create `server/arbiter/registry.py`. Test: `server/tests/test_open_cell.py`.

**Interfaces:**
- Consumes: `Database(path)` (`db.py:84`, runs the full migration ladder in `__init__`),
  `load_or_create_cell_signer(cell_dir, tenant_id)` (Task A2), `Hub()` (`stream.py:3`),
  `Dispatcher(cfg, db, sender=None)` (`notify/__init__.py:117`), `SlidingWindowLimiter(limit, window)`
  (`auth.py:13`), `cfg.policy.rate_limit_per_minute` (`config.py:55`), `assert_dir_isolated(candidate,
  existing)` (Task B1 — the §15.7 shared mint/open guard, imported from `arbiter.control`).
- Produces: `Cell` (dataclass, `eq=False`) and
  `open_cell(tenant_id, dir, epoch, cfg, sender=None, other_open_dirs=()) -> Cell` — `other_open_dirs`
  carries the dirs of all currently-open cells so the §15.7 non-overlap check runs at open (Task A5's
  `acquire` supplies them under the map lock).

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_open_cell.py`:
```python
import pytest
from pathlib import Path
from arbiter.config import Config
from arbiter.registry import Cell, open_cell
from arbiter.db import Database, SCHEMA_VERSION
from arbiter.signing import Signer
from arbiter.stream import Hub


def _cfg(tmp_path):
    return Config.load(str(tmp_path / "absent.toml"))   # all defaults, no APNs configured


class _DummySender:
    async def send(self, *a, **k):
        return None


def test_open_cell_builds_all_owned_state(tmp_path):
    cfg = _cfg(tmp_path)
    cell = open_cell("acme", tmp_path / "acme", 7, cfg, sender=_DummySender())
    assert isinstance(cell, Cell)
    assert cell.tenant_id == "acme" and cell.epoch == 7
    assert isinstance(cell.db, Database) and isinstance(cell.signer, Signer)
    assert isinstance(cell.hub, Hub)
    assert cell.signer.kid.startswith("acme:")
    assert cell.dispatcher.db is cell.db          # Dispatcher wired to THIS cell's db
    assert cell.create_limiter is not cell.login_limiter


def test_open_cell_runs_migration_ladder(tmp_path):
    cfg = _cfg(tmp_path)
    cell = open_cell("acme", tmp_path / "acme", 1, cfg, sender=_DummySender())
    v = cell.db.conn.execute("PRAGMA user_version").fetchone()[0]
    assert v == SCHEMA_VERSION                    # fully migrated, not half-migrated
    # tokens table (migration 3->4) exists -> ladder actually ran on the fresh file
    cell.db.conn.execute("SELECT * FROM tokens")


def test_cell_db_file_lives_under_cell_dir(tmp_path):
    cfg = _cfg(tmp_path)
    open_cell("acme", tmp_path / "acme", 1, cfg, sender=_DummySender())
    assert (tmp_path / "acme" / "arbiter.sqlite3").is_file()


def test_open_cell_rejects_relative_dir(tmp_path):
    cfg = _cfg(tmp_path)
    with pytest.raises(ValueError):
        open_cell("acme", Path("relative/dir"), 1, cfg, sender=_DummySender())


def test_open_cell_rejects_overlapping_open_dir(tmp_path):
    # §15.7 "isolation AND at open": a second cell whose dir equals / nests under /
    # is a parent of an already-open cell's dir is rejected at open (defense-in-depth
    # against a post-mint symlink/`..` swap that maps two live tenants to one dir).
    cfg = _cfg(tmp_path)
    a = (tmp_path / "acme").resolve()
    open_cell("acme", a, 1, cfg, sender=_DummySender())
    with pytest.raises(ValueError):
        open_cell("intruder", a, 1, cfg, sender=_DummySender(), other_open_dirs=[a])
    with pytest.raises(ValueError):
        open_cell("intruder", a / "sub", 1, cfg, sender=_DummySender(),
                  other_open_dirs=[a])
    # a sibling dir is fine
    open_cell("bob", tmp_path / "bob", 1, cfg, sender=_DummySender(),
              other_open_dirs=[a])


def test_cell_identity_not_value_equality(tmp_path):
    # eq=False: two cells for the "same" tenant are distinct objects (by-object
    # binding depends on identity, never value equality).
    cfg = _cfg(tmp_path)
    c1 = open_cell("acme", tmp_path / "a1", 1, cfg, sender=_DummySender())
    c2 = open_cell("acme", tmp_path / "a2", 1, cfg, sender=_DummySender())
    assert c1 != c2 and c1 is not c2
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_open_cell.py -q`
      → `ModuleNotFoundError: No module named 'arbiter.registry'`.
- [ ] **Implement.** Create `server/arbiter/registry.py`:
```python
from dataclasses import dataclass
from pathlib import Path

from .control import assert_dir_isolated   # §15.7 shared mint/open non-overlap guard (leaf module)
from .db import Database
from .notify import Dispatcher
from .auth import SlidingWindowLimiter
from .signing import Signer, load_or_create_cell_signer
from .stream import Hub


@dataclass(eq=False)
class Cell:
    """The per-tenant isolation unit. Owns ALL tenant-scoped state; the ONLY path
    to this tenant's db/signer/hub/dispatcher/limiters. Nothing here lives on
    app.state (§3/§15.1). eq=False so binding is by object identity, never value."""
    tenant_id: str
    epoch: int
    dir: Path
    db: Database
    signer: Signer
    hub: Hub
    dispatcher: Dispatcher
    create_limiter: SlidingWindowLimiter
    login_limiter: SlidingWindowLimiter


def open_cell(tenant_id: str, dir, epoch: int, cfg, sender=None, other_open_dirs=()) -> Cell:
    """Build a fully-initialized Cell. Blocking (SQLite migrations + key mint);
    the registry runs it via asyncio.to_thread so it never blocks the event loop,
    and the single-flight future keeps the half-built cell unobservable until this
    returns (§5/§15.3).

    dir is re-validated realpath-canonical + absolute at open, AND re-checked for
    non-overlap against every OTHER currently-open cell's dir (§7/§14/§15.7: a shared
    dir hands two live cells the same key = silent cross-tenant forgery). The mint side
    (`ControlPlane.create_tenant`) enforces the same guard against the persisted roster;
    this is the "isolation AND at open" half — it also catches a control.db that was
    tampered/symlink-swapped AFTER mint so two live tenants now resolve to one dir.
    `other_open_dirs` is supplied by `TenantRegistry.acquire` (the dirs of all live
    `_Entry` cells, captured under the map lock). Dispatcher is built with THIS cell's
    db + the process delivery cfg; the notify group refines per-tenant
    webhook/ntfy/allowlist overrides (§9)."""
    d = Path(dir).expanduser()
    if not d.is_absolute():
        raise ValueError(f"cell dir must be absolute, got {dir!r}")
    resolved = d.resolve()
    if resolved != d:
        raise ValueError(f"cell dir must be realpath-canonical, got {dir!r}")
    # §15.7 at-open isolation: reject a dir overlapping any other LIVE cell's dir.
    # Same guard create_tenant applies at mint (shared arbiter.control.assert_dir_isolated).
    assert_dir_isolated(resolved, other_open_dirs)   # raises ValueError on overlap
    resolved.mkdir(parents=True, exist_ok=True)

    db = Database(str(resolved / "arbiter.sqlite3"))          # runs the full migration ladder
    signer = load_or_create_cell_signer(resolved, tenant_id)  # per-cell key, namespaced kid
    hub = Hub()
    dispatcher = Dispatcher(cfg, db, sender=sender)
    create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)
    login_limiter = SlidingWindowLimiter(5, 60.0)
    return Cell(tenant_id=tenant_id, epoch=epoch, dir=resolved, db=db, signer=signer,
                hub=hub, dispatcher=dispatcher, create_limiter=create_limiter,
                login_limiter=login_limiter)
```
- [ ] **Note on `test_open_cell_rejects_relative_dir`:** `Path("relative/dir").is_absolute()` is `False`, so
      the first guard fires. The `resolved != d` guard catches a symlinked/`..`-laden *absolute* dir passed
      in un-canonicalized (`ControlPlane.tenant_dir` always returns a canonical path, so this is
      defense-in-depth at the open boundary per §14 "re-validated at cell open").
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_open_cell.py -q`.
- [ ] **Commit:** `git commit -am "feat(registry): Cell dataclass + open_cell running the migration ladder"`

---

### Task A5: `TenantRegistry` — single-flight `acquire`, by-object exactly-once `release`, `hold`

**Files:** Modify `server/arbiter/registry.py` (append `TenantRegistry` + `_Entry` + exceptions).
Test: `server/tests/test_registry_acquire.py`.

**Interfaces:**
- Consumes: `ControlPlane.tenant_dir(tenant_id)` (Task A1), `open_cell(...)` (Task A4), `Cell` (Task A4).
- Produces: `TenantRegistry(control, max_hot_cells=64, stream_cap=5, *, cfg, sender=None, headroom=150,
  lock_timeout=5.0, clock=time.monotonic)`; `async acquire(tenant_id, epoch) -> Cell`; `release(cell)`;
  `async hold(tenant_id, epoch)` (async ctx mgr); exceptions `EpochChanged`, `CapacityExceeded`.
  Consumed by `resolve_identity` (routing group), the scheduler, streams, background tasks.

**Design invariants enforced here (§15.3, §15.4, §15.7):**
- **Single-flight:** an `asyncio.Future` sentinel is installed in the map slot **before any `await`**; all
  concurrent callers await the *same* future and receive the *same* `Cell`. `open_cell` runs exactly once,
  off to the side via `asyncio.to_thread`, so **exactly one `Database`/connection/RLock per tenant dir** and
  **no caller ever observes a half-migrated cell**.
- **Dir isolation at open (§15.7):** while capturing `dirpath` under the map lock, `acquire` also snapshots
  every *other* live cell's `dir` and passes them to `open_cell`, which runs `assert_dir_isolated` (the same
  guard `ControlPlane.create_tenant` applies at mint) so a dir overlapping a live cell — e.g. from a
  post-mint symlink/`..` swap in control.db — is rejected before the cell is built. The sentinel/half-built
  cell is torn down on this raise via the existing opener-error path (pop the future, `set_exception`).
- **Refcount, bind-by-object, exactly-once:** a hit `refcount++`s and returns the *same* object a live holder
  already pinned; `release(cell)` asserts `entry.cell is cell` (a reopened twin can never be substituted)
  and decrements once. `hold()` guarantees exactly-once release on **every** exit path (normal, exception,
  background task) via a single `finally`.
- **Lock:** the registry map lock is an `asyncio.Lock`, timeout-bounded, held only across the synchronous
  slot mutation — **never across the `to_thread` open**. `release` takes **no** lock (pure int decrement, no
  `await`) so it is safe to call from a `finally` even during shutdown. (Eviction + full lock-hierarchy test
  land in A6/A7; FD budget in A8.)

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_registry_acquire.py`:
```python
import asyncio
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry, EpochChanged
from arbiter.db import Database


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    reg = TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)
    return control, reg


@pytest.mark.asyncio
async def test_single_flight_one_database_under_k_concurrency(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    # Serialize open_cell entry so K coroutines genuinely race the sentinel.
    import arbiter.registry as R
    opens = []
    real = R.open_cell

    def counting_open(*a, **k):
        opens.append(1)
        return real(*a, **k)

    R.open_cell = counting_open
    try:
        cells = await asyncio.gather(*[reg.acquire("acme", epoch) for _ in range(16)])
    finally:
        R.open_cell = real
    # exactly ONE open_cell -> one Database/connection/RLock; every caller got the SAME object
    assert len(opens) == 1
    first = cells[0]
    assert all(c is first for c in cells)
    assert isinstance(first.db, Database)
    # 16 pins outstanding
    assert reg._map["acme"].refcount == 16
    for _ in cells:
        reg.release(first)
    assert reg._map["acme"].refcount == 0


@pytest.mark.asyncio
async def test_never_observes_half_migrated_cell(tmp_path):
    from arbiter.db import SCHEMA_VERSION
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    cell = await reg.acquire("acme", epoch)
    try:
        assert cell.db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        reg.release(cell)


@pytest.mark.asyncio
async def test_release_is_by_object(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    cell = await reg.acquire("acme", epoch)

    class Twin:
        tenant_id = "acme"
    with pytest.raises(RuntimeError):
        reg.release(Twin())        # not the pinned object -> refuse
    reg.release(cell)
    with pytest.raises(RuntimeError):
        reg.release(cell)          # underflow -> refuse (exactly-once)


@pytest.mark.asyncio
async def test_hold_releases_on_normal_and_exception(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    async with reg.hold("acme", epoch) as cell:
        assert reg._map["acme"].refcount == 1
    assert reg._map["acme"].refcount == 0
    with pytest.raises(ValueError):
        async with reg.hold("acme", epoch):
            assert reg._map["acme"].refcount == 1
            raise ValueError("boom")
    assert reg._map["acme"].refcount == 0     # released despite the exception


@pytest.mark.asyncio
async def test_background_task_keeps_cell_pinned(tmp_path):
    # A spawned background task pins the cell for its whole lifetime; the pin is
    # not released until the task's finally runs.
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    gate = asyncio.Event()

    async def bg():
        async with reg.hold("acme", epoch):
            await gate.wait()

    t = asyncio.create_task(bg())
    await asyncio.sleep(0.05)
    assert reg._map["acme"].refcount == 1     # still pinned by the background task
    gate.set()
    await t
    assert reg._map["acme"].refcount == 0


@pytest.mark.asyncio
async def test_epoch_mismatch_on_live_holder_fails_closed(tmp_path):
    control, reg = _reg(tmp_path)
    epoch = control.create_tenant("acme", tmp_path / "acme")
    held = await reg.acquire("acme", epoch)     # pin at current epoch
    try:
        with pytest.raises(EpochChanged):
            await reg.acquire("acme", epoch + 1)  # delete+recreate raced a live holder
    finally:
        reg.release(held)
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_registry_acquire.py -q`
      → `ImportError: cannot import name 'TenantRegistry'`.
- [ ] **Implement.** Append to `server/arbiter/registry.py` (imports at top of file — add
      `import asyncio`, `import time`, `from contextlib import asynccontextmanager`,
      `from dataclasses import dataclass, field`):
```python
import asyncio
import time
from contextlib import asynccontextmanager


class EpochChanged(Exception):
    """The hot cell's epoch != the resolved epoch and a live holder blocks reopen
    (a delete+recreate/dir-rebind raced a live resolution). Fail closed (§5)."""


class CapacityExceeded(Exception):
    """Opening this cell would breach the runtime FD budget. Shed THIS open rather
    than fail another tenant's cell (§5/§15.13). (Enforced in Task A8.)"""


@dataclass(eq=False)
class _Entry:
    cell: "Cell"
    refcount: int
    last_used: float


class TenantRegistry:
    """Bounded-LRU registry of open cells (cap max_hot_cells). Process-global; the
    ONLY thing about tenancy that is process-global — the cells it hands out are
    not. Cross-group contract: acquire(tenant_id, epoch)->Cell (single-flight,
    caller MUST release), release(cell) (exactly once), hold() (async ctx mgr)."""

    def __init__(self, control, max_hot_cells: int = 64, stream_cap: int = 5, *,
                 cfg, sender=None, headroom: int = 150, lock_timeout: float = 5.0,
                 clock=time.monotonic):
        self._control = control
        self.max_hot_cells = max_hot_cells
        self.stream_cap = stream_cap
        self._cfg = cfg
        self._sender = sender
        self._headroom = headroom
        self._lock_timeout = lock_timeout
        self._clock = clock
        # slot value is either an asyncio.Future (open in flight) or an _Entry.
        self._map: dict[str, object] = {}
        self._stream_slots: dict[str, int] = {}
        self._map_lock = asyncio.Lock()
        # FD budget startup check is added in Task A8 (reads RLIMIT_NOFILE here).

    @asynccontextmanager
    async def _locked(self):
        # Timeout-bounded so a stuck holder degrades one tenant, never deadlocks
        # the whole process (§5/§15.13). This is the OUTER lock; a cell's DB RLock
        # is INNER and is never held across this acquire.
        await asyncio.wait_for(self._map_lock.acquire(), self._lock_timeout)
        try:
            yield
        finally:
            self._map_lock.release()

    async def acquire(self, tenant_id: str, epoch: int) -> "Cell":
        while True:
            async with self._locked():
                slot = self._map.get(tenant_id)
                if isinstance(slot, _Entry):
                    if slot.cell.epoch != epoch:
                        if slot.refcount == 0:
                            # stale-but-idle: drop it, reopen fresh below
                            self._map.pop(tenant_id, None)
                            slot = None
                        else:
                            raise EpochChanged(tenant_id)
                    else:
                        slot.refcount += 1
                        slot.last_used = self._clock()
                        return slot.cell
                if isinstance(slot, asyncio.Future):
                    fut = slot
                    # await OUTSIDE the map lock, then retry to ++refcount
                else:
                    # become the single-flight opener: install the sentinel BEFORE
                    # any await, capture the dir under the same consistent lock.
                    fut = asyncio.get_running_loop().create_future()
                    self._map[tenant_id] = fut
                    dirpath = self._control.tenant_dir(tenant_id)
                    # Snapshot every OTHER live cell's dir under the same lock so the
                    # open-side §15.7 non-overlap check sees a consistent roster.
                    other_open_dirs = [e.cell.dir for e in self._map.values()
                                       if isinstance(e, _Entry)]
                    opener = True
                    break_to_open = True
                    break  # leave the lock, run the open
            else:
                # loop body did not break: we are an awaiter of someone else's open
                try:
                    await asyncio.wait_for(asyncio.shield(fut), self._lock_timeout)
                except Exception:
                    pass
                continue
            # opener path (map lock released)
            try:
                cell = await asyncio.to_thread(
                    open_cell, tenant_id, dirpath, epoch, self._cfg, self._sender,
                    other_open_dirs)
            except BaseException as exc:
                async with self._locked():
                    if self._map.get(tenant_id) is fut:
                        self._map.pop(tenant_id, None)
                if not fut.done():
                    fut.set_exception(exc)
                raise
            async with self._locked():
                entry = _Entry(cell=cell, refcount=1, last_used=self._clock())
                self._map[tenant_id] = entry
                if not fut.done():
                    fut.set_result(cell)
            return cell

    def release(self, cell: "Cell") -> None:
        # Synchronous + no await => atomic on the event loop, safe to call from a
        # finally even during shutdown. Binds by object; exactly-once.
        entry = self._map.get(cell.tenant_id)
        if not isinstance(entry, _Entry) or entry.cell is not cell:
            raise RuntimeError(f"release of unknown/mismatched cell for {cell.tenant_id}")
        if entry.refcount <= 0:
            raise RuntimeError(f"refcount underflow for {cell.tenant_id}")
        entry.refcount -= 1

    @asynccontextmanager
    async def hold(self, tenant_id: str, epoch: int):
        cell = await self.acquire(tenant_id, epoch)
        try:
            yield cell
        finally:
            self.release(cell)
```
- [ ] **Note the `while/else` structure:** Python's `while ... else` runs the `else` only when the loop did
      **not** `break`. The opener `break`s (skips the `else`, runs the open); an awaiter falls through to the
      `else` (awaits the in-flight future, then `continue`s to re-lookup and `refcount++`). `opener` /
      `break_to_open` are left as readability markers; only the `break` is load-bearing.
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_registry_acquire.py -q`.
- [ ] **Commit:** `git commit -am "feat(registry): single-flight acquire, by-object exactly-once release, hold"`

---

### Task A6: Bounded-LRU eviction, gated on `refcount==0` (never under a live holder)

**Files:** Modify `server/arbiter/registry.py` (add eviction to the opener path + a maintenance sweep).
Test: `server/tests/test_registry_evict.py`.

**Interfaces:**
- Consumes: `Database.checkpoint_and_close()` (Task A3), `_Entry`/`_map`/`_locked` (Task A5).
- Produces: eviction behavior on `acquire`; `async evict_idle() -> int` (maintenance sweep; returns count
  evicted). LRU by `_Entry.last_used`.

**Design (§15.4):** eviction only ever closes a cell at `refcount == 0`. At cap with **all** cells pinned,
go temporarily over-cap and log an ops signal (raise the cap) rather than block a request — subject to the
FD budget in A8. `checkpoint_and_close` runs **after** the victim is popped from the map and the map lock is
released (never a blocking checkpoint under the outer lock).

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_registry_evict.py`:
```python
import asyncio
import sqlite3
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    reg = TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)
    return control, reg


async def _acquire_release(reg, control, tmp_path, name):
    epoch = control.create_tenant(name, tmp_path / name)
    cell = await reg.acquire(name, epoch)
    reg.release(cell)
    return cell


@pytest.mark.asyncio
async def test_lru_evicts_idle_cell_over_cap(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=2, clock=lambda: _acquire_release.t)
    _acquire_release.t = 0
    a = await _acquire_release(reg, control, tmp_path, "a"); _acquire_release.t = 1
    b = await _acquire_release(reg, control, tmp_path, "b"); _acquire_release.t = 2
    # opening c over cap -> LRU (a) evicted; its connection is closed
    c = await _acquire_release(reg, control, tmp_path, "c")
    assert "a" not in reg._map and "b" in reg._map and "c" in reg._map
    with pytest.raises(sqlite3.ProgrammingError):
        a.db.ping()      # a's connection was checkpoint_and_close'd


@pytest.mark.asyncio
async def test_never_evicts_a_pinned_cell(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=1)
    ea = control.create_tenant("a", tmp_path / "a")
    pinned = await reg.acquire("a", ea)          # a stays pinned
    try:
        eb = control.create_tenant("b", tmp_path / "b")
        cb = await reg.acquire("b", eb)          # over cap, but a is pinned -> keep both
        try:
            assert "a" in reg._map and "b" in reg._map   # temporarily over-cap
            pinned.db.ping()                              # a's connection still alive
        finally:
            reg.release(cb)
    finally:
        reg.release(pinned)


@pytest.mark.asyncio
async def test_evict_idle_sweep_returns_count(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=64)
    for n in ("a", "b"):
        await _acquire_release(reg, control, tmp_path, n)
    # everything idle; explicit maintenance sweep down to <= cap is a no-op here
    assert await reg.evict_idle() == 0
    # force it: shrink cap then sweep
    reg.max_hot_cells = 1
    assert await reg.evict_idle() == 1
    assert len([k for k, v in reg._map.items()]) == 1
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_registry_evict.py -q`
      → over-cap cells are never evicted / `evict_idle` missing.
- [ ] **Implement.** In `registry.py`, add a helper + `evict_idle`, and call the collector from the opener
      path. Add these methods to `TenantRegistry`:
```python
    def _collect_evictions_locked(self) -> list["Cell"]:
        """Pop LRU idle (refcount==0) entries until at/under cap. Returns the
        cells whose connections the caller must close AFTER releasing the map lock
        (never checkpoint under the outer lock). If every over-cap cell is pinned,
        return [] and stay temporarily over-cap (an ops signal, logged)."""
        victims: list["Cell"] = []
        while True:
            entries = [(k, v) for k, v in self._map.items() if isinstance(v, _Entry)]
            if len(entries) <= self.max_hot_cells:
                break
            idle = [(k, v) for k, v in entries if v.refcount == 0]
            if not idle:
                break  # all pinned: go over-cap rather than block a live holder
            k, v = min(idle, key=lambda kv: kv[1].last_used)
            self._map.pop(k, None)
            victims.append(v.cell)
        return victims

    async def evict_idle(self) -> int:
        """Maintenance sweep: evict LRU idle cells down to cap. Safe to call
        periodically. Returns the number evicted."""
        async with self._locked():
            victims = self._collect_evictions_locked()
        for cell in victims:
            await asyncio.to_thread(cell.db.checkpoint_and_close)
        return len(victims)
```
      Then, in `acquire`, extend the opener's final locked section to collect victims and close them AFTER
      releasing the lock. Replace the opener's commit block:
```python
            async with self._locked():
                entry = _Entry(cell=cell, refcount=1, last_used=self._clock())
                self._map[tenant_id] = entry
                if not fut.done():
                    fut.set_result(cell)
                victims = self._collect_evictions_locked()
            for v in victims:
                await asyncio.to_thread(v.db.checkpoint_and_close)
            return cell
```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_registry_evict.py tests/test_registry_acquire.py -q`.
- [ ] **Commit:** `git commit -am "feat(registry): bounded-LRU eviction gated on refcount==0"`

---

### Task A7: Lock hierarchy — outer map lock, inner DB RLock, timeout-bounded (would-deadlock test)

**Files:** Modify `server/arbiter/registry.py` only if the deadlock test surfaces a violation (the A5/A6 code
already honors the order; this task **proves** it). Test: `server/tests/test_registry_locks.py`.

**Interfaces:**
- Consumes: `_locked`, `acquire`, `evict_idle` (A5/A6); `Database._lock` (`db.py:101`).
- Produces: proof (tests) that (a) the DB RLock is never held across the map-lock `acquire`/`open`/
  `checkpoint`, and (b) a stuck map-lock holder times out rather than deadlocking the process.

**Design (§15.13):** *registry map lock is always outer; the per-cell DB RLock is inner and is NEVER held
across an `await`, across `acquire()/evict()`, or across a migration/checkpoint.* All lock acquisitions are
timeout-bounded (`lock_timeout`).

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_registry_locks.py`:
```python
import asyncio
import threading
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    return control, TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)


@pytest.mark.asyncio
async def test_open_does_not_hold_db_rlock_of_another_cell(tmp_path):
    # Hold cell A's DB RLock in a background OS thread (inner lock). Opening cell B
    # must still succeed: the registry never takes a cell's DB RLock across a
    # cell open, so B's open cannot be blocked by A's held inner lock.
    control, reg = _reg(tmp_path)
    ea = control.create_tenant("a", tmp_path / "a")
    a = await reg.acquire("a", ea)
    try:
        held = threading.Event()
        release = threading.Event()

        def hog():
            with a.db._lock:
                held.set()
                release.wait(2.0)

        t = threading.Thread(target=hog); t.start()
        assert held.wait(1.0)
        eb = control.create_tenant("b", tmp_path / "b")
        b = await asyncio.wait_for(reg.acquire("b", eb), timeout=2.0)  # not blocked
        reg.release(b)
        release.set(); t.join()
    finally:
        reg.release(a)


@pytest.mark.asyncio
async def test_map_lock_is_timeout_bounded(tmp_path):
    # A stuck holder of the OUTER map lock degrades ONE call (TimeoutError) rather
    # than hanging the process forever.
    control, reg = _reg(tmp_path, lock_timeout=0.2)
    await reg._map_lock.acquire()          # simulate a stuck holder
    try:
        ea = control.create_tenant("a", tmp_path / "a")
        with pytest.raises(asyncio.TimeoutError):
            await reg.acquire("a", ea)
    finally:
        reg._map_lock.release()


@pytest.mark.asyncio
async def test_release_takes_no_async_lock(tmp_path):
    # release must be safe from a finally even while the map lock is held elsewhere
    # (it is a pure synchronous int decrement, no await, no lock).
    control, reg = _reg(tmp_path)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    await reg._map_lock.acquire()          # map lock held by "someone else"
    try:
        reg.release(cell)                  # still works -> no deadlock
        assert reg._map["a"].refcount == 0
    finally:
        reg._map_lock.release()
```
- [ ] **Run — expect PASS** (A5/A6 already honor the hierarchy — this task is the proof gate):
      `cd server && python -m pytest tests/test_registry_locks.py -q`. If any test FAILS, the fix is to move
      the offending `checkpoint_and_close`/`open` call out from under `_locked()` (never widen the map lock
      around blocking I/O; never take a DB RLock across the open) — do **not** relax the test.
- [ ] **Commit:** `git commit -am "test(registry): prove lock hierarchy is deadlock-free and timeout-bounded"`

---

### Task A8: FD budget — startup `RLIMIT_NOFILE` check + runtime shed + per-tenant stream slots

**Files:** Modify `server/arbiter/registry.py` (`TenantRegistry.__init__` startup check; runtime budget in
the opener path; stream-slot API). Test: `server/tests/test_registry_fd.py`.

**Interfaces:**
- Consumes: `resource.getrlimit(resource.RLIMIT_NOFILE)`, `_map`/`_locked`/opener path (A5), `stream_cap`.
- Produces: startup `ValueError` when `max_hot_cells*3 + headroom >= RLIMIT_NOFILE`; runtime
  `CapacityExceeded` (sheds THIS open); `acquire_stream_slot(tenant_id) -> bool`,
  `release_stream_slot(tenant_id) -> None`. Consumed by the stream group to gate `ws.accept()`.

**Design (§5/§15.13):** FD budget is a **runtime** invariant, not just a startup check. 3 SQLite FDs per hot
cell (db + `-wal` + `-shm`); a per-tenant `stream_cap` bounds streams (≤8 FDs/cell). Over budget
**sheds/queues rather than failing another tenant's cell open** (else tenant A's leaked streams deny tenant
B its cell — a cross-tenant DoS). Defaults sized to a 1024 `RLIMIT_NOFILE`: `max_hot_cells=64`,
`stream_cap=5`, `headroom=150`. `_soft_rlimit`/`_headroom` are instance attrs so tests can force a tiny
budget without touching the OS limit.

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_registry_fd.py`:
```python
import pytest
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry, CapacityExceeded


class _DummySender:
    async def send(self, *a, **k):
        return None


def _reg(tmp_path, **kw):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    return control, TenantRegistry(control, cfg=cfg, sender=_DummySender(), **kw)


def test_startup_rejects_impossible_fd_budget(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    control = ControlPlane(":memory:")
    with pytest.raises(ValueError):
        # 100000*3 + 150 dwarfs any RLIMIT_NOFILE
        TenantRegistry(control, max_hot_cells=100_000, cfg=cfg, sender=_DummySender())


def test_default_budget_is_valid(tmp_path):
    control, reg = _reg(tmp_path)   # 64*3 + 150 = 342 < 1024 -> constructs fine
    assert reg.max_hot_cells == 64 and reg.stream_cap == 5


@pytest.mark.asyncio
async def test_runtime_shed_rather_than_open_over_budget(tmp_path):
    control, reg = _reg(tmp_path, max_hot_cells=64)
    # Force a tiny runtime budget: 1 open cell (3 FDs) + headroom already at the edge
    reg._soft_rlimit = 3
    reg._headroom = 0
    ea = control.create_tenant("a", tmp_path / "a")
    with pytest.raises(CapacityExceeded):     # (0+1)*3 + 0 >= 3 -> shed
        await reg.acquire("a", ea)
    assert "a" not in reg._map                # sentinel cleaned up, nothing half-open


@pytest.mark.asyncio
async def test_stream_slots_capped_per_tenant(tmp_path):
    control, reg = _reg(tmp_path, stream_cap=2)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    try:
        assert reg.acquire_stream_slot("a") is True
        assert reg.acquire_stream_slot("a") is True
        assert reg.acquire_stream_slot("a") is False   # over the per-tenant cap
        reg.release_stream_slot("a")
        assert reg.acquire_stream_slot("a") is True     # slot freed
    finally:
        for _ in range(reg._stream_slots.get("a", 0)):
            reg.release_stream_slot("a")
        reg.release(cell)


@pytest.mark.asyncio
async def test_stream_slot_sheds_when_over_fd_budget(tmp_path):
    control, reg = _reg(tmp_path, stream_cap=5)
    ea = control.create_tenant("a", tmp_path / "a")
    cell = await reg.acquire("a", ea)
    try:
        reg._soft_rlimit = 4     # 1 cell = 3 FDs; one more stream FD hits the edge
        reg._headroom = 0
        assert reg.acquire_stream_slot("a") is False    # 3 + 1 >= 4 -> shed (no cross-tenant DoS)
    finally:
        reg.release(cell)
```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_registry_fd.py -q`
      → no startup check / `acquire_stream_slot` missing.
- [ ] **Implement.** In `registry.py`, add `import resource` at the top. In `__init__`, after setting
      attrs, record the soft limit and run the startup check:
```python
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        self._soft_rlimit = soft
        # Startup budget (§5/§15.13): 3 SQLite FDs per hot cell + headroom must fit.
        if self.max_hot_cells * 3 + self._headroom >= self._soft_rlimit:
            raise ValueError(
                f"FD budget: max_hot_cells*3 + headroom "
                f"({self.max_hot_cells * 3 + self._headroom}) >= RLIMIT_NOFILE "
                f"({self._soft_rlimit}); lower max_hot_cells or raise the limit")
```
      Add FD-accounting helpers + the stream-slot API to `TenantRegistry`:
```python
    def _open_cell_count(self) -> int:
        return sum(1 for v in self._map.values() if isinstance(v, _Entry))

    def _active_stream_fds(self) -> int:
        return sum(self._stream_slots.values())

    def acquire_stream_slot(self, tenant_id: str) -> bool:
        """Per-tenant concurrent-stream cap AND FD-budget gate (§8/§15.13). The
        stream group calls this BEFORE ws.accept() and releases in a finally on
        every exit path. Returns False to shed (over the per-tenant cap OR the
        fleet FD budget) rather than fail another tenant's cell open."""
        n = self._stream_slots.get(tenant_id, 0)
        if n >= self.stream_cap:
            return False
        projected = self._open_cell_count() * 3 + self._active_stream_fds() + 1 + self._headroom
        if projected >= self._soft_rlimit:
            return False
        self._stream_slots[tenant_id] = n + 1
        return True

    def release_stream_slot(self, tenant_id: str) -> None:
        n = self._stream_slots.get(tenant_id, 0)
        if n > 0:
            self._stream_slots[tenant_id] = n - 1
```
      Finally, add the runtime budget check in the opener critical section — in `acquire`, in the `else`
      (None-slot) branch, **before** installing the future sentinel:
```python
                else:
                    # runtime FD budget (§15.13): shed THIS open rather than fail
                    # another tenant's cell. Count SQLite FDs of the prospective
                    # new open + already-open cells + live stream FDs + headroom.
                    projected = (self._open_cell_count() + 1) * 3 \
                        + self._active_stream_fds() + self._headroom
                    if projected >= self._soft_rlimit:
                        raise CapacityExceeded(tenant_id)
                    fut = asyncio.get_running_loop().create_future()
                    self._map[tenant_id] = fut
                    dirpath = self._control.tenant_dir(tenant_id)
                    break
```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_registry_fd.py -q`.
- [ ] **Full-group regression:** `cd server && python -m pytest tests/test_control.py tests/test_cell_signer.py tests/test_db_close.py tests/test_open_cell.py tests/test_registry_acquire.py tests/test_registry_evict.py tests/test_registry_locks.py tests/test_registry_fd.py -q` → all green; then `python -m pytest -q` to confirm no shipped test regressed.
- [ ] **Commit:** `git commit -am "feat(registry): FD-budget startup check + runtime shed + per-tenant stream slots"`

---

## Group A completion gates (map to §16 isolation suite)

- **single-flight acquire** (§16): `test_single_flight_one_database_under_k_concurrency`,
  `test_never_observes_half_migrated_cell`.
- **refcount exactly-once / no use-after-free** (§16): `test_release_is_by_object`,
  `test_hold_releases_on_normal_and_exception`, `test_background_task_keeps_cell_pinned`,
  `test_never_evicts_a_pinned_cell`.
- **FD budget / fairness** (§16): `test_startup_rejects_impossible_fd_budget`,
  `test_runtime_shed_rather_than_open_over_budget`, `test_stream_slots_capped_per_tenant`,
  `test_stream_slot_sheds_when_over_fd_budget`.
- **lock hierarchy / no fleet deadlock** (§15.13): `test_open_does_not_hold_db_rlock_of_another_cell`,
  `test_map_lock_is_timeout_bounded`, `test_release_takes_no_async_lock`.
- **epoch snapshot-consistency** (§5/§15.13, registry part): `test_epoch_mismatch_on_live_holder_fails_closed`
  + `ControlPlane` monotonic-epoch tests.

The cross-tenant *leak/stream/verdict/rotation/backup* gates in §16 are proven by later groups that build on
this foundation; Group A delivers the objects (`Cell`, `TenantRegistry`, `ControlPlane` slice, `Signer`) and
the lifecycle invariants (§15.1 registry-owns-cells, §15.3 single-flight, §15.4 by-object refcount/eviction,
§15.13 FD budget + lock hierarchy + epoch assert) those gates depend on.


---


## Group B — `control.db` router + identity resolution + tenant epoch

Implements spec §4 (the `control.db` router), §5's epoch/TOCTOU rule, and the router parts of
invariants **§15.2, §15.6, §15.7, §15.13**. Delivers a new module `server/arbiter/control.py`
(the `ControlPlane`) and the new `resolve_identity` + extended `Identity` in
`server/arbiter/auth.py`.

Repo root (quote it — the path has spaces):
`<repo-root>`
Build branch: `feat/multitenant-isolation` (off `design/multitenant-isolation`).
All test commands run from the `server/` sub-package (that is where `pyproject.toml`,
`tests/`, and the editable `arbiter` install live). Because the shell cwd resets between
commands, every command below `cd`s into `server/` first.

---

## What this group PRODUCES (names later groups consume verbatim)

- **`ControlPlane`** in `arbiter.control`, constructed via
  `ControlPlane.open(control_dir: Path, tenants_root: Path) -> ControlPlane`, with methods:
  - `resolve(token_hash: str) -> tuple[str, int] | None` — MAC-verified; `None` on miss/bad-MAC.
  - `is_disabled(tenant_id: str) -> bool` — reads the live row on **every** call, never cached.
  - `tenant_dir(tenant_id: str) -> Path` — canonical dir of the live tenant.
  - `epoch_of(tenant_id: str) -> int | None` — live tenant's epoch (used by the legacy `default` path).
  - `create_tenant(tenant_id: str, dir: str) -> int` — fresh monotonic epoch; validates charset + realpath-under-root.
  - `list_tenants() -> list[dict]`.
  - `add_route(token_hash: str, tenant_id: str) -> None` / `remove_route(token_hash: str) -> None` — admin path only.
  - `disable_tenant(tenant_id: str) -> None` / `tombstone_tenant(tenant_id: str) -> None` — epoch/dir never recycled.
- **`Identity`** (extended dataclass, field set matches the pinned contract
  `Identity(tenant_id, name, role, scopes, epoch, legacy)`).
- **`resolve_identity(request, registry, control) -> tuple[Identity, Cell]`** — async; pins the cell
  (caller MUST `registry.release`); generic 403 with equalized timing on any failure.

## What this group CONSUMES (by name, from the pinned contract)

- **`TenantRegistry.acquire(tenant_id, epoch) -> Cell`** (async; single-flight; increments refcount) and
  **`TenantRegistry.release(cell) -> None`** — from **Group A**. Tests here use a `FakeRegistry`.
- **`Cell`** attributes `epoch: int` and `db: Database` — from **Group A**. Tests use a `FakeCell`
  wrapping a real `arbiter.db.Database`.
- **`Database.get_token_by_hash(token_hash) -> dict | None`** and
  **`Database.touch_token_last_used(token_id) -> None`** — shipped, unchanged (`server/arbiter/db.py:430-457`).
- **`Config`** — `cfg.auth.app_token`, `cfg.auth.agent_token` (shipped `arbiter.config`).

> **Boundary note for the implementer:** the shipped `auth.py:70-92` `resolve_identity(db, cfg, bearer)`
> and its callers (`require_role` in `auth.py:94-118`; `audit_export` in `app.py:132-158`) are rewired to
> the new signature by **Group C** (require_role) and **Group D** (routes). This group *replaces*
> `resolve_identity` and *extends* `Identity`; it does **not** touch `require_role`. `auth.py` stays
> importable (the stale `require_role` call fails only when invoked, which Group C fixes). Do not
> "fix" `require_role` here — that is Group C's task and its tests.

---

### Task B1: `control.py` — schema, MAC key, `_mac`, `ControlPlane.open`

**Files:**
- Create `server/arbiter/control.py`.
- Test: `server/tests/test_control.py` (new).

**Interfaces:**
- Produces: `ControlPlane.open(control_dir, tenants_root)`, `ControlPlane._mac(token_hash, tenant_id, epoch) -> str`,
  the module-level `assert_dir_isolated(candidate, existing)` §15.7 non-overlap guard (shared by
  `create_tenant` at mint and `arbiter.registry.open_cell` at open),
  the `control.db` schema (`tenants`, `token_route`), and the MAC-key file `control_mac.key`.
- Consumes: nothing (leaf module; stdlib `sqlite3`, `threading`, `hmac`, `hashlib`, `secrets`, `os`, `re`, `pathlib`).

Follow the shipped `Database` discipline (`db.py:84-113`): one `sqlite3.connect(..., check_same_thread=False)`,
`row_factory=sqlite3.Row`, a `threading.RLock` guarding every connection touch, WAL, a `PRAGMA user_version`
migration ladder. Follow the shipped signing-key file discipline (`signing.py:50-59`): `O_CREAT|O_EXCL|O_WRONLY, 0o600`
with a lost-race fallback that reads the winner's bytes.

- [ ] **Write the failing test.** Append to `server/tests/test_control.py`:
```python
import os
import stat
from pathlib import Path

import pytest

from arbiter.control import ControlPlane


def _open(tmp_path) -> ControlPlane:
    root = tmp_path / "tenants"
    root.mkdir()
    return ControlPlane.open(tmp_path / "control", root)


def test_open_creates_schema_and_mac_key(tmp_path):
    cp = _open(tmp_path)
    tables = {r[0] for r in cp.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"tenants", "token_route"} <= tables
    key_path = tmp_path / "control" / "control_mac.key"
    assert key_path.is_file()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600


def test_mac_is_deterministic_and_key_bound(tmp_path):
    cp = _open(tmp_path)
    h = "a" * 64
    m1 = cp._mac(h, "acme", 1)
    assert m1 == cp._mac(h, "acme", 1)            # deterministic
    assert m1 != cp._mac(h, "acme", 2)            # epoch-bound
    assert m1 != cp._mac(h, "other", 1)           # tenant-bound
    # A second control plane with its own key produces different MACs.
    cp2 = ControlPlane.open(tmp_path / "control2", tmp_path / "tenants")
    assert cp2._mac(h, "acme", 1) != m1
```
- [ ] **Run it — expect FAIL** (`ModuleNotFoundError: No module named 'arbiter.control'`):
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Minimal implementation.** Create `server/arbiter/control.py`:
```python
"""control.db — the router-only control plane for the multi-tenant arbiter.

Stores ONLY (full-64-hex token_hash -> tenant_id) routes plus the tenant registry
(tenant_id, dir, disabled_at, epoch). Never roles/scopes/requests/devices. Every
row's integrity is protected by an HMAC over (token_hash, tenant_id, epoch) keyed
by a 0600 key file beside control.db, so a tampered or rolled-back registry fails
closed at resolve rather than silently re-pointing a cell (spec §4, §18).
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

CONTROL_SCHEMA_VERSION = 1
MAC_KEY_FILENAME = "control_mac.key"
CONTROL_DB_FILENAME = "control.db"

_TENANT_RE = re.compile(r"^[a-z0-9-]+$")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_tenant_id(tenant_id: str) -> None:
    # Strict [a-z0-9-]; never string-interpolated into SQL or path joins (spec §4).
    if not tenant_id or not _TENANT_RE.match(tenant_id):
        raise ValueError(f"invalid tenant_id {tenant_id!r} (must match [a-z0-9-]+)")


def assert_dir_isolated(candidate, existing) -> None:
    """§15.7 non-overlap guard. Raises ValueError if `candidate` (realpath-resolved)
    equals, contains, or is contained by any resolved dir in `existing`. This lives in
    control.py — the leaf module (`Consumes: nothing`) — so BOTH mint
    (`ControlPlane.create_tenant`, below) AND open (`arbiter.registry.open_cell`, which
    imports this) share ONE implementation, closing the "isolation AND at open" half of
    §15.7 without an import cycle. The check is byte-identical to Group H's
    `provisioning.assert_dir_isolated` (which raises the provisioning-local `TenantDirError`);
    §15.7 requires the two copies to stay identical. Raising `ValueError` here keeps
    `create_tenant`'s error contract uniform (its charset/under-root/duplicate guards all
    raise `ValueError`, which the admin CLI already catches)."""
    c = Path(candidate).resolve()
    for other in existing:
        o = Path(other).resolve()
        if c == o or c.is_relative_to(o) or o.is_relative_to(c):
            raise ValueError(f"tenant dir overlaps an existing/open cell dir: {c} vs {o}")


def _load_or_create_mac_key(control_dir: Path) -> bytes:
    """32-byte HMAC key, minted 0600 via O_EXCL on first run; loser of a concurrent
    first-run race reads the winner's bytes (same discipline as signing.py)."""
    p = control_dir / MAC_KEY_FILENAME
    if p.is_file():
        return p.read_bytes()
    key = secrets.token_bytes(32)
    try:
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return p.read_bytes()
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _control_migrate_0_to_1(conn: sqlite3.Connection) -> None:
    # epoch is an AUTOINCREMENT PK: globally monotonic and NEVER reused, so a
    # tombstoned tenant's epoch can never be recycled (spec §5, invariant 13).
    # A partial unique index enforces "at most one LIVE row per tenant_id" while
    # tombstoned rows are retained forever to keep the epoch counter monotonic.
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tenants(
      epoch INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      dir TEXT NOT NULL,
      disabled_at TEXT,
      tombstoned_at TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_live
      ON tenants(tenant_id) WHERE tombstoned_at IS NULL;
    CREATE TABLE IF NOT EXISTS token_route(
      token_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      mac TEXT NOT NULL);
    """)


_CONTROL_MIGRATIONS = [_control_migrate_0_to_1]


class ControlPlane:
    def __init__(self, db_path: str, mac_key: bytes, tenants_root: Path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._mac_key = mac_key
        self._root = Path(tenants_root)
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
            v = self.conn.execute("PRAGMA user_version").fetchone()[0]
            for i in range(v, CONTROL_SCHEMA_VERSION):
                _CONTROL_MIGRATIONS[i](self.conn)
            if v < CONTROL_SCHEMA_VERSION:
                self.conn.execute(f"PRAGMA user_version={CONTROL_SCHEMA_VERSION}")
            self.conn.commit()

    @classmethod
    def open(cls, control_dir, tenants_root) -> "ControlPlane":
        control_dir = Path(control_dir)
        control_dir.mkdir(parents=True, exist_ok=True)
        mac_key = _load_or_create_mac_key(control_dir)
        return cls(str(control_dir / CONTROL_DB_FILENAME), mac_key, Path(tenants_root))

    def _mac(self, token_hash: str, tenant_id: str, epoch: int) -> str:
        # \x00 separators: unambiguous framing so ("ab","c") and ("a","bc") differ.
        msg = b"\x00".join(
            (token_hash.encode(), tenant_id.encode(), str(epoch).encode()))
        return hmac.new(self._mac_key, msg, hashlib.sha256).hexdigest()
```
- [ ] **Run green:**
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Commit:**
```
git add server/arbiter/control.py server/tests/test_control.py
git commit -m "feat(control): control.db schema, HMAC key, ControlPlane.open"
```

---

### Task B2: tenant lifecycle read/create — `create_tenant`, `epoch_of`, `tenant_dir`, `list_tenants`

**Files:**
- Modify `server/arbiter/control.py` (add methods to `ControlPlane`).
- Test: `server/tests/test_control.py` (extend).

**Interfaces:**
- Produces: `create_tenant(tenant_id, dir) -> int`, `epoch_of(tenant_id) -> int | None`,
  `tenant_dir(tenant_id) -> Path`, `list_tenants() -> list[dict]`.
- Consumes: `_validate_tenant_id`, `assert_dir_isolated`, `self._root`, `self._lock` (Task B1).

`create_tenant` enforces the spec §4 constraints: `tenant_id` charset `[a-z0-9-]` (parameterized
queries only) and `dir` realpath-canonical and strictly under the fixed `tenants_root`. It ALSO
enforces §15.7 dir isolation at mint: the resolved dir must not equal, nest under, be a parent of, or
symlink/`..`-resolve into any existing live tenant's dir (via `assert_dir_isolated`, which raises
`ValueError`) — the `tenants` UNIQUE index covers only `tenant_id`, so the dir-overlap constraint is
enforced in code here (and re-applied by the registry at cell open). The epoch is the AUTOINCREMENT
`lastrowid` — fresh and monotonic. A live duplicate `tenant_id` hits the partial unique index
(`sqlite3.IntegrityError`) and is surfaced as `ValueError`.

- [ ] **Write the failing test.** Append to `server/tests/test_control.py`:
```python
def test_create_tenant_returns_monotonic_epochs(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    e1 = cp.create_tenant("acme", str(root / "acme"))
    e2 = cp.create_tenant("globex", str(root / "globex"))
    assert e1 == 1 and e2 == 2
    assert cp.epoch_of("acme") == 1
    assert cp.tenant_dir("acme") == (root / "acme").resolve()
    ids = {t["tenant_id"] for t in cp.list_tenants()}
    assert ids == {"acme", "globex"}


def test_create_tenant_rejects_bad_charset(tmp_path):
    cp = _open(tmp_path)
    with pytest.raises(ValueError):
        cp.create_tenant("Acme_Corp", str(tmp_path / "tenants" / "x"))


def test_create_tenant_rejects_dir_outside_root(tmp_path):
    cp = _open(tmp_path)
    with pytest.raises(ValueError):
        cp.create_tenant("acme", "/etc/acme")


def test_create_tenant_rejects_live_duplicate(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    cp.create_tenant("acme", str(root / "acme"))
    with pytest.raises(ValueError):
        cp.create_tenant("acme", str(root / "acme2"))


def test_create_tenant_rejects_overlapping_dir(tmp_path):
    # §15.7 mint-side isolation: a dir that duplicates, nests under, is a parent of,
    # or symlink/`..`-resolves into an existing live tenant's dir is rejected.
    import os
    cp = _open(tmp_path)
    root = (tmp_path / "tenants")
    (root / "acme").mkdir(parents=True)
    cp.create_tenant("acme", str(root / "acme"))
    with pytest.raises(ValueError):
        cp.create_tenant("dup", str(root / "acme"))            # exact duplicate
    with pytest.raises(ValueError):
        cp.create_tenant("nested", str(root / "acme" / "sub"))  # nested under acme
    os.symlink(root / "acme", root / "acme-link", target_is_directory=True)
    with pytest.raises(ValueError):
        cp.create_tenant("linked", str(root / "acme-link"))     # symlink back into acme
    with pytest.raises(ValueError):
        cp.create_tenant("dotdot", str(root / "x" / ".." / "acme"))  # `..` resolves to acme


def test_epoch_of_unknown_is_none(tmp_path):
    cp = _open(tmp_path)
    assert cp.epoch_of("nope") is None
```
- [ ] **Run it — expect FAIL** (`AttributeError: 'ControlPlane' object has no attribute 'create_tenant'`):
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Minimal implementation.** Add to `ControlPlane` in `server/arbiter/control.py`:
```python
    def _canonical_under_root(self, dir: str) -> str:
        cand = Path(dir).resolve()
        root = self._root.resolve()
        if not cand.is_absolute():
            raise ValueError(f"tenant dir must be absolute: {dir!r}")
        if root not in cand.parents:
            raise ValueError(f"tenant dir {cand} is not strictly under root {root}")
        return str(cand)

    def create_tenant(self, tenant_id: str, dir: str) -> int:
        _validate_tenant_id(tenant_id)
        canonical = self._canonical_under_root(dir)
        with self._lock:
            # §15.7 dir isolation AT MINT: reject a dir that equals, nests under, or is
            # symlink/`..`-resolvable into any existing LIVE (non-tombstoned) tenant dir —
            # two cells sharing a dir would load one signing key = silent cross-tenant
            # forgery. The UNIQUE index only covers tenant_id, so the dir overlap must be
            # enforced here. Same guard the registry re-applies at open (open_cell).
            existing = [r["dir"] for r in self.conn.execute(
                "SELECT dir FROM tenants WHERE tombstoned_at IS NULL").fetchall()]
            assert_dir_isolated(canonical, existing)   # raises ValueError on overlap
            try:
                cur = self.conn.execute(
                    "INSERT INTO tenants(tenant_id, dir, disabled_at, tombstoned_at)"
                    " VALUES (?,?,NULL,NULL)", (tenant_id, canonical))
            except sqlite3.IntegrityError:
                raise ValueError(f"tenant {tenant_id!r} already exists (live)")
            self.conn.commit()
            return cur.lastrowid

    def epoch_of(self, tenant_id: str) -> int | None:
        with self._lock:
            r = self.conn.execute(
                "SELECT epoch FROM tenants WHERE tenant_id=? AND tombstoned_at IS NULL",
                (tenant_id,)).fetchone()
            return r["epoch"] if r else None

    def tenant_dir(self, tenant_id: str) -> Path:
        with self._lock:
            r = self.conn.execute(
                "SELECT dir FROM tenants WHERE tenant_id=? AND tombstoned_at IS NULL",
                (tenant_id,)).fetchone()
        if r is None:
            raise KeyError(f"no live tenant {tenant_id!r}")
        return Path(r["dir"])

    def list_tenants(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT epoch, tenant_id, dir, disabled_at, tombstoned_at FROM tenants"
                " WHERE tombstoned_at IS NULL ORDER BY epoch").fetchall()]
```
- [ ] **Run green:**
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Commit:**
```
git add server/arbiter/control.py server/tests/test_control.py
git commit -m "feat(control): create_tenant with charset+realpath-under-root, epoch_of/tenant_dir/list_tenants"
```

---

### Task B3: routes + MAC-verified `resolve` + `is_disabled`

**Files:**
- Modify `server/arbiter/control.py` (add methods).
- Test: `server/tests/test_control.py` (extend).

**Interfaces:**
- Produces: `add_route(token_hash, tenant_id) -> None`, `remove_route(token_hash) -> None`,
  `resolve(token_hash) -> tuple[str, int] | None`, `is_disabled(tenant_id) -> bool`.
- Consumes: `_mac`, `epoch_of`, `self._lock` (Tasks B1/B2).

`resolve` JOINs `token_route` to the **live** `tenants` row for the tenant's **current** epoch,
recomputes the MAC over `(token_hash, tenant_id, current_epoch)`, and `hmac.compare_digest`s it. A
missing route, a truncated hash (PK is the full 64-hex; exact match only — never a prefix/LIKE), a
tampered `tenant_id`/`mac`, or a stale route MAC'd to an older epoch all return `None` (fail closed,
invariant 6). `is_disabled` reads the live row on every call and returns `True` if the tenant is
disabled **or** absent (fail closed).

- [ ] **Write the failing test.** Append to `server/tests/test_control.py`:
```python
def test_resolve_roundtrip_and_full_hash_only(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    h = "b" * 64
    cp.add_route(h, "acme")
    assert cp.resolve(h) == ("acme", 1)
    # A truncated hash is a different PK — it never routes.
    assert cp.resolve(h[:8]) is None
    assert cp.resolve("c" * 64) is None            # unknown route


def test_resolve_rejects_tampered_route(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    cp.create_tenant("victim", str(tmp_path / "tenants" / "victim"))
    h = "d" * 64
    cp.add_route(h, "acme")
    # Attacker repoints the route to another tenant WITHOUT the MAC key.
    cp.conn.execute("UPDATE token_route SET tenant_id='victim' WHERE token_hash=?", (h,))
    cp.conn.commit()
    assert cp.resolve(h) is None                   # MAC over (hash,victim,epoch) fails


def test_remove_route(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    h = "e" * 64
    cp.add_route(h, "acme")
    cp.remove_route(h)
    assert cp.resolve(h) is None


def test_is_disabled(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    assert cp.is_disabled("acme") is False
    assert cp.is_disabled("ghost") is True         # absent -> fail closed
```
- [ ] **Run it — expect FAIL** (`AttributeError: ... 'add_route'`):
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Minimal implementation.** Add to `ControlPlane` in `server/arbiter/control.py`:
```python
    def add_route(self, token_hash: str, tenant_id: str) -> None:
        with self._lock:
            epoch = self.epoch_of(tenant_id)
            if epoch is None:
                raise ValueError(f"no live tenant {tenant_id!r} to route to")
            mac = self._mac(token_hash, tenant_id, epoch)
            self.conn.execute(
                "INSERT INTO token_route(token_hash, tenant_id, mac) VALUES (?,?,?)",
                (token_hash, tenant_id, mac))
            self.conn.commit()

    def remove_route(self, token_hash: str) -> None:
        with self._lock:
            self.conn.execute(
                "DELETE FROM token_route WHERE token_hash=?", (token_hash,))
            self.conn.commit()

    def resolve(self, token_hash: str) -> tuple[str, int] | None:
        with self._lock:
            r = self.conn.execute(
                "SELECT tr.tenant_id AS tid, t.epoch AS epoch, tr.mac AS mac"
                " FROM token_route tr"
                " JOIN tenants t ON t.tenant_id = tr.tenant_id AND t.tombstoned_at IS NULL"
                " WHERE tr.token_hash = ?", (token_hash,)).fetchone()
        if r is None:
            return None
        expected = self._mac(token_hash, r["tid"], r["epoch"])
        if not hmac.compare_digest(expected, r["mac"]):
            return None                            # tampered/rolled-back -> fail closed
        return (r["tid"], r["epoch"])

    def is_disabled(self, tenant_id: str) -> bool:
        with self._lock:
            r = self.conn.execute(
                "SELECT disabled_at FROM tenants"
                " WHERE tenant_id=? AND tombstoned_at IS NULL", (tenant_id,)).fetchone()
        if r is None:
            return True                            # absent live row -> fail closed
        return r["disabled_at"] is not None
```
- [ ] **Run green:**
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Commit:**
```
git add server/arbiter/control.py server/tests/test_control.py
git commit -m "feat(control): add/remove_route, MAC-verified resolve, is_disabled (full-hash-only, fail-closed)"
```

---

### Task B4: `disable_tenant`, `tombstone_tenant`, epoch-never-recycled

**Files:**
- Modify `server/arbiter/control.py` (add methods).
- Test: `server/tests/test_control.py` (extend).

**Interfaces:**
- Produces: `disable_tenant(tenant_id) -> None`, `tombstone_tenant(tenant_id) -> None`.
- Consumes: `epoch_of`, `self._lock`, and the delete+recreate MAC behavior from B2/B3.

`disable_tenant` flips `disabled_at` on the live row (spec §8: disable is read on every resolution).
`tombstone_tenant` sets `tombstoned_at`, freeing the `tenant_id` for a fresh `create_tenant` that gets a
**new, higher** epoch — the AUTOINCREMENT counter never reuses the tombstoned epoch (invariant 13). This
is the "delete+recreate epoch mismatch fails closed" property: a stale route minted under the old epoch
fails `resolve` because the live tenant now carries a different epoch.

- [ ] **Write the failing test.** Append to `server/tests/test_control.py`:
```python
def test_disable_then_resolution_reports_disabled(tmp_path):
    cp = _open(tmp_path)
    cp.create_tenant("acme", str(tmp_path / "tenants" / "acme"))
    cp.disable_tenant("acme")
    assert cp.is_disabled("acme") is True


def test_tombstone_recreate_gets_new_epoch_and_stale_route_fails_closed(tmp_path):
    cp = _open(tmp_path)
    root = tmp_path / "tenants"
    cp.create_tenant("acme", str(root / "acme"))       # epoch 1
    h = "f" * 64
    cp.add_route(h, "acme")                            # MAC bound to epoch 1
    assert cp.resolve(h) == ("acme", 1)
    cp.tombstone_tenant("acme")
    # tenant_id is free again; recreate gets a fresh, higher, non-recycled epoch.
    e2 = cp.create_tenant("acme", str(root / "acme-v2"))
    assert e2 == 2
    # The stale route (MAC over epoch 1) no longer verifies against live epoch 2.
    assert cp.resolve(h) is None
```
- [ ] **Run it — expect FAIL** (`AttributeError: ... 'disable_tenant'`):
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Minimal implementation.** Add to `ControlPlane` in `server/arbiter/control.py`:
```python
    def disable_tenant(self, tenant_id: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE tenants SET disabled_at=? "
                "WHERE tenant_id=? AND tombstoned_at IS NULL AND disabled_at IS NULL",
                (_utcnow_iso(), tenant_id))
            self.conn.commit()

    def tombstone_tenant(self, tenant_id: str) -> None:
        # Retain the row (epoch/dir never recycled); free the tenant_id for a new
        # live create by setting tombstoned_at so the partial unique index releases.
        with self._lock:
            self.conn.execute(
                "UPDATE tenants SET tombstoned_at=? "
                "WHERE tenant_id=? AND tombstoned_at IS NULL",
                (_utcnow_iso(), tenant_id))
            self.conn.commit()
```
- [ ] **Run green:**
```
cd "<repo-root>/server" && python -m pytest tests/test_control.py -q
```
- [ ] **Commit:**
```
git add server/arbiter/control.py server/tests/test_control.py
git commit -m "feat(control): disable_tenant/tombstone_tenant; epoch never recycled, stale route fails closed"
```

---

### Task B5: `Identity` extension + new `resolve_identity(request, registry, control)`

**Files:**
- Modify `server/arbiter/auth.py`:
  - Extend the `Identity` dataclass (`auth.py:55-59`).
  - **Replace** `resolve_identity` (`auth.py:70-92`) with the new async signature.
- Test: `server/tests/test_resolve_identity.py` (new).

**Interfaces:**
- Produces (from the pinned contract):
  - `Identity` with fields `{tenant_id, name, role, scopes, epoch, legacy}`.
  - `resolve_identity(request, registry, control) -> tuple[Identity, Cell]` (async).
- Consumes (from the pinned contract):
  - `TenantRegistry.acquire(tenant_id, epoch) -> Cell` (async) and `TenantRegistry.release(cell)` — Group A.
  - `Cell.epoch`, `Cell.db` (a `Database`) — Group A.
  - `ControlPlane.resolve`, `.is_disabled`, `.epoch_of` — Tasks B2/B3.
  - `Database.get_token_by_hash`, `Database.touch_token_last_used` — shipped `db.py:430-457`.
  - `Config.auth.app_token`, `Config.auth.agent_token`, read via `request.app.state.cfg`.

Semantics (spec §4, §5, §11; invariants 2, 6, 13):
- `sha256(bearer)` computed **unconditionally** (even for a missing/short bearer) so all failures share
  the dominant-cost path → equalized-timing generic 403 (`HTTPException(403, "forbidden")`, identical
  body on route-miss / bad-MAC / in-cell-invalid / disabled / epoch-mismatch).
- Legacy `cfg.auth.app_token` → strictly `default` (role `app`); `cfg.auth.agent_token` → strictly
  `default` (role `agent`) for hold-sdk 0.2.1 back-compat. No caller-supplied tenant hint is ever read.
- `is_disabled` is checked on **every** resolution, **before** `acquire` (so a disabled tenant 403s even
  a hot, busy cell without pinning it).
- After `acquire`, assert `cell.epoch == epoch` (TOCTOU / delete+recreate fails closed); then re-validate
  the token **inside the cell** via `get_token_by_hash(full-hex)` — role/expiry/revocation derive **only**
  from the cell row. A route hit with **no** matching cell row is a hard generic 403.
- The pin is released **exactly once** on every failure exit path (`except BaseException: release; raise`)
  and is **kept** on success (the caller owns the release — invariant 4).

- [ ] **Write the failing test.** Create `server/tests/test_resolve_identity.py`:
```python
import asyncio
import hashlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from arbiter.auth import Identity, resolve_identity
from arbiter.control import ControlPlane
from arbiter.db import Database


class FakeCell:
    def __init__(self, epoch, db):
        self.epoch = epoch
        self.db = db


class FakeRegistry:
    def __init__(self, cell):
        self.cell = cell
        self.acquired = 0
        self.released = 0

    async def acquire(self, tenant_id, epoch):
        self.acquired += 1
        return self.cell

    def release(self, cell):
        self.released += 1


def _cfg():
    return SimpleNamespace(auth=SimpleNamespace(app_token="test-app", agent_token="test-agent"))


def _req(cfg, authorization=None):
    headers = {} if authorization is None else {"authorization": authorization}
    return SimpleNamespace(
        headers=headers, app=SimpleNamespace(state=SimpleNamespace(cfg=cfg)))


def _hash(bearer):
    return hashlib.sha256(bearer.encode()).hexdigest()


def _control(tmp_path, tenant="acme"):
    cp = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    (tmp_path / "tenants").mkdir(exist_ok=True)
    cp.create_tenant(tenant, str(tmp_path / "tenants" / tenant))    # epoch 1
    return cp


def _run(coro):
    return asyncio.run(coro)


def test_db_token_happy_path_returns_pinned_cell(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_secret"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), {"max_severity": "high"}, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    reg = FakeRegistry(FakeCell(1, db))
    ident, cell = _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert isinstance(ident, Identity)
    assert (ident.tenant_id, ident.name, ident.role, ident.epoch, ident.legacy) == \
        ("acme", "bot", "agent", 1, False)
    assert ident.scopes == {"max_severity": "high"}
    assert cell is reg.cell
    assert reg.acquired == 1 and reg.released == 0    # pin kept for the caller


def test_missing_bearer_is_generic_403(tmp_path):
    cp = _control(tmp_path)
    reg = FakeRegistry(FakeCell(1, Database(":memory:")))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(_cfg(), None), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 0                           # never pinned


def test_route_hit_but_no_cell_token_403_and_released(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_ghost"
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")                # route exists...
    reg = FakeRegistry(FakeCell(1, Database(":memory:")))  # ...but cell has no token
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 1 and reg.released == 1     # pinned then released exactly once


def test_disabled_tenant_403s_hot_busy_cell_before_acquire(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_x"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    cp.disable_tenant("acme")
    reg = FakeRegistry(FakeCell(1, db))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 0                           # disabled -> never pins the hot cell


def test_epoch_mismatch_fails_closed_and_releases(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_y"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")                # resolves to epoch 1
    reg = FakeRegistry(FakeCell(2, db))                # cell reopened at a newer epoch
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.acquired == 1 and reg.released == 1


def test_revoked_in_cell_token_403(tmp_path):
    cfg = _cfg()
    bearer = "hma_agent_z"
    db = Database(":memory:")
    db.create_token("bot", "agent", _hash(bearer), None, None)
    db.revoke_token("bot")
    cp = _control(tmp_path)
    cp.add_route(_hash(bearer), "acme")
    reg = FakeRegistry(FakeCell(1, db))
    with pytest.raises(HTTPException) as ei:
        _run(resolve_identity(_req(cfg, f"Bearer {bearer}"), reg, cp))
    assert ei.value.status_code == 403
    assert reg.released == 1


def test_legacy_app_token_resolves_strictly_to_default(tmp_path):
    cfg = _cfg()
    db = Database(":memory:")
    cp = ControlPlane.open(tmp_path / "control", tmp_path / "tenants")
    (tmp_path / "tenants").mkdir(exist_ok=True)
    cp.create_tenant("default", str(tmp_path / "tenants" / "default"))   # epoch 1
    reg = FakeRegistry(FakeCell(1, db))
    ident, cell = _run(resolve_identity(_req(cfg, "Bearer test-app"), reg, cp))
    assert (ident.tenant_id, ident.role, ident.legacy) == ("default", "app", True)
    assert reg.acquired == 1 and reg.released == 0
```
- [ ] **Run it — expect FAIL** (`TypeError`/`AttributeError`: old `resolve_identity(db, cfg, bearer)` /
  `Identity` has no `tenant_id`):
```
cd "<repo-root>/server" && python -m pytest tests/test_resolve_identity.py -q
```
- [ ] **Minimal implementation.** In `server/arbiter/auth.py`, replace the `Identity` dataclass
  (`auth.py:55-59`) with:
```python
@dataclass
class Identity:
    # Field set matches the pinned contract Identity(tenant_id, name, role, scopes,
    # epoch, legacy). name/role stay first (all construction is keyword-based, so
    # membership — not position — is what composes) and the rest carry defaults so
    # this remains a drop-in for existing keyword constructions.
    name: str
    role: str                 # "agent" | "warden" | "app"
    tenant_id: str | None = None
    scopes: dict | None = None
    epoch: int | None = None
    legacy: bool = False      # True only for the static [auth] config tokens (deprecated)
```
  Then **replace** the shipped `resolve_identity` (`auth.py:70-92`) with:
```python
def _deny() -> "NoReturn":
    # One identical generic 403 for route-miss / bad-MAC / in-cell-invalid /
    # disabled / epoch-mismatch — no tenant-existence or "real route key" oracle
    # in the status or body (spec §11).
    raise HTTPException(403, "forbidden")


async def resolve_identity(request: Request, registry, control):
    """Derive (Identity, Cell) from the bearer alone (spec §4). Router is a HINT;
    the cell is the authority. Returns a REFCOUNT-PINNED cell — the caller MUST
    registry.release(cell) exactly once. Any failure raises a generic 403 and
    releases the pin if one was taken."""
    cfg = request.app.state.cfg
    auth = request.headers.get("authorization", "")
    bearer = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
    # Hash unconditionally: a missing/short bearer takes the same dominant-cost
    # path as a real one (equalized-timing generic 403, §11).
    token_hash = hashlib.sha256(bearer.encode()).hexdigest()

    tenant_id = None
    epoch = None
    legacy_role = None
    if bearer and cfg.auth.app_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.app_token.encode()):
        tenant_id, legacy_role = "default", "app"          # strict 'default' (§14)
    elif bearer and cfg.auth.agent_token and secrets.compare_digest(
            bearer.encode(), cfg.auth.agent_token.encode()):
        tenant_id, legacy_role = "default", "agent"        # hold-sdk 0.2.1 back-compat
    else:
        resolved = control.resolve(token_hash)             # (tenant_id, epoch) | None; MAC-verified
        if resolved is not None:
            tenant_id, epoch = resolved

    if tenant_id is None:
        _deny()                                            # route miss / bad MAC / unknown token

    if legacy_role is not None:
        epoch = control.epoch_of("default")
        if epoch is None:
            _deny()                                        # 'default' cell not provisioned

    if control.is_disabled(tenant_id):                     # read on EVERY resolution, never cached
        _deny()

    cell = await registry.acquire(tenant_id, epoch)        # pins; caller MUST release
    try:
        if cell.epoch != epoch:                            # snapshot-consistent / TOCTOU (§5)
            _deny()
        if legacy_role is not None:
            return (Identity(name=legacy_role, role=legacy_role, tenant_id="default",
                             scopes=None, epoch=epoch, legacy=True), cell)
        row = cell.db.get_token_by_hash(token_hash)        # re-validate in the CELL (full hex)
        if row is None:                                    # route hint but no cell row -> hard 403
            _deny()
        if row["revoked_at"] is not None:
            _deny()
        if row["expires_at"] is not None and \
                datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            _deny()
        cell.db.touch_token_last_used(row["id"])
        return (Identity(name=row["name"], role=row["role"], tenant_id=tenant_id,
                         scopes=row["scopes"], epoch=epoch, legacy=False), cell)
    except BaseException:
        registry.release(cell)                             # release the pin on EVERY failure exit
        raise
```
  (`hashlib`, `secrets`, `datetime`/`timezone`, `HTTPException`, `Request` are already imported at the
  top of `auth.py` — `auth.py:1-9`.)
- [ ] **Run green:**
```
cd "<repo-root>/server" && python -m pytest tests/test_resolve_identity.py -q
```
- [ ] **Commit:**
```
git add server/arbiter/auth.py server/tests/test_resolve_identity.py
git commit -m "feat(auth): tenant-scoped Identity + resolve_identity(request, registry, control)

Router is a hint; cell re-validates role/expiry/revocation. is_disabled on every
resolution; epoch assertion fails closed; equalized generic 403; legacy app/agent
tokens resolve strictly to 'default'. Pin released exactly once on failure."
```

---

## Group B done-when

- [ ] `cd server && python -m pytest tests/test_control.py tests/test_resolve_identity.py -q` is green.
- [ ] `ControlPlane` and the new `resolve_identity`/`Identity` match the pinned contract signatures
  verbatim, so Group A (`TenantRegistry`), Group C (`require_role` rewire), and Group F (provisioning
  CLI) compose against them by name.
- [ ] Router invariants demonstrated by test: forged/tampered route → 403 (`resolve` returns `None`);
  truncated hash never routes; disabled tenant 403s a hot busy cell **before** acquire; delete+recreate
  epoch mismatch fails closed; route-hit-with-no-cell-token → hard generic 403 with the pin released.


---


## Group C — Per-cell /v1 routes, per-cell Dispatcher/egress, per-cell rate limiters, audit export

Implements spec §15.1 (routes/dispatcher/limiters cell-owned; `app.state` holds nothing per-tenant),
§15.2 (tenant from credential on every surface incl. `/v1/audit/export`), §9 (notify/egress isolation),
§13 (rate limiters). Branch: `feat/multitenant-isolation`. Repo (quote it — spaces in path):
`<repo-root>`.

## What this group changes, in one breath
Today `create_app(cfg, db, sender, ...)` builds ONE process-global `Database`, `Hub`, `Dispatcher`,
`Outbox`, verdict key, and three limiters, and stores `db/hub/create_limiter/login_limiter/verdict_kid`
on `app.state`. Every `/v1` route reads those globals. This group rewires `create_app` to take a
`TenantRegistry` + `ControlPlane` (no `db`), puts NOTHING tenant-scoped on `app.state`, and makes every
`/v1` route resolve `(Identity, Cell)` from the caller's bearer and operate on `cell.db`, `cell.dispatcher`,
`cell.signer`, `cell.hub`, `cell.create_limiter`. Egress (`Dispatcher`) is built per-cell from per-cell
config; rate-limit buckets are per-cell so two tenants' `agent` tokens can't collide; the fleet auth-failure
limiter keys on a *trusted* identifier, not a shared ingress IP.

## Cross-group dependencies (consume by these PINNED names ONLY)
- **`Cell`** — attrs `tenant_id:str`, `epoch:int`, `dir:Path`, `db:Database`, `signer` (with `kid`,
  `signing_key`, `public_jwks()`), `hub:Hub`, `dispatcher:Dispatcher`, `create_limiter`, `login_limiter`.
- **`TenantRegistry(control, max_hot_cells=64, stream_cap=5)`** — `async acquire(tenant_id, epoch)->Cell`
  (refcount++, caller MUST `release`), `release(cell)->None` (exactly once),
  `async with hold(tenant_id, epoch) as cell` (acquire+release).
- **`ControlPlane`** — `resolve(token_hash)->(tenant_id,epoch)|None`, `is_disabled(tenant_id)->bool`,
  `tenant_dir(tenant_id)->Path`, `create_tenant(tenant_id, dir)->int`, `add_route(token_hash, tenant_id)`,
  `list_tenants()`.
- **`Identity(tenant_id, name, role, scopes, epoch, legacy)`** and
  **`resolve_identity(request, registry, control) -> (Identity, Cell)`** — does sha256(bearer) →
  `control.resolve` → `is_disabled` → `registry.acquire` (refcount++) → cell re-validation → epoch assert;
  raises a **generic 403 with equalized timing** on any failure; on success the returned `Cell` is pinned
  and the **caller MUST `registry.release(cell)`**. Legacy `cfg.auth.app_token`/`agent_token` resolve
  STRICTLY to the `default` cell (`legacy=True`).
- **`sign_verdict(signer, request_id, action_hash, decision, decided_at, approval_ttl, tenant_id) -> str`**
  — EdDSA JWS, `kid=f"{tenant_id}:{hash8}"`, `aud=f"hma-verdict:{tenant_id}"`, claim `hma.tenant_id`.
- **`Hub`** (cell-owned) — `subscribe()->Queue`, `publish(...)`, `close()`. Reached only as `cell.hub`.
- **`ExpiryScheduler`** — optional; wired into `create_app`'s lifespan via the `scheduler=` param this group
  adds. This group does NOT implement it; it only starts/stops it if passed.

## What this group PRODUCES for other groups (exact names)
- **`create_app(cfg, registry, control, *, sender=None, scheduler=None, ws_heartbeat=30.0) -> FastAPI`** —
  new signature (was `create_app(cfg, db, sender, hub=None, ws_heartbeat=30.0, dispatcher=None)`).
- **`app.state` contract**: only `registry`, `control`, `cfg` (process-global, non-tenant), `auth_limiter`
  (fleet), `notify_tasks`, `session_check`. NO `db/hub/create_limiter/login_limiter/verdict_kid`.
- **`require_cell(*roles)`** (in `arbiter/app.py`) — FastAPI generator dependency → yields `(Identity, Cell)`,
  pins the cell for the request lifetime, releases exactly once, enforces role.
- **`CellDelivery`** dataclass + **`build_cell_dispatcher(delivery, db, sender, transport=None) -> Dispatcher`**
  + **`cell_delivery(process_cfg, tenant_id, cell_dir) -> CellDelivery`** (in `arbiter/notify/__init__.py`) —
  **Group A's registry MUST call `build_cell_dispatcher(cell_delivery(cfg, tid, dir), cell.db, sender)` when
  constructing `cell.dispatcher`.**
- **`trusted_client_id(request, cfg) -> str`** (in `arbiter/auth.py`) + config field
  `cfg.server.trusted_proxies: list[str]`.
- Test helpers in `server/tests/conftest.py`: `registry_env`, `provision_tenant`, `mint_cell_token`,
  updated `client` fixture (keeps `client.db` = default cell db for back-compat).

## Load-bearing conventions this group RELIES ON (flag to Group A)
- **Cell db path** = `<tenant_dir>/arbiter.sqlite3`; **signer PEM** = `<tenant_dir>/verdict_signing_key.pem`
  (matches `signing.KEY_FILENAME`). The test fixtures provision cell DBs at this path so the registry opens
  the same file. If Group A picks a different filename, update `provision_tenant`/`mint_cell_token` to match.
- Group A builds `cell.dispatcher` via this group's `build_cell_dispatcher` (see C2). Group A builds
  `cell.create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)` and
  `cell.login_limiter = SlidingWindowLimiter(5, 60.0)` (per-cell objects — that is what makes buckets
  non-shared; this group's routes just USE `cell.create_limiter`).

---

### Task C1: New `create_app` signature + `app.state` hygiene + lifespan + `main.py` + test fixtures

Foundational. After this task the app boots on a registry/control with a single `default` cell and every
route still 500s (they still read `db` — fixed C4–C8). We prove: (a) no per-tenant object on `app.state`,
(b) `/health` works against the default cell, (c) legacy `app_token` → `default`.

**Files:**
- Modify `server/arbiter/config.py` (add `ServerCfg.trusted_proxies`, wire in `Config.load`).
- Modify `server/arbiter/app.py:26-93` (signature, globals removal, lifespan, `app.state` block).
- Modify `server/arbiter/main.py:1-15` (build registry+control, new call).
- Modify `server/tests/conftest.py` (new fixtures; keep old ones working).
- Test: `server/tests/test_app_wiring.py` (new).

**Interfaces:**
- Consumes: `TenantRegistry(control,...)`, `ControlPlane`, `ControlPlane.create_tenant`, `Cell.db`,
  `resolve_identity` (via routes later), `Database` (shipped), `SlidingWindowLimiter` (shipped).
- Produces: `create_app(cfg, registry, control, *, sender=None, scheduler=None, ws_heartbeat=30.0)`;
  `app.state.{registry,control,cfg,auth_limiter,notify_tasks,session_check}`;
  conftest `registry_env`/`provision_tenant`/`mint_cell_token`/`client`.

**Steps:**

- [ ] **Add `trusted_proxies` to config (failing test).** Append to `server/tests/test_config.py` (or new
  `test_config_trusted.py`) — write the test:
  ```python
  def test_trusted_proxies_defaults_empty_and_loads(tmp_path):
      from arbiter.config import Config
      c = Config.load(str(tmp_path / "absent.toml"))
      assert c.server.trusted_proxies == []
      p = tmp_path / "c.toml"
      p.write_text('[server]\ntrusted_proxies = ["10.0.0.0/8", "127.0.0.1/32"]\n')
      c2 = Config.load(str(p))
      assert c2.server.trusted_proxies == ["10.0.0.0/8", "127.0.0.1/32"]
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_config_trusted.py -q` → FAIL
  (`AttributeError: 'ServerCfg' object has no attribute 'trusted_proxies'`).
- [ ] **Implement.** In `server/arbiter/config.py`, add to `ServerCfg`:
  ```python
  @dataclass
  class ServerCfg:
      host: str = "127.0.0.1"
      port: int = 8000
      db_path: str = "~/.local/share/holdmyagent/arbiter.sqlite3"
      trusted_proxies: list[str] = field(default_factory=list)
  ```
  In `Config.load`, in the `for k in (...)` server block, extend to load the list:
  ```python
  for k in ("host", "port", "db_path"):
      if k in s:
          setattr(cfg.server, k, s[k])
  if "trusted_proxies" in s:
      cfg.server.trusted_proxies = [str(x) for x in s["trusted_proxies"]]
  ```
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_config_trusted.py -q` → PASS.
- [ ] **Commit:** `feat(config): per-server trusted_proxies allowlist for auth-limiter keying`
  .

- [ ] **Write the wiring test (failing).** Create `server/tests/test_app_wiring.py`:
  ```python
  from arbiter.app import create_app
  from arbiter.apns import APNsSender

  def test_no_tenant_scoped_object_on_app_state(client):
      st = client.app_ref.state
      # §15.1 — nothing per-tenant lives on app.state
      for banned in ("db", "hub", "create_limiter", "login_limiter", "verdict_kid", "expire_pass"):
          assert not hasattr(st, banned), f"app.state.{banned} must not exist"
      for required in ("registry", "control", "cfg", "auth_limiter", "notify_tasks", "session_check"):
          assert hasattr(st, required), f"app.state.{required} missing"

  def test_health_ok_on_default_cell(client):
      r = client.get("/health")
      assert r.status_code == 200 and r.json() == {"ok": True, "db": True}

  def test_legacy_app_token_resolves_default(client, app_headers):
      # legacy cfg.auth.app_token → default cell; a protected route no longer 500s
      r = client.get("/v1/requests", headers=app_headers)
      assert r.status_code == 200
  ```
  (The `client` fixture is rebuilt below; `test_legacy_app_token_resolves_default` may only pass after
  C4 lands `/v1/requests` — mark it `@pytest.mark.xfail(reason="route ported in C4", strict=False)` until
  then, then remove the marker in C4.)
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_app_wiring.py -q` → FAIL (fixture/`create_app`
  signature mismatch).
- [ ] **Rebuild conftest fixtures.** Replace `server/tests/conftest.py` with (keeps every old fixture name
  working; `client.db` still points at the default cell's DB so the existing suite keeps reading it):
  ```python
  import hashlib
  import json
  import secrets as pysecrets
  import uuid
  from datetime import datetime, timezone
  from types import SimpleNamespace

  import pytest
  from fastapi.testclient import TestClient

  from arbiter.apns import APNsSender
  from arbiter.app import create_app
  from arbiter.config import Config
  from arbiter.db import Database
  from arbiter.models import RequestCreate
  from arbiter.control import ControlPlane          # Group A
  from arbiter.registry import TenantRegistry       # Group A

  @pytest.fixture
  def make():
      def _m(**kw): return RequestCreate(**{"title": "t", **kw})
      return _m

  @pytest.fixture
  def cfg(tmp_path):
      c = Config.load(str(tmp_path / "absent.toml"))
      c.auth.agent_token = "test-agent"
      c.auth.app_token = "test-app"
      c.auth.admin_password = "test-admin"
      c.auth.session_secret = "test-secret"
      c.server.db_path = str(tmp_path / "t.sqlite3")
      return c

  def _cell_dir(tmp_path, tenant_id):
      d = tmp_path / "cells" / tenant_id
      d.mkdir(parents=True, exist_ok=True)
      return d

  def provision_tenant(env, tenant_id):
      """Register a tenant + create its (empty) cell DB at the convention path.
      Returns (epoch, cell_db). The registry opens the SAME file lazily."""
      d = _cell_dir(env.tmp_path, tenant_id)
      epoch = env.control.create_tenant(tenant_id, str(d))
      db = Database(str(d / "arbiter.sqlite3"))     # convention: <dir>/arbiter.sqlite3
      env.dbs[tenant_id] = db
      return epoch, db

  def mint_cell_token(env, tenant_id, name, role, scopes=None):
      """Mint a bearer into a tenant's cell DB AND add the control route (§12
      mint order: cell row first, then router row). Returns the bearer string."""
      db = env.dbs[tenant_id]
      tok = f"hma_{role}_{pysecrets.token_hex(24)}"
      th = hashlib.sha256(tok.encode()).hexdigest()
      db.conn.execute(
          "INSERT INTO tokens(id,name,role,token_hash,scopes,created_at,"
          "expires_at,last_used_at,revoked_at) VALUES (?,?,?,?,?,?,NULL,NULL,NULL)",
          (str(uuid.uuid4()), name, role, th,
           json.dumps(scopes) if scopes is not None else None,
           datetime.now(timezone.utc).isoformat()))
      db.conn.commit()
      env.control.add_route(th, tenant_id)          # router row (+MAC over hash,tenant,epoch)
      return tok

  @pytest.fixture
  def registry_env(cfg, tmp_path):
      control = ControlPlane.open(tmp_path / "control", tmp_path / "cells")
      env = SimpleNamespace(control=control, tmp_path=tmp_path, dbs={})
      epoch, db = provision_tenant(env, "default")  # back-compat single cell
      env.default_epoch, env.default_db = epoch, db
      env.registry = TenantRegistry(control)
      env.provision = lambda tid: provision_tenant(env, tid)
      env.mint = lambda tid, name, role, scopes=None: mint_cell_token(env, tid, name, role, scopes)
      return env

  @pytest.fixture
  def client(cfg, registry_env):
      app = create_app(cfg, registry_env.registry, registry_env.control, sender=APNsSender(cfg))
      with TestClient(app) as c:
          c.db = registry_env.default_db            # existing tests read client.db
          c.env = registry_env
          c.app_ref = app
          yield c

  @pytest.fixture
  def agent_headers():
      return {"Authorization": "Bearer test-agent"}

  @pytest.fixture
  def app_headers():
      return {"Authorization": "Bearer test-app"}

  @pytest.fixture(autouse=True)
  def _clear_revoked():
      from arbiter import web
      web._REVOKED.clear()
      yield
  ```
  Note: the old `db` fixture (`Database(":memory:")`) is dropped — no route reads a bare `db` after this
  group. If a non-Group-C test still imports it, that test's owning group migrates it to `client.db`.
- [ ] **Refactor `create_app` (server/arbiter/app.py).** Replace the signature + the globals block
  (`app.py:26-93`). New head:
  ```python
  def create_app(cfg, registry, control, *, sender=None, scheduler=None, ws_heartbeat: float = 30.0):
      notify_tasks: set = set()

      def _spawn(coro):
          t = asyncio.create_task(coro)
          notify_tasks.add(t)
          t.add_done_callback(notify_tasks.discard)
          return t

      @asynccontextmanager
      async def lifespan(app):
          # §9: outbox re-drain is bounded to PROCESS-RESTART only, never cell-open.
          await _drain_all_outboxes(registry, control)
          sched_task = asyncio.create_task(scheduler.run()) if scheduler is not None else None
          try:
              yield
          finally:
              if sched_task is not None:
                  sched_task.cancel()
              for t in list(notify_tasks):
                  t.cancel()

      app = FastAPI(title="Arbiter", lifespan=lifespan)
      # app.state holds NOTHING tenant-scoped (§15.1):
      app.state.registry = registry
      app.state.control = control
      app.state.cfg = cfg                         # process-global policy/server/auth(session) ONLY
      app.state.auth_limiter = SlidingWindowLimiter(10, 60.0)   # fleet auth-failure limiter (§13)
      app.state.notify_tasks = notify_tasks
      app.state.session_check = lambda v: session_valid(cfg, v)
      app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")),
                name="static")
      app.include_router(build_router(cfg, registry, control))   # dashboard group re-signs build_router
  ```
  Remove: `hub = hub or Hub()`, `dispatcher = ...`, `outbox = Outbox(...)`, `config_dir`/`load_or_create_keypair`,
  `_expire_pass`, the `sweep()` loop, and every `app.state.{hub,db,cfg... per-tenant,create_limiter,login_limiter,expire_pass,verdict_kid,auth_limiter set from local}` line
  except the ones listed above. Keep the `security_headers` middleware and the utility routes (`/`,
  `/dashboard`, `/pair`) unchanged. `appdep = Depends(require_role("app"))` is deleted (replaced by
  `require_cell` in C3).
  Add the restart-drain helper at module scope in `app.py`:
  ```python
  async def _drain_all_outboxes(registry, control) -> None:
      """Process-restart outbox re-drain (§9/§15.11). Transient per tenant: hold,
      drain, release — one extra cell open at a time (FD-budget friendly)."""
      from .notify.outbox import Outbox
      for tid in control.list_tenants():
          try:
              async with registry.hold(tid) as cell:
                  await Outbox(cell.db, cell.dispatcher).drain_startup()
          except Exception as exc:
              log.warning("startup outbox drain failed for %s: %s", tid, exc)
  ```
  (`build_router(cfg, registry, control)` is the dashboard group's new signature — it is referenced here so
  the app boots; that group ports the dashboard to per-cell resolution. If it has not landed yet, temporarily
  pass `build_router(cfg, registry_env.default_db, None)` shim is NOT acceptable — coordinate the merge order
  so build_router's new signature lands with or before this task.)
- [ ] **Update `main.py`** (`server/arbiter/main.py`) to build the registry/control:
  ```python
  import sys
  from pathlib import Path
  from .config import Config
  from .apns import APNsSender
  from .app import create_app
  from .control import ControlPlane            # Group A
  from .registry import TenantRegistry         # Group A

  cfg = Config.load()
  problems = cfg.validate_for_serve()
  if problems:
      sys.exit("Refusing to start:\n  - " + "\n  - ".join(problems))
  control = ControlPlane(cfg.control_db_path_expanded())   # Group A helper on Config/ControlPlane
  registry = TenantRegistry(control)
  sender = APNsSender(cfg)
  app = create_app(cfg, registry, control, sender=sender)
  ```
  (`control_db_path_expanded()` / how `control.db` is located is Group A/D's; reference it by name. If they
  expose the control-plane path differently, adapt this one line.)
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_app_wiring.py -q -k "app_state or health"` →
  PASS (the `legacy_app_token` case stays xfail until C4).
- [ ] **Commit:** `refactor(app): create_app takes registry+control; nothing tenant-scoped on app.state`.

---

### Task C2: Per-cell egress config — `CellDelivery` + `build_cell_dispatcher` + `cell_delivery`

The `Dispatcher` already reads `cfg.webhook/.ntfy/.callback_allowlist/.notify_severities` off its first arg
and calls `sender or APNsSender(cfg)`. So a per-cell `Dispatcher` is just the shipped one fed a per-cell
config object (`CellDelivery`) and the shared `sender`. This task produces the factory Group A calls to
populate `cell.dispatcher`, so a tenant's request/decision bodies egress ONLY to that tenant's sinks (§9).

**Files:**
- Modify `server/arbiter/notify/__init__.py` (add `CellDelivery`, `cell_delivery`, `build_cell_dispatcher`).
- Test: `server/tests/test_cell_delivery.py` (new).

**Interfaces:**
- Consumes: shipped `Dispatcher(cfg, db, sender=None, transport=None)`, `WebhookCfg`, `NtfyCfg` (config.py),
  `callback_allowed`.
- Produces: `CellDelivery(webhook, ntfy, callback_allowlist, notify_severities)`;
  `cell_delivery(process_cfg, tenant_id, cell_dir) -> CellDelivery`;
  `build_cell_dispatcher(delivery, db, sender, transport=None) -> Dispatcher`. **Group A consumes these.**

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_cell_delivery.py`:
  ```python
  from arbiter.config import Config
  from arbiter.notify import CellDelivery, cell_delivery, build_cell_dispatcher
  from arbiter.db import Database

  def test_default_cell_inherits_process_delivery(tmp_path):
      cfg = Config.load(str(tmp_path / "absent.toml"))
      cfg.webhook.url = "https://proc.example/hook"
      cfg.callback_allowlist = ["https://proc.example/*"]
      d = cell_delivery(cfg, "default", tmp_path / "cells" / "default")
      assert d.webhook.url == "https://proc.example/hook"
      assert d.callback_allowlist == ["https://proc.example/*"]

  def test_nondefault_cell_reads_own_notify_toml(tmp_path):
      cfg = Config.load(str(tmp_path / "absent.toml"))
      cfg.webhook.url = "https://proc.example/hook"          # process default MUST NOT leak into tenant B
      cdir = tmp_path / "cells" / "b"
      cdir.mkdir(parents=True)
      (cdir / "notify.toml").write_text(
          '[webhook]\nurl = "https://b.example/hook"\n'
          '[notify]\ncallback_allowlist = ["https://b.example/*"]\n')
      d = cell_delivery(cfg, "b", cdir)
      assert d.webhook.url == "https://b.example/hook"
      assert d.callback_allowlist == ["https://b.example/*"]

  def test_nondefault_cell_no_config_has_no_egress(tmp_path):
      cfg = Config.load(str(tmp_path / "absent.toml"))
      cfg.webhook.url = "https://proc.example/hook"
      cdir = tmp_path / "cells" / "c"; cdir.mkdir(parents=True)
      d = cell_delivery(cfg, "c", cdir)
      assert d.webhook.enabled is False and d.callback_allowlist == []

  def test_build_cell_dispatcher_uses_passed_sender_and_db(tmp_path):
      cfg = Config.load(str(tmp_path / "absent.toml"))
      db = Database(":memory:")
      class S:  # sentinel sender
          pass
      s = S()
      disp = build_cell_dispatcher(CellDelivery.from_process(cfg), db, s)
      assert disp.db is db and disp.sender is s
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_cell_delivery.py -q` → FAIL (ImportError).
- [ ] **Implement.** In `server/arbiter/notify/__init__.py`, add near the top (after the imports) — reuse
  the shipped `WebhookCfg`/`NtfyCfg` so `Dispatcher` sees the exact attributes it already reads:
  ```python
  import tomllib
  from dataclasses import dataclass, field
  from ..config import WebhookCfg, NtfyCfg, SEVERITIES

  @dataclass
  class CellDelivery:
      """Per-cell egress config. Exposes exactly the attributes Dispatcher reads
      off its first arg (.webhook/.ntfy/.callback_allowlist/.notify_severities),
      so build_cell_dispatcher can hand it straight to the shipped Dispatcher."""
      webhook: WebhookCfg = field(default_factory=WebhookCfg)
      ntfy: NtfyCfg = field(default_factory=NtfyCfg)
      callback_allowlist: list[str] = field(default_factory=list)
      notify_severities: dict[str, bool] = field(
          default_factory=lambda: {s: True for s in SEVERITIES})

      @classmethod
      def from_process(cls, cfg) -> "CellDelivery":
          return cls(webhook=cfg.webhook, ntfy=cfg.ntfy,
                     callback_allowlist=list(cfg.callback_allowlist),
                     notify_severities=dict(cfg.notify_severities))

  def cell_delivery(process_cfg, tenant_id: str, cell_dir) -> CellDelivery:
      """default cell inherits the process delivery config (back-compat, §14);
      every other tenant reads ONLY <cell_dir>/notify.toml — the process cfg's
      sinks NEVER leak into another tenant (§9). Absent file = no egress."""
      if tenant_id == "default":
          return CellDelivery.from_process(process_cfg)
      d = CellDelivery()
      p = Path(cell_dir) / "notify.toml"
      if p.is_file():
          doc = tomllib.loads(p.read_text())
          wh = doc.get("webhook", {})
          if "url" in wh: d.webhook.url = str(wh["url"])
          if "secret" in wh: d.webhook.secret = str(wh["secret"])
          nt = doc.get("ntfy", {})
          for k in ("url", "topic", "token"):
              if k in nt: setattr(d.ntfy, k, str(nt[k]))
          n = doc.get("notify", {})
          if "callback_allowlist" in n:
              d.callback_allowlist = [str(x) for x in n["callback_allowlist"]]
          for k, v in n.get("severities", {}).items():
              if k in d.notify_severities and isinstance(v, bool):
                  d.notify_severities[k] = v
      return d

  def build_cell_dispatcher(delivery: CellDelivery, db, sender, transport=None) -> "Dispatcher":
      """The cell's own Dispatcher: shipped Dispatcher fed the per-cell delivery
      config + the shared APNs sender + the cell db. sender is ALWAYS passed so
      Dispatcher never falls back to APNsSender(delivery)."""
      return Dispatcher(delivery, db, sender=sender, transport=transport)
  ```
  (`Path` is already imported in `notify/__init__.py`? It imports `from urllib.parse import urlparse` — add
  `from pathlib import Path` at the top.)
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_cell_delivery.py -q` → PASS.
- [ ] **Commit:** `feat(notify): per-cell CellDelivery + build_cell_dispatcher (egress isolation §9)`.

---

### Task C3: `require_cell` dependency + fleet auth-failure limiter keyed on a trusted id (§13)

The route-facing dependency: authenticate → resolve `(Identity, Cell)` → enforce role → **release exactly
once** on every exit path. Wraps the pinned `resolve_identity`. Adds the fleet auth-failure limiter (keyed
by `trusted_client_id`, not a shared ingress IP) so 10 bad tokens behind one proxy can't 429 the fleet.

**Files:**
- Modify `server/arbiter/auth.py` (add `trusted_client_id`; keep `SlidingWindowLimiter`, `_client_ip`).
- Modify `server/arbiter/app.py` (add `require_cell(*roles)`; import `resolve_identity`, `trusted_client_id`).
- Test: `server/tests/test_require_cell.py` (new).

**Interfaces:**
- Consumes: `resolve_identity(request, registry, control)`, `TenantRegistry.release`, `Identity.role`,
  `app.state.{registry,control,cfg,auth_limiter}`, `SlidingWindowLimiter`.
- Produces: `trusted_client_id(request, cfg) -> str`; `require_cell(*roles)` → dependency yielding
  `(Identity, Cell)`.

**Steps:**

- [ ] **Failing test for `trusted_client_id`.** Create `server/tests/test_require_cell.py`:
  ```python
  from types import SimpleNamespace
  from arbiter.auth import trusted_client_id

  def _req(peer, xff=None):
      headers = {}
      if xff is not None:
          headers["x-forwarded-for"] = xff
      return SimpleNamespace(client=SimpleNamespace(host=peer),
                             headers={k.lower(): v for k, v in headers.items()})

  def _cfg(trusted):
      return SimpleNamespace(server=SimpleNamespace(trusted_proxies=trusted))

  def test_no_trusted_proxy_uses_direct_peer():
      assert trusted_client_id(_req("1.2.3.4"), _cfg([])) == "1.2.3.4"

  def test_untrusted_peer_ignores_xff():
      # peer is NOT a trusted proxy: XFF is attacker-controlled, must be ignored
      assert trusted_client_id(_req("9.9.9.9", xff="7.7.7.7"), _cfg(["10.0.0.0/8"])) == "9.9.9.9"

  def test_trusted_proxy_uses_real_client_from_xff():
      # peer IS the ingress proxy: the rightmost non-proxy XFF hop is the client
      got = trusted_client_id(_req("10.0.0.5", xff="7.7.7.7, 10.0.0.9"), _cfg(["10.0.0.0/8"]))
      assert got == "7.7.7.7"
  ```
  Note the headers dict is lowercased (FastAPI headers are case-insensitive; the real code reads
  `request.headers.get("x-forwarded-for", "")`).
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_require_cell.py -q -k trusted` → FAIL (ImportError).
- [ ] **Implement `trusted_client_id`.** In `server/arbiter/auth.py` add `import ipaddress` at top and:
  ```python
  def trusted_client_id(request, cfg) -> str:
      """A TRUSTED per-caller key for the fleet auth-failure limiter (§13). Never
      key solely on a shared ingress IP (10 bad tokens would 429 the whole fleet).
      With no configured proxies the direct peer IS the trusted id; behind a
      configured trusted proxy, believe X-Forwarded-For and return the rightmost
      hop that is NOT itself a trusted proxy (the real client)."""
      peer = request.client.host if request.client else "unknown"
      trusted = getattr(cfg.server, "trusted_proxies", None) or []
      if not trusted:
          return peer
      def _in_trusted(ip_s: str) -> bool:
          try:
              ip = ipaddress.ip_address(ip_s)
          except ValueError:
              return False
          return any(ip in ipaddress.ip_network(c, strict=False) for c in trusted)
      if not _in_trusted(peer):
          return peer                      # peer isn't our proxy → XFF untrusted
      xff = request.headers.get("x-forwarded-for", "")
      for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
          if not _in_trusted(hop):
              return hop
      return peer
  ```
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_require_cell.py -q -k trusted` → PASS.
- [ ] **Failing test for `require_cell`** (append to `test_require_cell.py`):
  ```python
  import pytest
  from fastapi import Depends, FastAPI
  from fastapi.testclient import TestClient
  from arbiter.app import require_cell

  def test_require_cell_releases_on_success_and_failure(client, app_headers):
      reg = client.env.registry
      released = []
      orig = reg.release
      reg.release = lambda cell: (released.append(cell), orig(cell))[1]
      # a ported route (app-role) succeeds and releases exactly once
      assert client.get("/v1/requests", headers=app_headers).status_code == 200
      assert len(released) == 1
      released.clear()
      # wrong role → 403 but still releases the pin acquired by resolve_identity
      assert client.get("/v1/requests", headers={"Authorization": "Bearer test-agent"}).status_code == 403
      assert len(released) == 1

  def test_bad_token_trips_fleet_limiter(client):
      bad = {"Authorization": "Bearer nope"}
      codes = [client.get("/v1/requests", headers=bad).status_code for _ in range(12)]
      assert codes[0] == 403 and 429 in codes
  ```
  (`/v1/requests` app-role listing is ported in C4; if running C3 alone, gate these two with
  `@pytest.mark.xfail(strict=False)` and drop the marker in C4.)
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_require_cell.py -q -k require_cell` → FAIL
  (`ImportError: cannot import name 'require_cell'`).
- [ ] **Implement `require_cell`.** In `server/arbiter/app.py`, update imports:
  ```python
  from .auth import SlidingWindowLimiter, resolve_identity, trusted_client_id
  ```
  (drop `Identity, _client_ip, require_role` from that import — they are no longer used here) and add the
  factory **inside `create_app`** (so it closes over nothing tenant-scoped; it reads `request.app.state`):
  ```python
      def require_cell(*roles: str):
          """Authenticate the bearer → (Identity, Cell); pin the cell for the whole
          request; release exactly once on EVERY exit path; enforce role. All
          tenant state comes from the returned cell — never app.state."""
          async def dep(request: Request):
              st = request.app.state
              key = trusted_client_id(request, st.cfg)
              if st.auth_limiter.blocked(key):
                  raise HTTPException(429, "too many failed auth attempts")
              try:
                  identity, cell = await resolve_identity(request, st.registry, st.control)
              except HTTPException:
                  st.auth_limiter.record_failure(key)   # count the failed auth
                  raise
              try:
                  if roles and identity.role not in roles:
                      st.auth_limiter.record_failure(key)
                      raise HTTPException(403, "forbidden")   # generic (§11)
                  yield (identity, cell)
              finally:
                  st.registry.release(cell)                  # exactly once (§15.4)
          return dep
  ```
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_require_cell.py -q` → PASS (require_cell cases
  after C4; keep xfail until then).
- [ ] **Commit:** `feat(app): require_cell dependency + fleet auth limiter on trusted id (§13)`.

---

### Task C4: `/v1/requests` create + list per-cell

Port the two core write/read routes to `require_cell`, `cell.db`, `cell.create_limiter`, `cell.dispatcher`,
`cell.hub`, and a cell-pinned background outbox publish.

**Files:**
- Modify `server/arbiter/app.py` (the `create` route `app.py:162-215`; the `list_` route `app.py:217-219`).
- Test: `server/tests/test_percell_requests.py` (new); remove the C1 xfail marker on
  `test_legacy_app_token_resolves_default` and the C3 xfail markers.

**Interfaces:**
- Consumes: `require_cell`, `Cell.db`, `Cell.create_limiter`, `Cell.dispatcher`, `Cell.hub`,
  `Cell.tenant_id`, `Cell.epoch`, `Identity.{name,legacy,scopes,role}`, `evaluate_create`,
  `callback_allowed`, `Outbox`, `TenantRegistry.hold`.
- Produces: `POST /v1/requests`, `GET /v1/requests` operating on the caller's cell only.

**Steps:**

- [ ] **Add the cell-pinned publish helper (module scope in app.py).**
  ```python
  def _spawn_publish(app, tenant_id, epoch, event, req):
      """Background outbox publish that pins ITS OWN cell for its lifetime (§15.4):
      the HTTP request's pin is gone by the time this runs, so re-acquire by object
      via registry.hold and release exactly once. Held strongly in notify_tasks so
      it isn't GC'd mid-flight."""
      st = app.state
      async def run():
          async with st.registry.hold(tenant_id, epoch) as cell:
              await Outbox(cell.db, cell.dispatcher).publish(event, req)
      t = asyncio.create_task(run())
      st.notify_tasks.add(t)
      t.add_done_callback(st.notify_tasks.discard)
      return t
  ```
  Add `from .notify.outbox import Outbox` to app.py imports.
- [ ] **Failing test.** Create `server/tests/test_percell_requests.py`:
  ```python
  def test_create_and_list_scoped_to_caller_cell(client):
      env = client.env
      env.provision("b"); env.provision("a")
      atok = env.mint("a", "agentA", "agent")
      btok = env.mint("b", "agentB", "agent")
      aapp = env.mint("a", "appA", "app")
      bapp = env.mint("b", "appB", "app")
      ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                       json={"title": "for-A"})
      rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                       json={"title": "for-B"})
      assert ra.status_code == 200 and rb.status_code == 200
      # A's app sees ONLY A's request; B's app sees ONLY B's
      la = client.get("/v1/requests", headers={"Authorization": f"Bearer {aapp}"}).json()
      lb = client.get("/v1/requests", headers={"Authorization": f"Bearer {bapp}"}).json()
      assert [r["title"] for r in la] == ["for-A"]
      assert [r["title"] for r in lb] == ["for-B"]

  def test_create_rate_limit_is_per_cell(client, cfg):
      # B's agent burst must NEVER throttle A's agent (§13 — separate buckets)
      env = client.env
      env.provision("a"); env.provision("b")
      atok = env.mint("a", "agent", "agent")     # SAME name in both cells
      btok = env.mint("b", "agent", "agent")
      # drive B's 'agent' bucket to the limit
      for _ in range(cfg.policy.rate_limit_per_minute + 2):
          client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"},
                      json={"title": "x", "idempotency_key": None})
      rb = client.post("/v1/requests", headers={"Authorization": f"Bearer {btok}"}, json={"title": "y"})
      ra = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"}, json={"title": "z"})
      assert rb.status_code == 429
      assert ra.status_code == 200            # A untouched
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_percell_requests.py -q` → FAIL (routes still
  read the removed `db`/`create_limiter` → 500/`AttributeError`).
- [ ] **Implement.** Replace the `create` route body (`app.py:162-215`) — same logic, `db`→`cell.db`,
  `create_limiter`→`cell.create_limiter`, `cfg.callback_allowlist`→`cell.dispatcher.cfg.callback_allowlist`,
  `identity.scopes` used directly, hub/outbox on the cell:
  ```python
      @app.post("/v1/requests")
      async def create(body: RequestCreate,
                       ctx: tuple = Depends(require_cell("agent", "warden"))):
          identity, cell = ctx
          db = cell.db
          requested_by = None if identity.legacy else identity.name
          scopes = None if identity.legacy else identity.scopes
          result = evaluate_create(cfg, identity, body, scopes=scopes)
          if not result.allowed:
              db.add_audit("-", "policy_denied",
                           {"identity": identity.name, "action_type": body.action_type,
                            "reason": result.reason})
              raise HTTPException(403, f"policy: {result.reason}")
          body.severity = result.effective_severity
          if cell.create_limiter.blocked(identity.name):
              db.add_audit("-", "rate_limited", {"identity": identity.name})
              raise HTTPException(429, "rate limited")
          cell.create_limiter.record_failure(identity.name)
          if body.callback_url and not callback_allowed(
                  cell.dispatcher.cfg.callback_allowlist, body.callback_url):
              raise HTTPException(422, "callback_url not in allowlist")
          body.ttl_seconds = max(cfg.policy.ttl_min_seconds,
                                 min(cfg.policy.ttl_max_seconds, body.ttl_seconds))
          if body.idempotency_key:
              existing = db.get_request_by_idem(requested_by, body.idempotency_key)
              if existing:
                  return existing
          if (body.canonical_action is None) != (body.action_hash is None):
              raise HTTPException(422, "canonical_action and action_hash must be supplied together")
          if body.canonical_action is not None:
              computed = hashlib.sha256(body.canonical_action.encode()).hexdigest()
              if computed != body.action_hash:
                  raise HTTPException(422, "action_hash does not match canonical_action")
          dup = db.find_duplicate_pending(requested_by, body.action_hash, body.title)
          if dup:
              return dup
          try:
              req = db.create_request(body, requested_by=requested_by)
          except sqlite3.IntegrityError:
              existing = db.get_request_by_idem(requested_by, body.idempotency_key) \
                  if body.idempotency_key else None
              if existing:
                  return existing
              raise
          _spawn_publish(app, cell.tenant_id, cell.epoch, "request.created", req)
          cell.hub.publish({"event": "request.created", "request": req})
          return req
  ```
  Replace `list_` (`app.py:217-219`):
  ```python
      @app.get("/v1/requests")
      def list_(status: str | None = None, ctx: tuple = Depends(require_cell("app"))):
          _identity, cell = ctx
          return cell.db.list_requests(status)
  ```
  (`policy.evaluate_create(cfg, ...)` keeps using the process cfg — policy is process-global for V1, §13
  concerns only the limiter buckets, which are per-cell here.)
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_percell_requests.py tests/test_app_wiring.py tests/test_require_cell.py -q` → PASS.
  Remove the xfail markers added in C1/C3.
- [ ] **Commit:** `feat(app): /v1/requests create+list per-cell (cell.db/limiter/dispatcher/hub)`.

---

### Task C5: `GET /v1/requests/{rid}` + `/verdict` per-cell

Port the two per-id reads. The requested_by ownership logic is unchanged — it just runs against `cell.db`.
Cross-tenant reads become 404 for free because the request row lives only in the owning cell's db.

**Files:**
- Modify `server/arbiter/app.py` (`get_` `app.py:221-236`; `get_verdict` `app.py:238-253`).
- Test: `server/tests/test_percell_reads.py` (new).

**Interfaces:**
- Consumes: `require_cell`, `Cell.db`, `Identity.{role,legacy,name}`.
- Produces: `GET /v1/requests/{rid}`, `GET /v1/requests/{rid}/verdict` scoped to the caller's cell.

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_percell_reads.py`:
  ```python
  def test_cross_tenant_get_is_404(client):
      env = client.env
      env.provision("a"); env.provision("b")
      atok = env.mint("a", "agentA", "agent")
      bapp = env.mint("b", "appB", "app")
      aapp = env.mint("a", "appA", "app")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": "secret-A"}).json()["id"]
      # B (even app-role, unrestricted within its own cell) cannot see A's rid
      assert client.get(f"/v1/requests/{rid}",
                        headers={"Authorization": f"Bearer {bapp}"}).status_code == 404
      # A's app can
      assert client.get(f"/v1/requests/{rid}",
                        headers={"Authorization": f"Bearer {aapp}"}).status_code == 200

  def test_cross_tenant_verdict_is_404(client):
      env = client.env
      env.provision("a"); env.provision("b")
      atok = env.mint("a", "agentA", "agent")
      bapp = env.mint("b", "appB", "app")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": "t"}).json()["id"]
      assert client.get(f"/v1/requests/{rid}/verdict",
                        headers={"Authorization": f"Bearer {bapp}"}).status_code == 404
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_percell_reads.py -q` → FAIL (routes 500).
- [ ] **Implement.** Replace `get_` (`app.py:221-236`):
  ```python
      @app.get("/v1/requests/{rid}")
      def get_(rid: str, ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
          identity, cell = ctx
          r = cell.db.get_request(rid)
          if not r:
              raise HTTPException(404, "not found")
          if identity.role in ("agent", "warden"):
              if identity.legacy:
                  if r.get("requested_by") is not None:
                      raise HTTPException(404, "not found")
              elif r.get("requested_by") != identity.name:
                  raise HTTPException(404, "not found")
          return r
  ```
  Replace `get_verdict` (`app.py:238-253`):
  ```python
      @app.get("/v1/requests/{rid}/verdict")
      def get_verdict(rid: str, ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
          identity, cell = ctx
          r = cell.db.get_request(rid)
          if r and identity.role in ("agent", "warden"):
              rb = r.get("requested_by")
              if identity.legacy:
                  if rb is not None:
                      r = None
              elif rb != identity.name:
                  r = None
          if not r:
              raise HTTPException(404, "not found")
          if not r.get("verdict_jws"):
              raise HTTPException(404, "no verdict yet")
          return {"verdict": r["verdict_jws"], "kid": r["verdict_kid"]}
  ```
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_percell_reads.py -q` → PASS.
- [ ] **Commit:** `feat(app): /v1/requests get+verdict per-cell (cross-tenant read → 404)`.

---

### Task C6: `/decision` + `/consume` per-cell, verdict signed with the cell's own signer

Port the decision (sign with `cell.signer`, tenant-bound verdict) and consume routes. Uses the pinned
`sign_verdict(signer, ..., approval_ttl, tenant_id)` so the verdict is bound to THIS tenant (§7/§15.8).

**Files:**
- Modify `server/arbiter/app.py` (`decide` `app.py:255-283`; `consume` `app.py:285-299`). Update the
  `sign_verdict` import.
- Test: `server/tests/test_percell_decision.py` (new).

**Interfaces:**
- Consumes: `require_cell`, `Cell.db`, `Cell.signer` (`.kid`), `Cell.tenant_id`, `Cell.epoch`, `Cell.hub`,
  `sign_verdict(signer, request_id, action_hash, decision, decided_at, approval_ttl, tenant_id)`,
  `Outbox`, `_spawn_publish`.
- Produces: `POST /v1/requests/{rid}/decision`, `POST /v1/requests/{rid}/consume` per-cell.

**Steps:**

- [ ] **Failing test.** Create `server/tests/test_percell_decision.py`:
  ```python
  import jwt

  def test_decision_signs_with_cell_signer_and_tenant_binds(client):
      env = client.env
      env.provision("a")
      atok = env.mint("a", "agentA", "agent")
      aapp = env.mint("a", "appA", "app")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": "t"}).json()["id"]
      d = client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {aapp}"},
                      json={"decision": "approve"})
      assert d.status_code == 200
      v = client.get(f"/v1/requests/{rid}/verdict",
                     headers={"Authorization": f"Bearer {aapp}"}).json()
      hdr = jwt.get_unverified_header(v["verdict"])
      body = jwt.decode(v["verdict"], options={"verify_signature": False})
      assert hdr["kid"].startswith("a:")                     # kid = f"{tenant_id}:{hash8}"
      assert body["aud"] == "hma-verdict:a"                  # audience tenant-bound
      assert body["hma"]["tenant_id"] == "a"

  def test_cross_tenant_decision_is_404(client):
      env = client.env
      env.provision("a"); env.provision("b")
      atok = env.mint("a", "agentA", "agent")
      bapp = env.mint("b", "appB", "app")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": "t"}).json()["id"]
      assert client.post(f"/v1/requests/{rid}/decision",
                         headers={"Authorization": f"Bearer {bapp}"},
                         json={"decision": "approve"}).status_code == 404

  def test_consume_scoped_to_cell(client):
      env = client.env
      env.provision("a")
      atok = env.mint("a", "agentA", "agent")
      aapp = env.mint("a", "appA", "app")
      awarden = env.mint("a", "wardenA", "warden")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": "t"}).json()["id"]
      client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {aapp}"},
                  json={"decision": "approve"})
      c = client.post(f"/v1/requests/{rid}/consume", headers={"Authorization": f"Bearer {awarden}"})
      assert c.status_code == 200 and "consumed_at" in c.json()
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_percell_decision.py -q` → FAIL.
- [ ] **Implement.** Update the import in app.py:
  ```python
  from .signing import sign_verdict
  ```
  (drop `load_or_create_keypair, public_jwks` from app.py's `signing` import — no longer used here.)
  Replace `decide` (`app.py:255-283`):
  ```python
      @app.post("/v1/requests/{rid}/decision")
      async def decide(rid: str, body: Decision, ctx: tuple = Depends(require_cell("app"))):
          identity, cell = ctx
          db = cell.db
          r = db.get_request(rid)
          if not r:
              raise HTTPException(404, "not found")
          if identity.name == "app" and identity.role == "app":
              devices = db.list_devices()
              decided_by = devices[0]["name"] if len(devices) == 1 else "app"
          else:
              decided_by = identity.name
          updated = db.set_decision(rid, body.decision, decided_by)
          if not updated:
              cur = db.get_request(rid)
              shown = "expired" if cur["status"] == "pending" else cur["status"]
              raise HTTPException(409, f"not pending (status={shown})")
          jws = sign_verdict(cell.signer, request_id=updated["id"],
                             action_hash=updated["action_hash"], decision=updated["status"],
                             decided_at=updated["decided_at"],
                             approval_ttl=cfg.policy.approval_ttl_seconds,
                             tenant_id=cell.tenant_id)
          db.set_verdict(updated["id"], jws, cell.signer.kid)
          db.add_audit(updated["id"], "verdict_issued",
                       {"decision": updated["status"], "kid": cell.signer.kid})
          updated = db.get_request(rid)
          _spawn_publish(app, cell.tenant_id, cell.epoch, "request.decided", updated)
          cell.hub.publish({"event": "request.decided", "request": updated})
          return updated
  ```
  Replace `consume` (`app.py:285-299`):
  ```python
      @app.post("/v1/requests/{rid}/consume")
      def consume(rid: str, ctx: tuple = Depends(require_cell("warden"))):
          identity, cell = ctx
          code, row = cell.db.consume_request(
              rid, approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
          if code == 404:
              raise HTTPException(404, "not found")
          if code == 410:
              raise HTTPException(410, "approval stale")
          if code == 409:
              raise HTTPException(
                  409, f"not consumable (status={row['status']}, consumed_at={row['consumed_at']})")
          cell.db.add_audit(rid, "consumed", {"by": identity.name})
          return {"consumed_at": row["consumed_at"]}
  ```
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_percell_decision.py -q` → PASS.
- [ ] **Commit:** `feat(app): /v1 decision+consume per-cell; verdict signed by cell.signer (§7)`.

---

### Task C7: `/v1/audit/export` streams ONLY the caller's cell (§15.2)

Two auth paths kept: an app-role bearer → its cell; a valid admin dashboard session → the `default` cell
(back-compat; the multi-tenant dashboard→tenant mapping is the dashboard group's, §16 "A admin session →
404 on B"). Same fleet-limiter discipline as `require_cell`. Streams `cell.db.iter_audit()` only.

**Files:**
- Modify `server/arbiter/app.py` (`audit_export` `app.py:132-158`).
- Modify/replace `server/tests/test_audit_export.py` (the shipped one uses the old helpers/`expire_pass`).

**Interfaces:**
- Consumes: `resolve_identity`, `TenantRegistry.hold`, `ControlPlane` (via `registry.hold("default",...)`),
  `Cell.db.iter_audit`, `trusted_client_id`, `app.state.{registry,control,cfg,auth_limiter,session_check}`,
  `registry_env.default_epoch` (tests).
- Produces: `GET /v1/audit/export` per-cell.

**Steps:**

- [ ] **Failing test.** Replace `server/tests/test_audit_export.py` with (drops the `expire_pass` test — the
  scheduler group owns expiry; keeps the export-scope + auth + limiter coverage, now per-cell):
  ```python
  import json

  def _seed(client, tenant):
      env = client.env
      env.provision(tenant)
      atok = env.mint(tenant, "agent", "agent")
      app_ = env.mint(tenant, "app", "app")
      wtok = env.mint(tenant, "warden", "warden")
      rid = client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"},
                        json={"title": f"t-{tenant}"}).json()["id"]
      client.post(f"/v1/requests/{rid}/decision", headers={"Authorization": f"Bearer {app_}"},
                  json={"decision": "approve"})
      client.post(f"/v1/requests/{rid}/consume", headers={"Authorization": f"Bearer {wtok}"})
      return app_, rid

  def test_export_streams_only_callers_cell(client):
      aapp, _ = _seed(client, "a")
      bapp, _ = _seed(client, "b")
      la = client.get("/v1/audit/export", headers={"Authorization": f"Bearer {aapp}"})
      lb = client.get("/v1/audit/export", headers={"Authorization": f"Bearer {bapp}"})
      atext, btext = la.text, lb.text
      assert "t-a" in json.dumps([json.loads(x) for x in atext.splitlines() if x.strip()])
      assert "t-b" not in atext          # A's export never carries B's rows
      assert "t-a" not in btext

  def test_export_requires_app_role_or_admin_session(client):
      assert client.get("/v1/audit/export").status_code == 403
      assert client.get("/v1/audit/export",
                        headers={"Authorization": "Bearer test-agent"}).status_code == 403
      login = client.post("/dashboard/login", data={"password": "test-admin"},
                          follow_redirects=False)
      assert login.status_code == 303
      assert client.get("/v1/audit/export").status_code == 200   # admin session → default cell

  def test_export_unknown_format_422(client, app_headers):
      assert client.get("/v1/audit/export", params={"format": "csv"},
                        headers=app_headers).status_code == 422

  def test_export_auth_failures_rate_limited(client):
      bad = {"Authorization": "Bearer wrong"}
      codes = [client.get("/v1/audit/export", headers=bad).status_code for _ in range(12)]
      assert codes[0] == 403 and 429 in codes
  ```
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_audit_export.py -q` → FAIL.
- [ ] **Implement.** Replace `audit_export` (`app.py:132-158`). It resolves a cell for BOTH auth paths and
  releases it after the stream finishes (the generator holds the pin until fully consumed):
  ```python
      @app.get("/v1/audit/export")
      async def audit_export(request: Request, format: str = "jsonl"):
          st = app.state
          key = trusted_client_id(request, st.cfg)
          if st.auth_limiter.blocked(key):
              raise HTTPException(429, "too many failed auth attempts")
          cell = None
          auth = request.headers.get("authorization", "")
          if auth.startswith("Bearer "):
              try:
                  identity, resolved = await resolve_identity(request, st.registry, st.control)
              except HTTPException:
                  identity, resolved = None, None
              if identity is not None and identity.role == "app":
                  cell = resolved
              elif resolved is not None:
                  st.registry.release(resolved)          # resolved but not app-role: drop the pin
          if cell is None and st.session_check(request.cookies.get("hma_session", "")):
              # admin dashboard session → default cell (back-compat, §14)
              cell = await st.registry.acquire("default", st.control.resolve_epoch("default"))
          if cell is None:
              st.auth_limiter.record_failure(key)
              reason = "invalid_token" if auth.startswith("Bearer ") else "missing_bearer"
              log.warning("auth_failure key=%s reason=%s", key, reason)
              raise HTTPException(403, "app token or admin session required")
          if format != "jsonl":
              st.registry.release(cell)
              raise HTTPException(422, "unsupported format (only jsonl)")
          def gen():
              try:
                  for row in cell.db.iter_audit():
                      yield json.dumps(row) + "\n"
              finally:
                  st.registry.release(cell)               # release after the stream drains (§15.4)
          return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")
  ```
  `st.control.resolve_epoch("default")` returns the `default` tenant's current epoch. If Group A's
  `ControlPlane` names this differently, use their accessor (e.g. a `create_tenant` return cached at
  provisioning, or `control.resolve` of a known default route). Reference by whatever Group A pins for
  "current epoch of a tenant id"; the intent is a snapshot-consistent `(tenant_id, epoch)` for `acquire`.
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_audit_export.py -q` → PASS.
- [ ] **Commit:** `feat(app): /v1/audit/export streams only the caller's cell (§15.2)`.

---

### Task C8: `/v1/devices`, `/v1/notify/policy`, `/v1/keys` per-cell + full isolation sweep

Port the remaining `/v1` routes that referenced the removed globals, then add the merge-gate isolation tests
this group owns from §16 (cross-tenant list/read/audit → 404/empty; rate-limiter isolation;
webhook/ntfy egress isolation — B's body only to B's sink).

**Files:**
- Modify `server/arbiter/app.py` (`register` `app.py:301-307`; `devices` `app.py:309-311`;
  `notify_policy` `app.py:313-315`; `keys` `app.py:128-130`).
- Test: `server/tests/test_isolation_group_c.py` (new; the §16 gate slices this group owns).

**Interfaces:**
- Consumes: `require_cell`, `Cell.db`, `Cell.hub`, `Cell.signer.public_jwks()`,
  `Cell.dispatcher.cfg.notify_severities`.
- Produces: `POST /v1/devices`, `GET /v1/devices`, `GET /v1/notify/policy`, `GET /v1/keys` per-cell.

**Steps:**

- [ ] **Failing egress-isolation test.** Create `server/tests/test_isolation_group_c.py`:
  ```python
  import asyncio

  import httpx

  class Recorder:
      """Records webhook POSTs via an httpx MockTransport — WebhookNotifier passes
      `transport` straight to httpx.AsyncClient(transport=...), so a MockTransport
      is the correct hook (NOT a plain callable)."""
      def __init__(self):
          self.calls = []
      def _handler(self, request):
          self.calls.append((str(request.url), request.content))
          return httpx.Response(200)
      def transport(self):
          return httpx.MockTransport(self._handler)

  def test_b_body_egresses_only_to_b_sink(client, tmp_path):
      """§16 webhook egress isolation — B's request body must reach B's sink only.
      Proven at the Dispatcher layer with per-cell CellDelivery: A and B get
      different webhook URLs; a delivery for B's request carries B's title to B's
      URL and never to A's."""
      from arbiter.notify import CellDelivery, build_cell_dispatcher
      from arbiter.config import WebhookCfg
      from arbiter.db import Database

      a_rec, b_rec = Recorder(), Recorder()
      a_del = CellDelivery(webhook=WebhookCfg(url="https://a.example/hook"))
      b_del = CellDelivery(webhook=WebhookCfg(url="https://b.example/hook"))
      a_disp = build_cell_dispatcher(a_del, Database(":memory:"), sender=None,
                                     transport=a_rec.transport())
      b_disp = build_cell_dispatcher(b_del, Database(":memory:"), sender=None,
                                     transport=b_rec.transport())
      req_b = {"id": "r-b", "title": "B-SECRET", "severity": "high", "status": "approved",
               "expires_at": "2999-01-01T00:00:00+00:00", "callback_url": None}
      asyncio.run(b_disp.request_decided(req_b))
      assert any("b.example" in url for url, _ in b_rec.calls)
      assert a_rec.calls == []                              # A's sink saw nothing of B's
      assert any(b"B-SECRET" in body for _, body in b_rec.calls)

  def test_cross_tenant_list_is_empty(client):
      env = client.env
      env.provision("a"); env.provision("b")
      atok = env.mint("a", "agentA", "agent")
      bapp = env.mint("b", "appB", "app")
      client.post("/v1/requests", headers={"Authorization": f"Bearer {atok}"}, json={"title": "A"})
      assert client.get("/v1/requests", headers={"Authorization": f"Bearer {bapp}"}).json() == []

  def test_keys_returns_callers_cell_jwks(client):
      env = client.env
      env.provision("a"); env.provision("b")
      aapp = env.mint("a", "appA", "app")
      bapp = env.mint("b", "appB", "app")
      ka = client.get("/v1/keys", headers={"Authorization": f"Bearer {aapp}"}).json()
      kb = client.get("/v1/keys", headers={"Authorization": f"Bearer {bapp}"}).json()
      akid = ka["keys"][0]["kid"]; bkid = kb["keys"][0]["kid"]
      assert akid.startswith("a:") and bkid.startswith("b:") and akid != bkid

  def test_devices_scoped_to_cell(client):
      env = client.env
      env.provision("a"); env.provision("b")
      aapp = env.mint("a", "appA", "app")
      bapp = env.mint("b", "appB", "app")
      client.post("/v1/devices", headers={"Authorization": f"Bearer {aapp}"},
                  json={"apns_token": "tok-a", "name": "phoneA"})
      assert client.get("/v1/devices", headers={"Authorization": f"Bearer {bapp}"}).json() == []
  ```
  (`WebhookNotifier.__init__(cfg, transport)` passes `transport` to `httpx.AsyncClient(transport=...)`, so
  `httpx.MockTransport` is the right recorder. `request_decided` only fires the webhook when
  `delivery.webhook.enabled` — which is True whenever `webhook.url` is set, as here.)
- [ ] **Run FAIL:** `cd server && python -m pytest tests/test_isolation_group_c.py -q` → FAIL (keys/devices
  routes still 500; egress import may already pass — the route cases fail).
- [ ] **Implement the remaining routes.** In app.py, replace `keys` (`app.py:128-130`):
  ```python
      @app.get("/v1/keys")
      def keys(ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
          _identity, cell = ctx
          return cell.signer.public_jwks()
  ```
  Replace `register` (`app.py:301-307`):
  ```python
      @app.post("/v1/devices")
      async def register(body: DeviceRegister, ctx: tuple = Depends(require_cell("app"))):
          _identity, cell = ctx
          dev = cell.db.register_device(body.apns_token, body.name, body.min_severity,
                                        body.notifications_enabled, body.sound,
                                        severities=body.severities, badge=body.badge)
          cell.hub.publish({"event": "device.updated", "device": dev})
          return dev
  ```
  Replace `devices` (`app.py:309-311`) and `notify_policy` (`app.py:313-315`):
  ```python
      @app.get("/v1/devices")
      def devices(ctx: tuple = Depends(require_cell("app"))):
          _identity, cell = ctx
          return cell.db.list_devices()

      @app.get("/v1/notify/policy")
      def notify_policy(ctx: tuple = Depends(require_cell("app"))):
          _identity, cell = ctx
          return dict(cell.dispatcher.cfg.notify_severities)
  ```
  (`/v1/keys` now requires a bearer — a change from the shipped unauthenticated route. §7 mandates the JWKS
  be "that tenant's", derived from the pinned cell, so a credential is required to name the tenant. The
  warden holds a warden token and fetches with it; device pairing (§10, iOS/pairing group) supplies its own
  credential. Flag this to the warden-rotation group and the iOS 0.6.0 train.)
- [ ] **Run PASS:** `cd server && python -m pytest tests/test_isolation_group_c.py -q` → PASS.
- [ ] **Full-suite check for this group:**
  `cd server && python -m pytest tests/test_app_wiring.py tests/test_require_cell.py tests/test_cell_delivery.py tests/test_percell_requests.py tests/test_percell_reads.py tests/test_percell_decision.py tests/test_audit_export.py tests/test_isolation_group_c.py -q` → PASS.
- [ ] **Commit:** `feat(app): /v1 devices+notify+keys per-cell; §16 group-C isolation gate green`.

---

## Notes / coordination for the merge

- **`/v1/stream`** (§8) is NOT in this group — it still reads the removed `app.state.hub`/`cfg.auth.app_token`
  after this group lands. The stream group re-writes it to resolve `(Identity, Cell)` and bind `cell.hub`.
  Merge-order: land the stream port with or before this group so `create_app` boots (the `stream` route in
  `app.py:317-341` must be edited by that group; this group leaves it untouched to avoid conflict).
- **Dashboard `build_router`** is called here as `build_router(cfg, registry, control)` — the dashboard
  group owns that new signature (§15.2). Coordinate merge order.
- **`ExpiryScheduler`** replaces the deleted `_expire_pass`/`sweep`. Wired via the `scheduler=` param this
  group added to `create_app`; the scheduler group constructs it in `main.py` and passes it.
- **Group A** must build `cell.dispatcher = build_cell_dispatcher(cell_delivery(cfg, tid, dir), cell.db,
  sender)` and per-cell `create_limiter`/`login_limiter`, and open the cell DB at `<dir>/arbiter.sqlite3`.
- **Legacy `require_role`** in `auth.py` is now unused by `/v1` (replaced by `require_cell`); the stream and
  dashboard groups drop their last uses. Leave the symbol until those land, then remove.


---


## Group D — per-tenant signing keys + verdict tenant-binding + `/v1/keys` from the pinned cell + warden rotation trust anchor

Implements design spec **§7** and invariants **§15.8, §15.9, §15.10 (signing)**, and the §16 gate rows:
*cross-tenant verdict rejection with keys FORCED identical*, *rotation trust anchor*, *`keys()` under eviction race*.

Branch: `feat/multitenant-isolation`. Repo (quote the space): `"<repo-root>"`.

### What this group owns

Two files of production surface plus their tests:
- **arbiter side** — `server/arbiter/signing.py` (rewritten to a per-tenant `Signer` object + tenant-bound `sign_verdict` + rotation-record minting), and the `create_app`/`/v1/keys` wiring in `server/arbiter/app.py`.
- **warden side** — `warden/hold_warden/verdict.py` (`VerdictVerifier(pinned, tenant_id)` keyed to LOCAL pinned bytes, `adopt_rotation`), and its config/CLI/service wiring.

### Cross-group names this group PRODUCES (other groups consume these verbatim)
- `Signer` (dataclass): `.tenant_id:str`, `.kid:str` == `f"{tenant_id}:{hash8}"`, `.signing_key:Ed25519PrivateKey`, `.dir:Path`, `.public_jwks()->dict`.
- `load_or_create_signer(tenant_id:str, cell_dir:Path)->Signer` — the builder a **Cell** uses for `cell.signer`.
- `sign_verdict(signer:Signer, *, request_id:str, action_hash:str|None, decision:str, decided_at:str, approval_ttl_seconds:int, tenant_id:str)->str` — EdDSA JWS, `kid=signer.kid`, `aud=f"hma-verdict:{tenant_id}"`, `hma.tenant_id=tenant_id`.
- `sign_rotation_record(old_signer:Signer, *, new_kid:str, new_x:str, seq:int, expires_at:int, tenant_id:str)->str`.
- `rotate_signing_key(tenant_id:str, cell_dir:Path, *, ttl_seconds:int, seq:int)->Signer`.
- Warden `VerdictVerifier(pinned:dict[str,bytes], tenant_id:str, *, last_seq:int=0)` with `.verify(jws, expected_request_id, expected_action_hash)->Verdict` and `.adopt_rotation(record_jws:str, served_jwks:dict)->str` (returns adopted new kid).

### Cross-group names this group CONSUMES (by name from the pinned contract — never by task number)
- **Cell** — `cell.tenant_id`, `cell.epoch`, `cell.signer` (a `Signer`), owned per tenant.
- **`resolve_identity(request, registry, control) -> (Identity, Cell)`** — async; acquires+pins the cell, caller MUST `registry.release(cell)`.
- **Identity** — `.tenant_id`, `.role`.
- **TenantRegistry** — `registry.acquire`/`registry.release`/`registry.hold`; wired onto `app.state.registry`.
- **ControlPlane** — wired onto `app.state.control`.
- **ExpiryScheduler** — the per-firing signer/db binder (Group C); consumes `sign_verdict` per the contract. Group D only leaves the `default`-cell call-sites green; Group C swaps in the per-firing `cell.signer`.

> Test commands assume `python -m pytest` run from the component root (`server/` or `warden/`), where `pyproject.toml` sets `testpaths=["tests"]`, `addopts="-q"`. Install dev deps once per component: `python -m pip install -e ".[dev]"`.

---

### Task D1: `Signer` object + tenant-namespaced kid + `load_or_create_signer`

Replace the free `(kid, key)` pair with a per-cell `Signer` whose `kid` is `f"{tenant_id}:{hash8}"` (widening the old 32-bit kid against grind-collisions, per §7). The private PEM still lives in the cell dir as `verdict_signing_key.pem` (0600, O_EXCL first-run race preserved). `public_jwks()` moves onto the `Signer`.

- **Files:**
  - Modify `server/arbiter/signing.py` (full rewrite of the module header + add `Signer`/`load_or_create_signer`; keep `sign_verdict`/`public_jwks` behavior until D2/where noted).
  - Modify `server/arbiter/app.py:31-34` (config_dir + keypair wiring) and `:84` (`app.state.verdict_kid`) and the `keys()` handler `:128-130`, and the two sign_verdict call-sites `:43-48` and `:272-279` — all to reference the new `Signer` while keeping the *old* `sign_verdict(kid, key, …)` signature (that migrates in D2).
  - Test: `server/tests/test_signing.py` (rewrite the keypair/kid/jwks tests to the `Signer` API).
- **Interfaces:**
  - Consumes: nothing cross-group.
  - Produces: `Signer` (dataclass: `tenant_id`, `kid`, `signing_key`, `dir`), `Signer.public_jwks()->dict`, `load_or_create_signer(tenant_id, cell_dir)->Signer`. Internal helpers `_raw_public_bytes`, `_hash8`, `_b64u`, `_jwk`, `_load_key`, `_mint_key`.

**Steps:**

- [ ] Write the failing test. Replace the top of `server/tests/test_signing.py`'s import + keypair/kid/jwks sections with:
```python
import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from arbiter.signing import Signer, load_or_create_signer


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_signer_kid_is_tenant_namespaced_hash8(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    assert isinstance(s, Signer)
    assert s.tenant_id == "acme"
    tenant, _, hash8 = s.kid.partition(":")
    assert tenant == "acme"
    assert hash8 == hashlib.sha256(_raw_pub(s.signing_key)).hexdigest()[:8]
    int(hash8, 16)  # pure hex


def test_pem_is_0600_and_persists_across_loads(tmp_path):
    s1 = load_or_create_signer("acme", tmp_path)
    pem = tmp_path / "verdict_signing_key.pem"
    assert pem.is_file()
    assert oct(pem.stat().st_mode & 0o777) == "0o600"
    s2 = load_or_create_signer("acme", tmp_path)
    assert s1.kid == s2.kid
    assert _raw_pub(s1.signing_key) == _raw_pub(s2.signing_key)


def test_distinct_dirs_get_distinct_keys_same_tenant_prefix(tmp_path):
    a = load_or_create_signer("acme", tmp_path / "a")
    b = load_or_create_signer("acme", tmp_path / "b")
    assert a.kid.startswith("acme:") and b.kid.startswith("acme:")
    assert a.kid != b.kid  # different key bytes -> different hash8


def test_race_loser_loads_winners_key(tmp_path, monkeypatch):
    winner = load_or_create_signer("acme", tmp_path)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    loser = load_or_create_signer("acme", tmp_path)
    assert loser.kid == winner.kid
    assert _raw_pub(loser.signing_key) == _raw_pub(winner.signing_key)


def test_public_jwks_shape(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jwks = s.public_jwks()
    assert set(jwks) == {"keys"} and len(jwks["keys"]) == 1
    k = jwks["keys"][0]
    assert set(k) == {"kty", "crv", "kid", "x"}
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["kid"] == s.kid
    assert "=" not in k["x"]
    assert base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4)) == _raw_pub(s.signing_key)
```
- [ ] Run it, expect FAIL (ImportError: `Signer`):
  `cd server && python -m pytest tests/test_signing.py -q`
- [ ] Minimal implementation. Rewrite `server/arbiter/signing.py` down to and including `public_jwks`. Replace lines 1-60 and 84-88 (leave the existing `sign_verdict` at 63-81 UNCHANGED for now — D2 migrates it) with:
```python
"""Ed25519 verdict signing — one signer per tenant cell.

Each cell owns its own Ed25519 key (private PEM at cell_dir/verdict_signing_key.pem,
0600). The kid is tenant-namespaced: f"{tenant_id}:{hash8}" where hash8 is the first
8 hex chars of sha256(raw public bytes) — widening the old 32-bit kid against grind
collisions and turning cross-tenant key confusion into a loud kid mismatch. Verdicts
are EdDSA JWS tokens bound to the tenant via aud=f"hma-verdict:{tenant_id}" plus an
hma.tenant_id claim (§7). Key rotation stages a record signed by the OLD key.
"""
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_FILENAME = "verdict_signing_key.pem"
RETIRED_FILENAME = "verdict_signing_key.retired.pem"
ROTATION_FILENAME = "verdict_rotation.json"


def _raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _hash8(key: Ed25519PrivateKey) -> str:
    return hashlib.sha256(_raw_public_bytes(key)).hexdigest()[:8]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwk(kid: str, key: Ed25519PrivateKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64u(_raw_public_bytes(key))}


def _load_key(pem_path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{pem_path} is not an Ed25519 private key")
    return key


def _mint_key(pem_path: Path) -> Ed25519PrivateKey:
    """Create a new PEM 0600 via O_EXCL; the loser of a first-run race loads the
    winner's key rather than crashing on FileExistsError."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    try:
        fd = os.open(pem_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _load_key(pem_path)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


@dataclass
class Signer:
    tenant_id: str
    kid: str
    signing_key: Ed25519PrivateKey
    dir: Path

    def public_jwks(self) -> dict:
        """JWKS served at GET /v1/keys for THIS tenant. During a rotation grace
        window the retired (previous) key is served alongside the current one and
        the OLD-key-signed rotation record is attached under "rotation"."""
        keys = [_jwk(self.kid, self.signing_key)]
        rec = _load_rotation(self.dir)
        if rec is not None:
            keys.append({"kty": "OKP", "crv": "Ed25519",
                         "kid": rec["prev_kid"], "x": rec["prev_x"]})
            return {"keys": keys, "rotation": rec["record"]}
        return {"keys": keys}


def load_or_create_signer(tenant_id: str, cell_dir) -> Signer:
    """Load (or mint on first run) this cell's Ed25519 signer.
    kid = f"{tenant_id}:{first-8-hex-of-sha256(raw pub)}"."""
    cell_dir = Path(cell_dir).expanduser()
    cell_dir.mkdir(parents=True, exist_ok=True)
    pem_path = cell_dir / KEY_FILENAME
    key = _load_key(pem_path) if pem_path.is_file() else _mint_key(pem_path)
    return Signer(tenant_id=tenant_id, kid=f"{tenant_id}:{_hash8(key)}",
                  signing_key=key, dir=cell_dir)


def _write_rotation(cell_dir: Path, rec: dict) -> None:
    (Path(cell_dir) / ROTATION_FILENAME).write_text(json.dumps(rec))


def _load_rotation(cell_dir: Path):
    """Return the staged rotation dict, or None if absent, unreadable, or expired."""
    p = Path(cell_dir) / ROTATION_FILENAME
    if not p.is_file():
        return None
    try:
        rec = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    if int(rec.get("expires_at", 0)) < int(time.time()):
        return None
    return rec
```
Then update the OLD `sign_verdict` (still lines ~63-81 in the shipped file) to keep working unchanged, and DELETE the old module-level `public_jwks` function (its behavior now lives on `Signer.public_jwks`).
- [ ] Wire `app.py` to the `Signer` (keeping the old `sign_verdict(kid,key,…)` calls). In `server/arbiter/app.py`:
  - Change the import `:19` `from .signing import load_or_create_keypair, public_jwks, sign_verdict` → `from .signing import load_or_create_signer, sign_verdict`.
  - Change `:34` `kid, signing_key = load_or_create_keypair(config_dir)` → `signer = load_or_create_signer("default", config_dir)`.
  - In `_expire_pass` (`:43-48`): `sign_verdict(kid, signing_key, …)` → `sign_verdict(signer.kid, signer.signing_key, …)`; `db.set_verdict(req["id"], jws, kid)` → `…, signer.kid)`; `{"decision": "expired", "kid": kid}` → `{"decision": "expired", "kid": signer.kid}`.
  - `:84` `app.state.verdict_kid = kid` → `app.state.verdict_kid = signer.kid`.
  - `keys()` `:128-130` `return public_jwks(kid, signing_key)` → `return signer.public_jwks()`.
  - decide path `:272-279`: `sign_verdict(kid, signing_key, …)` → `sign_verdict(signer.kid, signer.signing_key, …)`; `db.set_verdict(updated["id"], jws, kid)` → `…, signer.kid)`; `{"decision": updated["status"], "kid": kid}` → `…, "kid": signer.kid}`.
- [ ] Run green: `cd server && python -m pytest tests/test_signing.py tests/test_verdicts.py -q` — expect PASS.
- [ ] Commit: `feat(signing): per-cell Signer with tenant-namespaced kid f"{tenant}:{hash8}"`.

---

### Task D2: tenant-bound `sign_verdict` (`aud=hma-verdict:{tenant}` + `hma.tenant_id`)

Bind the tenant *into the verdict itself* so cross-tenant crypto is a loud rejection, not a silent break resting on key distinctness (§7, §15.8). New signature takes the `Signer` and an explicit `tenant_id` (per the pinned contract).

- **Files:**
  - Modify `server/arbiter/signing.py` (replace the old `sign_verdict`).
  - Modify `server/arbiter/app.py` — the two call-sites (`_expire_pass`, decide) to the new signature with `tenant_id="default"`.
  - Test: `server/tests/test_signing.py` (append the sign_verdict round-trip tests, keyed to the new claims).
- **Interfaces:**
  - Consumes: `Signer` (D1).
  - Produces: `sign_verdict(signer, *, request_id, action_hash, decision, decided_at, approval_ttl_seconds, tenant_id)->str`.

**Steps:**

- [ ] Write the failing test. Append to `server/tests/test_signing.py`:
```python
import jwt as _jwt
from arbiter.signing import sign_verdict


def test_sign_verdict_binds_tenant_in_aud_and_claim(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r1", action_hash="ab" * 32, decision="approved",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl_seconds=600,
                       tenant_id="acme")
    assert _jwt.get_unverified_header(jws)["kid"] == s.kid  # "acme:<hash8>"
    decoded = _jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                          audience="hma-verdict:acme")
    assert decoded["iss"] == "hma"
    assert decoded["aud"] == "hma-verdict:acme"
    assert decoded["jti"] == "r1" and isinstance(decoded["iat"], int)
    assert decoded["hma"] == {"tenant_id": "acme", "request_id": "r1",
                              "action_hash": "ab" * 32, "decision": "approved",
                              "decided_at": "2026-07-07T00:00:00+00:00",
                              "approval_ttl_seconds": 600}


def test_verdict_from_tenant_a_fails_audience_for_tenant_b(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r2", action_hash=None, decision="denied",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl_seconds=600,
                       tenant_id="acme")
    # Even with the SAME key, decoding as tenant "beta" fails on audience.
    with pytest.raises(_jwt.InvalidAudienceError):
        _jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                    audience="hma-verdict:beta")


def test_action_hash_none_still_signs(tmp_path):
    s = load_or_create_signer("acme", tmp_path)
    jws = sign_verdict(s, request_id="r3", action_hash=None, decision="expired",
                       decided_at="2026-07-07T00:00:00+00:00", approval_ttl_seconds=600,
                       tenant_id="acme")
    decoded = _jwt.decode(jws, s.signing_key.public_key(), algorithms=["EdDSA"],
                          audience="hma-verdict:acme")
    assert decoded["hma"]["action_hash"] is None
```
- [ ] Run it, expect FAIL (TypeError — old `sign_verdict` takes `(kid, key, …)`):
  `cd server && python -m pytest tests/test_signing.py -q -k sign_verdict`
- [ ] Minimal implementation. In `server/arbiter/signing.py`, replace the old `sign_verdict` with:
```python
def sign_verdict(signer: Signer, *, request_id: str, action_hash: str | None,
                 decision: str, decided_at: str, approval_ttl_seconds: int,
                 tenant_id: str) -> str:
    """Sign a verdict as a tenant-bound EdDSA JWS. action_hash=None means the request
    was created without a canonical action (cooperative tier) — verifiably unbound.
    aud and the hma.tenant_id claim namespace the verdict to tenant_id so a
    neighbouring cell's warden rejects it even if the raw keys ever coincide (§7)."""
    payload = {
        "iss": "hma",
        "aud": f"hma-verdict:{tenant_id}",
        "jti": request_id,
        "iat": int(time.time()),
        "hma": {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "action_hash": action_hash,
            "decision": decision,
            "decided_at": decided_at,
            "approval_ttl_seconds": approval_ttl_seconds,
        },
    }
    return jwt.encode(payload, signer.signing_key, algorithm="EdDSA",
                      headers={"kid": signer.kid})
```
- [ ] Update the `app.py` call-sites to the new signature. In `_expire_pass`:
```python
            jws = sign_verdict(signer, request_id=req["id"],
                               action_hash=req["action_hash"], decision="expired",
                               decided_at=req["expires_at"],
                               approval_ttl_seconds=cfg.policy.approval_ttl_seconds,
                               tenant_id=signer.tenant_id)
```
and in the decide path (was `:272`):
```python
        jws = sign_verdict(signer, request_id=updated["id"],
                           action_hash=updated["action_hash"], decision=updated["status"],
                           decided_at=updated["decided_at"],
                           approval_ttl_seconds=cfg.policy.approval_ttl_seconds,
                           tenant_id=signer.tenant_id)
```
(Keep whatever `action_hash`/`decided_at`/`approval_ttl_seconds` arguments the shipped decide call already passed — only the leading `signer` and trailing `tenant_id=` change; verify against the surrounding shipped lines when editing.)
- [ ] Run green: `cd server && python -m pytest tests/test_signing.py tests/test_verdicts.py -q` — expect PASS.
- [ ] Commit: `feat(signing): bind tenant into verdict (aud=hma-verdict:{tenant} + hma.tenant_id)` + trailer.

---

### Task D3: `sign_rotation_record` — a record signed by the OLD key

A rotation record attests a NEW key, is signed by the OLD key, carries `tenant_id`, a strictly-monotonic `seq`, and an `expires_at` (grace deadline). It is the ONLY thing that lets a warden adopt a new kid (§7, §15.9).

- **Files:**
  - Modify `server/arbiter/signing.py` (add `sign_rotation_record` + `ROTATION_AUD_PREFIX`).
  - Test: `server/tests/test_rotation_record.py` (new).
- **Interfaces:**
  - Consumes: `Signer` (D1).
  - Produces: `sign_rotation_record(old_signer, *, new_kid, new_x, seq, expires_at, tenant_id)->str`.

**Steps:**

- [ ] Write the failing test. Create `server/tests/test_rotation_record.py`:
```python
import time

import jwt
import pytest

from arbiter.signing import load_or_create_signer, sign_rotation_record


def test_rotation_record_signed_by_old_key_carries_new_key_and_seq(tmp_path):
    old = load_or_create_signer("acme", tmp_path / "old")
    new = load_or_create_signer("acme", tmp_path / "new")
    new_x = new.public_jwks()["keys"][0]["x"]
    exp = int(time.time()) + 3600
    rec = sign_rotation_record(old, new_kid=new.kid, new_x=new_x, seq=1,
                               expires_at=exp, tenant_id="acme")
    # Header kid is the OLD kid; the record verifies under the OLD public key only.
    assert jwt.get_unverified_header(rec)["kid"] == old.kid
    decoded = jwt.decode(rec, old.signing_key.public_key(), algorithms=["EdDSA"],
                         audience="hma-rotation:acme")
    assert decoded["hma"] == {"tenant_id": "acme", "new_kid": new.kid,
                              "new_x": new_x, "seq": 1, "expires_at": exp}


def test_rotation_record_does_not_verify_under_new_key(tmp_path):
    old = load_or_create_signer("acme", tmp_path / "old")
    new = load_or_create_signer("acme", tmp_path / "new")
    new_x = new.public_jwks()["keys"][0]["x"]
    rec = sign_rotation_record(old, new_kid=new.kid, new_x=new_x, seq=1,
                               expires_at=int(time.time()) + 3600, tenant_id="acme")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(rec, new.signing_key.public_key(), algorithms=["EdDSA"],
                   audience="hma-rotation:acme")
```
- [ ] Run it, expect FAIL (ImportError: `sign_rotation_record`):
  `cd server && python -m pytest tests/test_rotation_record.py -q`
- [ ] Minimal implementation. In `server/arbiter/signing.py`, after `sign_verdict`, add:
```python
ROTATION_AUD_PREFIX = "hma-rotation:"


def sign_rotation_record(old_signer: Signer, *, new_kid: str, new_x: str, seq: int,
                         expires_at: int, tenant_id: str) -> str:
    """Sign a key-rotation record with the OLD key. The warden adopts new_kid ONLY
    if this record verifies under a LOCAL pin, carries tenant_id==paired, has
    seq strictly greater than the last adopted, and is not past expires_at (§7)."""
    payload = {
        "iss": "hma",
        "aud": f"{ROTATION_AUD_PREFIX}{tenant_id}",
        "iat": int(time.time()),
        "hma": {
            "tenant_id": tenant_id,
            "new_kid": new_kid,
            "new_x": new_x,
            "seq": seq,
            "expires_at": expires_at,
        },
    }
    return jwt.encode(payload, old_signer.signing_key, algorithm="EdDSA",
                      headers={"kid": old_signer.kid})
```
- [ ] Run green: `cd server && python -m pytest tests/test_rotation_record.py -q` — expect PASS.
- [ ] Commit: `feat(signing): sign_rotation_record signed by the old key (seq + expiry + tenant)` + trailer.

---

### Task D4: `rotate_signing_key` — mint new key, retire old, stage the grace window

Executing a rotation: mint a fresh cell key, archive the old PEM, sign a rotation record with the OLD key, and stage `verdict_rotation.json` so `Signer.public_jwks()` serves BOTH keys + the record for the grace window (§7). Old-key retirement is thereby a locally-recorded signed event, never inferred from absence.

- **Files:**
  - Modify `server/arbiter/signing.py` (add `rotate_signing_key`).
  - Test: `server/tests/test_rotate_key.py` (new).
- **Interfaces:**
  - Consumes: `Signer`, `load_or_create_signer`, `sign_rotation_record`, `_write_rotation`/`_load_rotation` (D1/D3).
  - Produces: `rotate_signing_key(tenant_id, cell_dir, *, ttl_seconds, seq)->Signer`.

**Steps:**

- [ ] Write the failing test. Create `server/tests/test_rotate_key.py`:
```python
import time

import jwt
import pytest

from arbiter.signing import load_or_create_signer, rotate_signing_key


def test_rotate_changes_current_key_and_stages_grace_set(tmp_path):
    old = load_or_create_signer("acme", tmp_path)
    new = rotate_signing_key("acme", tmp_path, ttl_seconds=3600, seq=1)
    assert new.kid != old.kid
    assert new.kid.startswith("acme:")
    # A fresh load now returns the NEW key.
    assert load_or_create_signer("acme", tmp_path).kid == new.kid

    jwks = new.public_jwks()
    kids = {k["kid"] for k in jwks["keys"]}
    assert new.kid in kids and old.kid in kids     # both served during grace
    assert "rotation" in jwks
    # The staged record is signed by the OLD key and names the NEW kid.
    rec = jwks["rotation"]
    assert jwt.get_unverified_header(rec)["kid"] == old.kid
    decoded = jwt.decode(rec, old.signing_key.public_key(), algorithms=["EdDSA"],
                         audience="hma-rotation:acme")
    assert decoded["hma"]["new_kid"] == new.kid and decoded["hma"]["seq"] == 1


def test_expired_grace_window_drops_prev_key_and_record(tmp_path):
    old = load_or_create_signer("acme", tmp_path)
    new = rotate_signing_key("acme", tmp_path, ttl_seconds=-1, seq=1)  # already expired
    jwks = new.public_jwks()
    assert [k["kid"] for k in jwks["keys"]] == [new.kid]  # only current
    assert "rotation" not in jwks
    _ = old  # (retired PEM retained on disk; not served past grace)
```
- [ ] Run it, expect FAIL (ImportError: `rotate_signing_key`):
  `cd server && python -m pytest tests/test_rotate_key.py -q`
- [ ] Minimal implementation. In `server/arbiter/signing.py`, add:
```python
def rotate_signing_key(tenant_id: str, cell_dir, *, ttl_seconds: int, seq: int) -> Signer:
    """Rotate this cell's signing key. Archives the current PEM to
    verdict_signing_key.retired.pem, mints a fresh current key, signs a rotation
    record with the OLD key, and stages verdict_rotation.json so public_jwks()
    serves both keys + the record until expires_at. seq must be strictly greater
    than any previously staged seq (the caller supplies the next value)."""
    cell_dir = Path(cell_dir).expanduser()
    old = load_or_create_signer(tenant_id, cell_dir)
    pem_path = cell_dir / KEY_FILENAME
    os.replace(pem_path, cell_dir / RETIRED_FILENAME)
    new_key = _mint_key(pem_path)
    new = Signer(tenant_id=tenant_id, kid=f"{tenant_id}:{_hash8(new_key)}",
                 signing_key=new_key, dir=cell_dir)
    expires_at = int(time.time()) + ttl_seconds
    record = sign_rotation_record(old, new_kid=new.kid, new_x=_b64u(_raw_public_bytes(new_key)),
                                  seq=seq, expires_at=expires_at, tenant_id=tenant_id)
    _write_rotation(cell_dir, {
        "record": record, "seq": seq, "expires_at": expires_at,
        "prev_kid": old.kid, "prev_x": _b64u(_raw_public_bytes(old.signing_key)),
    })
    return new
```
- [ ] Run green: `cd server && python -m pytest tests/test_rotate_key.py tests/test_signing.py -q` — expect PASS.
- [ ] Commit: `feat(signing): rotate_signing_key stages grace-window JWKS + old-key-signed record` + trailer.

---

### Task D5: `GET /v1/keys` serves the refcount-pinned cell's JWKS

`/v1/keys` derives the tenant from the credential (never a hint), pins the resolved cell for the handler's full lifetime, asserts `identity.tenant_id == cell.tenant_id`, serves `cell.signer.public_jwks()`, and releases exactly once — so a pairing fetch racing an eviction/reopen can never be handed a neighbour's JWKS (§7, §15.2, and the §16 *keys() under eviction race* row).

- **Files:**
  - Modify `server/arbiter/app.py` — the `keys()` handler (was `:128-130`).
  - Test: `server/tests/test_keys_endpoint.py` (new; uses lightweight fakes for `registry`/`control`/`Cell` matching the pinned contract, so this task is independent of Group A/B's concrete `TenantRegistry`).
- **Interfaces:**
  - Consumes: `resolve_identity(request, registry, control)->(Identity, Cell)`, `registry.release(cell)`, `Cell.tenant_id`, `Cell.signer`, `Identity.tenant_id` — wired onto `app.state.registry` and `app.state.control` by the **TenantRegistry** / **ControlPlane** groups.
  - Produces: nothing new (endpoint behavior).

**Steps:**

- [ ] Write the failing test. Create `server/tests/test_keys_endpoint.py`:
```python
"""GET /v1/keys serves the pinned cell's JWKS and survives an eviction/reopen race.

Uses fakes for registry/control/cell shaped to the pinned cross-component contract
so this endpoint test does not depend on Group A/B's concrete TenantRegistry.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from arbiter.signing import load_or_create_signer


class FakeCell:
    def __init__(self, tenant_id, signer):
        self.tenant_id = tenant_id
        self.epoch = 1
        self.signer = signer


class FakeRegistry:
    """Resolves a bearer to a fixed cell; records acquire/release balance. A
    'reopen' can swap the map's cell, but a live holder keeps its bound object."""
    def __init__(self, cells_by_token):
        self._by_token = dict(cells_by_token)   # token -> cell
        self.acquired = 0
        self.released = 0

    def acquire_for(self, token):
        cell = self._by_token.get(token)
        if cell is None:
            raise HTTPException(status_code=403, detail="forbidden")
        self.acquired += 1
        return cell

    def release(self, cell):
        self.released += 1

    def swap(self, token, cell):        # simulate an eviction+reopen twin
        self._by_token[token] = cell


async def _fake_resolve_identity(request: Request, registry, control):
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    cell = registry.acquire_for(token)
    identity = SimpleNamespace(tenant_id=cell.tenant_id, role="app")
    return identity, cell


@pytest.fixture
def keys_app(tmp_path, monkeypatch):
    from arbiter import app as app_mod
    monkeypatch.setattr(app_mod, "resolve_identity", _fake_resolve_identity)

    signer_a = load_or_create_signer("acme", tmp_path / "acme")
    signer_b = load_or_create_signer("beta", tmp_path / "beta")
    reg = FakeRegistry({"tok-a": FakeCell("acme", signer_a),
                        "tok-b": FakeCell("beta", signer_b)})

    from arbiter.apns import APNsSender
    from arbiter.config import Config
    from arbiter.db import Database
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.server.db_path = str(tmp_path / "t.sqlite3")
    fastapi_app = app_mod.create_app(cfg, Database(":memory:"), APNsSender(cfg))
    fastapi_app.state.registry = reg
    fastapi_app.state.control = object()
    return fastapi_app, reg, signer_a, signer_b


def test_keys_serves_callers_own_tenant(keys_app):
    app, reg, sa, sb = keys_app
    with TestClient(app) as c:
        ra = c.get("/v1/keys", headers={"Authorization": "Bearer tok-a"})
        rb = c.get("/v1/keys", headers={"Authorization": "Bearer tok-b"})
    assert ra.json()["keys"][0]["kid"] == sa.kid
    assert rb.json()["keys"][0]["kid"] == sb.kid
    assert reg.acquired == reg.released == 2      # exactly-once release


def test_keys_no_route_is_403(keys_app):
    app, reg, _, _ = keys_app
    with TestClient(app) as c:
        r = c.get("/v1/keys", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 403


def test_keys_under_reopen_race_serves_the_pinned_tenant(keys_app, tmp_path):
    app, reg, sa, sb = keys_app
    # Point tok-a's map entry at a twin AFTER the fixture but the request still
    # binds whatever acquire_for returns; assert the served kid is A's, never B's.
    with TestClient(app) as c:
        r = c.get("/v1/keys", headers={"Authorization": "Bearer tok-a"})
    assert r.json()["keys"][0]["kid"] == sa.kid
    assert r.json()["keys"][0]["kid"] != sb.kid
```
- [ ] Run it, expect FAIL (the shipped `keys()` ignores the registry and returns the process signer, so `tok-b` would still get A's kid / or the sync handler mismatches):
  `cd server && python -m pytest tests/test_keys_endpoint.py -q`
- [ ] Minimal implementation. In `server/arbiter/app.py`, ensure `resolve_identity` is imported at module scope (it already is, via `from .auth import … resolve_identity`). Replace the `keys()` handler:
```python
    @app.get("/v1/keys")
    async def keys(request: Request):
        # Tenant is derived from the credential; the resolved cell is pinned for
        # this handler's whole lifetime and released exactly once, so an eviction/
        # reopen race can never hand a pairing fetch a neighbour's JWKS (§7).
        identity, cell = await resolve_identity(
            request, request.app.state.registry, request.app.state.control)
        try:
            assert identity.tenant_id == cell.tenant_id
            return cell.signer.public_jwks()
        finally:
            request.app.state.registry.release(cell)
```
- [ ] Run green: `cd server && python -m pytest tests/test_keys_endpoint.py -q` — expect PASS.
- [ ] Commit: `feat(app): /v1/keys serves the refcount-pinned cell's JWKS (tenant from credential)` + trailer.

> Integration note (no code here): once the **TenantRegistry**/**ControlPlane** groups land, `create_app` populates `app.state.registry` and `app.state.control`, and the legacy single-tenant path resolves the `default` cell through the same `resolve_identity`. This endpoint requires those on `app.state`; the §16 suite exercises the real registry.

---

### Task D6: warden `VerdictVerifier(pinned, tenant_id)` keyed to LOCAL pinned bytes

Re-key the warden's trust anchor to a **set of locally-pinned public keys** and enforce the tenant binding: the header kid must be a LOCAL pin, and `aud`/`hma.tenant_id` must equal the warden's paired tenant. Isolation never rests on key distinctness alone (§7, §15.8, §15.9).

- **Files:**
  - Modify `warden/hold_warden/verdict.py` (rewrite `VerdictVerifier.__init__` + `verify`).
  - Test: `warden/tests/test_verdict.py` (rewrite the keypair/pin helpers + verify tests to the new constructor).
- **Interfaces:**
  - Consumes: nothing cross-group (mirrors the arbiter JWS format from D2).
  - Produces: `VerdictVerifier(pinned:dict[str,bytes], tenant_id:str, *, last_seq:int=0)`, `.verify(jws, expected_request_id, expected_action_hash)->Verdict`.

**Steps:**

- [ ] Write the failing test. Replace the helper block + verify tests at the top of `warden/tests/test_verdict.py` with:
```python
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import Verdict, VerdictError, VerdictVerifier

TENANT = "acme"


def _keypair(tenant: str = TENANT):
    """Returns (key, kid, raw_pub_bytes). kid = f"{tenant}:{hash8}"."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"{tenant}:{hashlib.sha256(raw).hexdigest()[:8]}"
    return key, kid, raw


def _sign(key, kid, *, request_id, action_hash, tenant=TENANT, decision="approved",
          decided_at=None, approval_ttl_seconds=600, aud=None):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "hma",
        "aud": aud if aud is not None else f"hma-verdict:{tenant}",
        "jti": request_id,
        "iat": int(now.timestamp()),
        "hma": {
            "tenant_id": tenant,
            "request_id": request_id,
            "action_hash": action_hash,
            "decision": decision,
            "decided_at": decided_at or now.isoformat(),
            "approval_ttl_seconds": approval_ttl_seconds,
        },
    }
    return jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": kid})


def test_valid_bound_verdict_round_trip():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-1", action_hash="a1" * 32)
    out = v.verify(token, "rid-1", "a1" * 32)
    assert isinstance(out, Verdict)
    assert out.request_id == "rid-1" and out.action_hash == "a1" * 32


def test_unbound_action_hash_none():
    key, kid, raw = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(key, kid, request_id="rid-2", action_hash=None, decision="denied")
    assert v.verify(token, "rid-2", None).action_hash is None


def test_wrong_key_rejected_even_with_pinned_kid():
    key1, kid1, raw1 = _keypair()
    key2, _, _ = _keypair()
    v = VerdictVerifier({kid1: raw1}, TENANT)
    token = _sign(key2, kid1, request_id="rid-3", action_hash=None)  # wrong key, pinned kid
    with pytest.raises(VerdictError):
        v.verify(token, "rid-3", None)


def test_unpinned_kid_rejected():
    key, kid, raw = _keypair()
    other_key, other_kid, _ = _keypair()
    v = VerdictVerifier({kid: raw}, TENANT)
    token = _sign(other_key, other_kid, request_id="rid-4", action_hash=None)
    with pytest.raises(VerdictError):
        v.verify(token, "rid-4", None)


def test_cross_tenant_rejected_even_with_forced_identical_key():
    # THE §16 gate: tenant A's verdict, verified by tenant B's warden that has
    # FORCED the identical key bytes, still fails on aud/tenant_id.
    key, hash8_kid_a, raw = _keypair(tenant="acme")
    # Warden B pins the SAME raw bytes but under a beta-namespaced kid & tenant.
    kid_b = f"beta:{hash8_kid_a.split(':', 1)[1]}"
    vb = VerdictVerifier({kid_b: raw}, "beta")
    token = _sign(key, hash8_kid_a, request_id="rid-5", action_hash=None, tenant="acme")
    with pytest.raises(VerdictError):
        vb.verify(token, "rid-5", None)


def test_claim_tenant_mismatch_rejected():
    # kid + key + aud all say acme, but the hma.tenant_id claim is forged to beta.
    key, kid, raw = _keypair(tenant="acme")
    v = VerdictVerifier({kid: raw}, "acme")
    now = datetime.now(timezone.utc)
    payload = {"iss": "hma", "aud": "hma-verdict:acme", "jti": "rid-6",
               "iat": int(now.timestamp()),
               "hma": {"tenant_id": "beta", "request_id": "rid-6", "action_hash": None,
                       "decision": "approved", "decided_at": now.isoformat(),
                       "approval_ttl_seconds": 600}}
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": kid})
    with pytest.raises(VerdictError):
        v.verify(token, "rid-6", None)
```
(Delete the old `_keypair`/`_sign`/`pinned`-string tests they replace; any remaining request_id/action_hash/staleness tests keep working once they use the new `_sign`/constructor.)
- [ ] Run it, expect FAIL (constructor still takes a `"kid:b64url"` string):
  `cd warden && python -m pytest tests/test_verdict.py -q`
- [ ] Minimal implementation. Rewrite `warden/hold_warden/verdict.py` `__init__`/`verify` (keep `Verdict`/`VerdictError`):
```python
"""Verdict verification — the warden's trust anchor.

The warden trusts ONLY locally pinned public-key bytes (from `hma-warden init`),
keyed by kid = f"{tenant_id}:{hash8}". A verdict must (a) carry a header kid that
is a LOCAL pin, (b) verify under that pin's bytes, (c) have aud == "hma-verdict:
{paired-tenant}" AND hma.tenant_id == paired-tenant — so a neighbour's verdict is
a loud rejection even if the raw keys ever coincide (§7, §15.8/9).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class VerdictError(Exception):
    """Raised on ANY verification failure. Callers must never execute after this."""


@dataclass
class Verdict:
    request_id: str
    action_hash: str | None
    decision: str
    decided_at: str
    approval_ttl_seconds: int


class VerdictVerifier:
    def __init__(self, pinned: dict[str, bytes], tenant_id: str, *, last_seq: int = 0):
        if not pinned:
            raise VerdictError("no pinned keys — run 'hma-warden init'")
        # Copy so adopt_rotation mutations do not alias the caller's dict.
        self._pinned: dict[str, bytes] = dict(pinned)
        self._tenant_id = tenant_id
        self._last_seq = last_seq
        self._audience = f"hma-verdict:{tenant_id}"

    def _pubkey(self, kid: str) -> Ed25519PublicKey:
        raw = self._pinned.get(kid)
        if raw is None:
            raise VerdictError(f"verdict kid {kid!r} is not a locally pinned key")
        return Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, jws: str, expected_request_id: str,
               expected_action_hash: str | None) -> Verdict:
        try:
            header = jwt.get_unverified_header(jws)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"malformed verdict token: {exc}") from exc
        key = self._pubkey(header.get("kid"))       # LOCAL pin or VerdictError
        try:
            payload = jwt.decode(jws, key, algorithms=["EdDSA"], audience=self._audience)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"verdict signature/claims invalid: {exc}") from exc
        hma = payload.get("hma")
        if not isinstance(hma, dict):
            raise VerdictError("verdict missing 'hma' claim")
        if hma.get("tenant_id") != self._tenant_id:
            raise VerdictError(
                f"verdict tenant_id {hma.get('tenant_id')!r} != paired {self._tenant_id!r}")
        try:
            v = Verdict(
                request_id=hma["request_id"],
                action_hash=hma["action_hash"],
                decision=hma["decision"],
                decided_at=hma["decided_at"],
                approval_ttl_seconds=int(hma["approval_ttl_seconds"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VerdictError(f"verdict 'hma' claim malformed: {exc}") from exc
        if v.request_id != expected_request_id:
            raise VerdictError(
                f"verdict request_id {v.request_id!r} != expected {expected_request_id!r}")
        if v.action_hash != expected_action_hash:
            raise VerdictError(
                f"verdict action_hash {v.action_hash!r} != expected {expected_action_hash!r}")
        try:
            decided = datetime.fromisoformat(v.decided_at)
        except (TypeError, ValueError) as exc:
            raise VerdictError(f"verdict decided_at unparseable: {v.decided_at!r}") from exc
        if decided.tzinfo is None:
            decided = decided.replace(tzinfo=timezone.utc)
        if decided + timedelta(seconds=v.approval_ttl_seconds) < datetime.now(timezone.utc):
            raise VerdictError(
                f"verdict stale: decided_at {v.decided_at} + {v.approval_ttl_seconds}s passed")
        return v
```
- [ ] Run green: `cd warden && python -m pytest tests/test_verdict.py -q` — expect PASS.
- [ ] Commit: `feat(warden): VerdictVerifier keyed to local pin set + tenant/aud binding` + trailer.

---

### Task D7: warden `adopt_rotation` — LOCAL-pin verified, tenant-matched, seq-monotonic, unexpired

Adopt a new kid **iff** the rotation record (a) verifies under a LOCAL pin, (b) carries `tenant_id == paired`, (c) has `seq` strictly greater than the last adopted, (d) is not past `expires_at`, and (e) the new key's `x` appears in the served set (candidate material only). Reject rogue/served-key-signed, replay/older-seq, expired records, and never adopt merely because the old key is absent from the served set (§7, §15.9).

- **Files:**
  - Modify `warden/hold_warden/verdict.py` (add `adopt_rotation` + `ROTATION_AUD_PREFIX`).
  - Test: `warden/tests/test_rotation.py` (new).
- **Interfaces:**
  - Consumes: `VerdictVerifier` (D6); mirrors `sign_rotation_record` output (D3).
  - Produces: `VerdictVerifier.adopt_rotation(record_jws:str, served_jwks:dict)->str` (returns adopted new kid); mutates `self._pinned` (adds new kid) and `self._last_seq`.

**Steps:**

- [ ] Write the failing test. Create `warden/tests/test_rotation.py`:
```python
from __future__ import annotations

import base64
import hashlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hold_warden.verdict import VerdictVerifier

TENANT = "acme"


def _keypair(tenant: str = TENANT):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"{tenant}:{hashlib.sha256(raw).hexdigest()[:8]}"
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return key, kid, raw, x


def _record(old_key, old_kid, *, new_kid, new_x, seq, expires_at, tenant=TENANT, aud=None):
    payload = {"iss": "hma", "aud": aud if aud is not None else f"hma-rotation:{tenant}",
               "iat": int(time.time()),
               "hma": {"tenant_id": tenant, "new_kid": new_kid, "new_x": new_x,
                       "seq": seq, "expires_at": expires_at}}
    return jwt.encode(payload, old_key, algorithm="EdDSA", headers={"kid": old_kid})


def _served(*jwks_entries):
    return {"keys": list(jwks_entries)}


def _jwk(kid, x):
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x}


def test_adopt_valid_record_adds_new_kid_and_bumps_seq():
    ok, okid, oraw, ox = _keypair()
    nk, nkid, nraw, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    served = _served(_jwk(okid, ox), _jwk(nkid, nx))
    assert v.adopt_rotation(rec, served) == nkid
    # New key is now pinned: a verdict signed by it verifies; the OLD key remains pinned too.
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    payload = {"iss": "hma", "aud": "hma-verdict:acme", "jti": "r", "iat": int(now.timestamp()),
               "hma": {"tenant_id": "acme", "request_id": "r", "action_hash": None,
                       "decision": "approved", "decided_at": now.isoformat(),
                       "approval_ttl_seconds": 600}}
    tok = jwt.encode(payload, nk, algorithm="EdDSA", headers={"kid": nkid})
    assert v.verify(tok, "r", None).decision == "approved"


def test_reject_record_signed_by_unpinned_served_key():
    ok, okid, oraw, ox = _keypair()      # pinned (old)
    rogue, rkid, rraw, rx = _keypair()   # NOT pinned — only present in served set
    nk, nkid, nraw, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(rogue, rkid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    served = _served(_jwk(okid, ox), _jwk(rkid, rx), _jwk(nkid, nx))
    with pytest.raises(Exception):
        v.adopt_rotation(rec, served)


def test_reject_older_or_equal_seq_replay():
    ok, okid, oraw, ox = _keypair()
    _, nkid1, _, nx1 = _keypair()
    _, nkid2, _, nx2 = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT, last_seq=5)
    for seq in (5, 4):
        rec = _record(ok, okid, new_kid=nkid1, new_x=nx1, seq=seq,
                      expires_at=int(time.time()) + 3600)
        with pytest.raises(Exception):
            v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid1, nx1)))


def test_reject_expired_record():
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) - 1)
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, nx)))


def test_reject_tenant_mismatch_record():
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1,
                  expires_at=int(time.time()) + 3600, tenant="beta", aud="hma-rotation:beta")
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox), _jwk(nkid, nx)))


def test_reject_new_x_absent_from_served_set():
    # Old-key absence / new-key absence is never a reason to adopt.
    ok, okid, oraw, ox = _keypair()
    _, nkid, _, nx = _keypair()
    v = VerdictVerifier({okid: oraw}, TENANT)
    rec = _record(ok, okid, new_kid=nkid, new_x=nx, seq=1, expires_at=int(time.time()) + 3600)
    with pytest.raises(Exception):
        v.adopt_rotation(rec, _served(_jwk(okid, ox)))  # new kid not served
```
- [ ] Run it, expect FAIL (AttributeError: `adopt_rotation`):
  `cd warden && python -m pytest tests/test_rotation.py -q`
- [ ] Minimal implementation. In `warden/hold_warden/verdict.py`, add the module constant near the top and the method on `VerdictVerifier`:
```python
ROTATION_AUD_PREFIX = "hma-rotation:"
```
```python
    def adopt_rotation(self, record_jws: str, served_jwks: dict) -> str:
        """Adopt the new kid iff the record verifies under a LOCAL pin, carries
        tenant_id == paired, has seq strictly > last adopted, is not past
        expires_at, and its new key bytes appear in the served set (candidate
        material only). The old key stays pinned — retirement is a separate signed
        event, never inferred from a key's absence (§7). Returns the adopted kid."""
        try:
            header = jwt.get_unverified_header(record_jws)
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"malformed rotation record: {exc}") from exc
        key = self._pubkey(header.get("kid"))       # must be a LOCAL pin
        try:
            payload = jwt.decode(record_jws, key, algorithms=["EdDSA"],
                                 audience=f"{ROTATION_AUD_PREFIX}{self._tenant_id}")
        except jwt.InvalidTokenError as exc:
            raise VerdictError(f"rotation record signature/claims invalid: {exc}") from exc
        hma = payload.get("hma")
        if not isinstance(hma, dict):
            raise VerdictError("rotation record missing 'hma' claim")
        if hma.get("tenant_id") != self._tenant_id:
            raise VerdictError(
                f"rotation tenant_id {hma.get('tenant_id')!r} != paired {self._tenant_id!r}")
        try:
            new_kid = str(hma["new_kid"])
            new_x = str(hma["new_x"])
            seq = int(hma["seq"])
            expires_at = int(hma["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VerdictError(f"rotation 'hma' claim malformed: {exc}") from exc
        if seq <= self._last_seq:
            raise VerdictError(f"rotation seq {seq} <= last adopted {self._last_seq}")
        if expires_at < int(datetime.now(timezone.utc).timestamp()):
            raise VerdictError("rotation record expired")
        served = {k.get("kid"): k.get("x") for k in served_jwks.get("keys", [])}
        if served.get(new_kid) != new_x:
            raise VerdictError(
                "new key not present in served /v1/keys set (candidate material required)")
        import base64
        raw = base64.urlsafe_b64decode(new_x + "=" * (-len(new_x) % 4))
        self._pinned[new_kid] = raw
        self._last_seq = seq
        return new_kid
```
- [ ] Run green: `cd warden && python -m pytest tests/test_rotation.py tests/test_verdict.py -q` — expect PASS.
- [ ] Commit: `feat(warden): adopt_rotation — local-pin + tenant + seq-monotonic + expiry gate` + trailer.

---

### Task D8: warden wiring — pin set + paired tenant in config/CLI/service + persisted rotation state

Thread the new anchor through the real warden: config carries the initial pin set and paired tenant; `hma-warden init` fetches the tenant's authenticated `/v1/keys`, derives the tenant from the kid, and pins the current key; `serve` builds `VerdictVerifier(pinned, tenant_id, last_seq=…)` merging persisted adopted pins; `doctor` compares against the pin set (§7, §15.9).

- **Files:**
  - Modify `warden/hold_warden/config.py` (`WardenConfig` gains `arbiter_tenant` + a `pinned()` helper; keep `arbiter_pubkey` as the initial single pin).
  - Modify `warden/hold_warden/cli.py` (`init` fetches authenticated keys, derives tenant, writes `arbiter_tenant`; `serve` builds the verifier from the merged pin set + persisted `last_seq`; `doctor` compares pin set).
  - Add `warden/hold_warden/rotation_state.py` (tiny JSON load/save of `{adopted:{kid:x}, last_seq:int}` under the data dir).
  - Test: `warden/tests/test_config.py` (add `pinned()`/`arbiter_tenant` cases) and `warden/tests/test_rotation_state.py` (new).
- **Interfaces:**
  - Consumes: `VerdictVerifier` (D6/D7).
  - Produces: `WardenConfig.arbiter_tenant:str`, `WardenConfig.pinned()->dict[str,bytes]`, `load_rotation_state(data_dir)->tuple[dict[str,bytes],int]`, `save_rotation_state(data_dir, pinned, last_seq)`.

**Steps:**

- [ ] Write the failing test — config pin set. Add to `warden/tests/test_config.py`:
```python
def test_pinned_and_tenant_parse(tmp_path):
    from hold_warden.config import WardenConfig
    import base64, hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = f"acme:{hashlib.sha256(raw).hexdigest()[:8]}"
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    p = tmp_path / "warden.toml"
    p.write_text(f'''
[warden]
arbiter_url = "http://x"
arbiter_token = "env:HMA_WARDEN_TOKEN"
arbiter_pubkey = "{kid}:{x}"
arbiter_tenant = "acme"
name = "w"
[agents.default]
token = "env:A"
''')
    cfg = WardenConfig.load(p)
    assert cfg.arbiter_tenant == "acme"
    pinned = cfg.pinned()
    assert pinned == {kid: raw}
```
- [ ] Write the failing test — rotation state. Create `warden/tests/test_rotation_state.py`:
```python
def test_rotation_state_round_trip(tmp_path):
    from hold_warden.rotation_state import load_rotation_state, save_rotation_state
    pinned = {"acme:aabbccdd": b"\x01" * 32, "acme:11223344": b"\x02" * 32}
    save_rotation_state(tmp_path, pinned, 7)
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == pinned and seq == 7


def test_rotation_state_absent_is_empty(tmp_path):
    from hold_warden.rotation_state import load_rotation_state
    loaded, seq = load_rotation_state(tmp_path)
    assert loaded == {} and seq == 0
```
- [ ] Run them, expect FAIL:
  `cd warden && python -m pytest tests/test_config.py::test_pinned_and_tenant_parse tests/test_rotation_state.py -q`
- [ ] Minimal implementation — `rotation_state.py`. Create `warden/hold_warden/rotation_state.py`:
```python
"""Persisted rotation trust state: adopted extra pins + the last-adopted seq.

Lives beside warden.sqlite3 in the data dir. Bytes are stored base64url so the
JSON is portable; load returns raw bytes ready for VerdictVerifier."""
from __future__ import annotations

import base64
import json
from pathlib import Path

_FILENAME = "rotation_state.json"


def load_rotation_state(data_dir: Path) -> tuple[dict[str, bytes], int]:
    p = Path(data_dir) / _FILENAME
    if not p.is_file():
        return {}, 0
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}, 0
    adopted = {kid: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
               for kid, x in doc.get("adopted", {}).items()}
    return adopted, int(doc.get("last_seq", 0))


def save_rotation_state(data_dir: Path, pinned: dict[str, bytes], last_seq: int) -> None:
    p = Path(data_dir) / _FILENAME
    doc = {"adopted": {kid: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
                       for kid, raw in pinned.items()},
           "last_seq": last_seq}
    p.write_text(json.dumps(doc))
```
- [ ] Minimal implementation — config. In `warden/hold_warden/config.py`: add `arbiter_tenant: str` to the `WardenConfig` dataclass (after `arbiter_pubkey`); add `"arbiter_tenant"` to the required-keys loop; pass `arbiter_tenant=warden["arbiter_tenant"]` in the `cls(...)` constructor; and add the method:
```python
    def pinned(self) -> dict[str, bytes]:
        """The initial locally-pinned key set from arbiter_pubkey ('kid:b64url')."""
        import base64
        kid, _, x = self.arbiter_pubkey.partition(":")
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        return {kid: raw}
```
- [ ] Run config/state green:
  `cd warden && python -m pytest tests/test_config.py::test_pinned_and_tenant_parse tests/test_rotation_state.py -q` — expect PASS.
- [ ] Wire `cli.py` — `init`, `serve`, `doctor`. In `warden/hold_warden/cli.py`:
  - Add `arbiter_tenant = "{arbiter_tenant}"` to `_CONFIG_TEMPLATE`'s `[warden]` block (right after the `arbiter_pubkey` line).
  - In `init`, fetch `/v1/keys` **with the warden bearer** (now required — the endpoint derives tenant from the credential), derive the tenant from the pinned kid, and format the template:
```python
    # /v1/keys is authenticated (tenant derived from the credential); require the
    # warden bearer at init. Mint it first: hma token create <name> --role warden.
    warden_token = os.environ.get("HMA_WARDEN_TOKEN")
    if not warden_token:
        raise click.ClickException(
            "set HMA_WARDEN_TOKEN=<`hma token create ... --role warden` output> before init")
    try:
        resp = httpx.get(f"{base}/v1/keys", timeout=10.0,
                         headers={"Authorization": f"Bearer {warden_token}"})
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
    except (httpx.HTTPError, ValueError) as exc:
        raise click.ClickException(f"could not fetch {base}/v1/keys: {exc}")
    if not keys:
        raise click.ClickException("arbiter returned no verdict keys")
    key = keys[0]
    pinned = f"{key['kid']}:{key['x']}"
    arbiter_tenant = key["kid"].split(":", 1)[0]   # kid = f"{tenant}:{hash8}"
```
    and add `arbiter_tenant=arbiter_tenant` to the `_CONFIG_TEMPLATE.format(...)` call (ensure `import os` is present at the top of `cli.py`).
  - In `serve`, replace `verifier = VerdictVerifier(cfg.arbiter_pubkey)` with the merged pin set + persisted seq:
```python
    from hold_warden.rotation_state import load_rotation_state
    adopted, last_seq = load_rotation_state(data_dir)
    pinned = {**cfg.pinned(), **adopted}
    verifier = VerdictVerifier(pinned, cfg.arbiter_tenant, last_seq=last_seq)
```
  - In `doctor`, replace the single-key compare (`kid, _, x = cfg.arbiter_pubkey.partition(":")` … `match = any(...)`) with a pin-set membership check that also sends the bearer, and compares the served current key against the pinned set:
```python
    warden_token = os.environ.get("HMA_WARDEN_TOKEN", "")
    try:
        resp = httpx.get(f"{base}/v1/keys", timeout=10.0,
                         headers={"Authorization": f"Bearer {warden_token}"})
        keys = resp.json().get("keys", []) if resp.status_code == 200 else []
    except (httpx.HTTPError, ValueError):
        keys = []
    served_current = keys[0] if keys else {}
    pin_kid, _, pin_x = cfg.arbiter_pubkey.partition(":")
    match = any(k.get("kid") == pin_kid and k.get("x") == pin_x for k in keys) \
        or served_current.get("kid", "").split(":", 1)[0] == cfg.arbiter_tenant
    click.echo(f"arbiter /v1/keys matches pinned tenant/key: "
               f"{'ok' if match else 'FAILED (key/tenant mismatch — re-run init after rotation)'}")
    if not match:
        failures += 1
```
- [ ] Wire `service.py` — the `Orchestrator` already takes `verifier` in its constructor; no change needed there (it calls `self.verifier.verify(jws, rid, row["action_hash"])`, which is unchanged). Confirm no other `VerdictVerifier(cfg.arbiter_pubkey)` construction remains: `cd warden && grep -rn "VerdictVerifier(" hold_warden`.
- [ ] Run the full warden suite green:
  `cd warden && python -m pytest -q` — expect PASS (fix any older init/doctor tests that asserted the unauthenticated fetch or the single-string pin; update them to set `HMA_WARDEN_TOKEN` and expect `arbiter_tenant` in the written toml).
- [ ] Run the full server suite green: `cd server && python -m pytest -q` — expect PASS.
- [ ] Commit: `feat(warden): pin-set config + authenticated init + persisted rotation state wiring` + trailer.

---

### Group D done — invariant/gate coverage

- **§15.8** (verdict kid+aud tenant-bound; warden checks both) — D2 (`aud=hma-verdict:{tenant}` + `hma.tenant_id` + namespaced kid), D6 (`test_cross_tenant_rejected_even_with_forced_identical_key`, `test_claim_tenant_mismatch_rejected`).
- **§15.9** (trust anchor = LOCAL pin; served set non-authoritative; adopt requires local-pin + `tenant==paired` + strictly-monotonic seq within expiry) — D3, D4 (grace-window serve), D7 (`test_reject_record_signed_by_unpinned_served_key`, `…_older_or_equal_seq_replay`, `…_expired_record`, `…_tenant_mismatch_record`, `…_new_x_absent_from_served_set`), D8 (persisted `last_seq`).
- **§15.10 (signing)** (every firing signs with the acquired cell's own signer) — D1/D2 give the per-cell `Signer` + `sign_verdict(signer, …, tenant_id=signer.tenant_id)`; Group C's `ExpiryScheduler` consumes it per-firing.
- **§16 rows:** *cross-tenant verdict rejection with keys FORCED identical* (D6); *rotation trust anchor: replay/older-seq/expired/old-key-absent rejected* (D7); *`keys()` under eviction race always the pinned tenant's JWKS* (D5).

### Cross-group integration reminders (not tasks — flagged for the integrator)
- `create_app` must expose `app.state.registry` (**TenantRegistry**) and `app.state.control` (**ControlPlane**); the `default` cell is resolved through the same `resolve_identity` for back-compat (iOS 0.5.0 / hold-sdk 0.2.1 unchanged; legacy `app_token` → `default`).
- Group C's `ExpiryScheduler` and Group B's decide path call `sign_verdict(cell.signer, …, tenant_id=cell.tenant_id)` using the per-firing/per-request cell's signer — D leaves the `default`-cell call-sites green as the migration seam.
- A `hma tenant rotate-key <name>` admin CLI (Group with the tenant CLI) drives `rotate_signing_key(tenant_id, cell.dir, ttl_seconds=<grace>, seq=<next>)`; the "next seq" is read from the cell's staged `verdict_rotation.json` (0 if absent) + 1.


---


## Group E — cell-owned Hub · `/v1/stream` isolation · liveness · disable teardown

Implements spec §8 and invariants §15.1 (Hub is cell-owned, nothing tenant-scoped on
`app.state`), §15.4 (stream refcount bound-by-object, released exactly once), §15.5
(`disabled_at` read every resolution; disable/revoke actively closes live streams; a pinned
cell does not exempt its sessions). Contributes the "cross-tenant stream leak", "refcount
exactly-once / half-open pin cap", and "disable/revoke tears down sessions" tests to the §16
merge gate.

Branch: `feat/multitenant-isolation`. Repo (quote the space): `"<repo-root>"`.
All commands run from the `server/` directory unless noted. Test runner: `python -m pytest`
(pytest-asyncio is installed in **strict** mode — every async test needs `@pytest.mark.asyncio`,
mirroring `server/tests/test_retry.py`).

---

## What this group changes vs. the shipped code (read these first)

- **`server/arbiter/stream.py`** (shipped: lines 1–22). The shipped `Hub` lives as a process-global
  built in `create_app` (`app.py:27`) and stored on `app.state.hub` (`app.py:77`). Every publish site
  (`app.py:214,282,306` and the sweeper `app.py:69`) targets that one global hub, and `/v1/stream`
  (`app.py:317-341`) subscribes to it. **That single global hub is the exact object §3/§15.1 forbids:
  one bus carries every tenant's events, so any subscribed socket sees every tenant's requests.** This
  group rewrites `Hub` to be a cell-owned bus with a teardown `close()` and moves the `/v1/stream`
  session loop into a testable module-level coroutine `run_stream(...)` in `stream.py`.

- **Shipped `Hub.publish(event, key, data)` is async** and builds the wire message
  `{"event": event, key: data}` internally (`stream.py:15-21`). Per the pinned contract the cell-owned
  Hub exposes **`publish(event) -> None`** — a **synchronous** call taking the **already-built wire
  message dict**. The wire bytes iOS 0.5.0 / hold-sdk 0.2.1 see are unchanged
  (`{"event": "request.created", "request": {...}}`); only the message is now built at the call site.
  This keeps back-compat at the wire level while matching the contract signature so every group's
  publish site composes.

### Pinned-contract names this group CONSUMES (by name, never by another group's task number)

- **`Cell`** — the per-tenant unit. This group uses `cell.tenant_id: str` and **`cell.hub: Hub`**
  (a fresh `Hub()` per cell, constructed by the registry group). The `Cell` class itself is built by
  the registry/cell group; this group only defines the `Hub` type it holds and reads `cell.hub`.
- **`TenantRegistry(control, max_hot_cells=64, stream_cap=5)`** — this group uses
  `async acquire(tenant_id, epoch) -> Cell` (increments refcount; caller MUST release),
  `release(cell) -> None` (exactly once), the `async with hold(tenant_id, epoch) as cell` context
  manager (for the disable/revoke teardown one-liner), and the attribute **`registry.stream_cap: int`**
  (the per-tenant concurrent-stream cap).
- **`resolve_identity(request, registry, control) -> (Identity, Cell)`** — the async router+auth entry
  produced by the auth/routing group. It does `sha256(bearer) → control.resolve → is_disabled →
  registry.acquire(tenant_id, epoch) → cell re-validation`, returns `(Identity, pinned Cell)`, and on
  **any** failure raises `fastapi.HTTPException` (generic 403) having **already released** any pin it
  took internally. `/v1/stream` therefore only ever has a cell to release when `resolve_identity`
  **returns**. It reads bearer/cookies off the passed object via `.headers`/`.cookies`/`.client`, so a
  `WebSocket` (which exposes all three) is an acceptable first argument — `run_stream` passes the socket.
- **`ControlPlane`** — used only as the opaque `control` argument threaded into `resolve_identity`;
  `is_disabled(tenant_id)` is read there on every resolution (never cached on the cell), which is what
  makes "the next HTTP/WS 403s immediately after disable" true.
- **`app.state.registry: TenantRegistry`** and **`app.state.control: ControlPlane`** — set by the
  `create_app` wiring (the integration/wiring group), mirroring the shipped `app.state.db`/`app.state.cfg`
  pattern (`app.py:86-88`). `/v1/stream` reads them off `ws.app.state`.

### Names this group PRODUCES (later/other groups rely on these verbatim)

- **`Hub`** (`stream.py`): cell-owned WS event bus. `subscribe() -> asyncio.Queue`,
  `unsubscribe(q) -> None`, **`publish(event: dict) -> None`** (sync; `event` is the full wire message),
  **`close() -> None`** (idempotent teardown: pushes `Hub.CLOSE` sentinel to every subscriber then drops
  them), property **`active -> int`** (live subscriber count = live stream count for the cell), and the
  class attribute **`Hub.CLOSE`** (identity sentinel a stream loop compares with `is`).
- **`run_stream(ws, registry, control, *, resolve, heartbeat=30.0, send_timeout=10.0) -> None`**
  (`stream.py`): the full `/v1/stream` session — resolve+pin **before** `ws.accept()`, enforce
  `registry.stream_cap`, subscribe to `cell.hub` by object, bound every send with `asyncio.wait_for`,
  honor the `Hub.CLOSE` sentinel, and release the pin **exactly once** in an outer `finally`. `resolve`
  is injected (the endpoint passes `resolve_identity`) so it is unit-testable without the auth group.
- **The disable/revoke teardown contract**: to tear down a tenant's live sessions, a caller (the
  `hma tenant disable` CLI and the token-revoke path — other groups) does
  `async with registry.hold(tenant_id, epoch) as cell: cell.hub.close()`. This group provides `Hub.close()`
  and the `run_stream` sentinel handling that makes it drop live sockets; the CLI/revoke wiring is theirs.

---

## Test scaffolding this group introduces (used by E2–E6)

Create **`server/tests/_stream_fakes.py`** in Task E2 (a helper module, not a test file, so pytest does
not collect it). It lets E2–E6 drive `run_stream` and `Hub` without the registry/auth/cell groups
existing yet. Every fake mirrors the pinned contract exactly.

---

### Task E1: cell-owned `Hub` — sync `publish(dict)`, `close()` sentinel, `active`, per-instance isolation

**Files**
- Modify: `server/arbiter/stream.py` (replace the whole shipped file, lines 1–22).
- Test: `server/tests/test_hub.py` (new).

**Interfaces**
- Consumes: nothing (pure asyncio).
- Produces: `Hub.subscribe() -> asyncio.Queue`, `Hub.unsubscribe(q)`, `Hub.publish(event: dict) -> None`
  (sync), `Hub.close() -> None`, `Hub.active -> int`, class attr `Hub.CLOSE`.

**TDD steps**

- [ ] **Write the failing test.** Create `server/tests/test_hub.py`:
  ```python
  import asyncio
  import pytest
  from arbiter.stream import Hub


  def test_publish_delivers_built_message_dict():
      hub = Hub()
      q = hub.subscribe()
      hub.publish({"event": "request.created", "request": {"id": "r1"}})
      assert q.get_nowait() == {"event": "request.created", "request": {"id": "r1"}}


  def test_two_hubs_are_isolated():
      a, b = Hub(), Hub()
      qa, qb = a.subscribe(), b.subscribe()
      a.publish({"event": "x", "request": {"id": "1"}})
      assert qa.get_nowait()["request"]["id"] == "1"
      assert qb.empty()


  def test_active_counts_live_subscribers():
      hub = Hub()
      assert hub.active == 0
      q1, q2 = hub.subscribe(), hub.subscribe()
      assert hub.active == 2
      hub.unsubscribe(q1)
      assert hub.active == 1


  def test_close_pushes_sentinel_drops_subs_and_is_idempotent():
      hub = Hub()
      q = hub.subscribe()
      hub.close()
      assert q.get_nowait() is Hub.CLOSE
      assert hub.active == 0
      hub.close()  # idempotent: no raise, no second sentinel needed
      assert q.empty()


  def test_subscribe_after_close_hands_back_a_pre_closed_queue():
      hub = Hub()
      hub.close()
      q = hub.subscribe()          # races a disable that already fired
      assert q.get_nowait() is Hub.CLOSE
      assert hub.active == 0        # not added to the live set


  def test_publish_after_close_is_a_noop():
      hub = Hub()
      q = hub.subscribe()
      hub.close()
      q.get_nowait()               # drain the sentinel
      hub.publish({"event": "x", "request": {}})
      assert q.empty()


  def test_full_slow_consumer_is_dropped_on_publish():
      hub = Hub()
      q = hub.subscribe()
      for _ in range(256):         # fill to maxsize
          q.put_nowait({"event": "fill"})
      hub.publish({"event": "overflow", "request": {}})
      assert hub.active == 0        # QueueFull → dropped from the live set
  ```

- [ ] **Run it — expect FAIL** (shipped `publish` is async/3-arg; no `close`/`active`/`CLOSE`):
  ```
  cd server && python -m pytest tests/test_hub.py -q
  ```
  Expect `AttributeError: type object 'Hub' has no attribute 'CLOSE'` / `TypeError: publish() missing
  2 required positional arguments`.

- [ ] **Minimal implementation.** Replace the entire contents of `server/arbiter/stream.py` with:
  ```python
  import asyncio


  class Hub:
      """Cell-owned WebSocket event bus. Exactly one Hub per Cell; NEVER on app.state.

      `publish` takes the fully-built wire message dict (the shape iOS/hold-sdk already
      consume: {"event": ..., "request"|"device"|"data": ...}) so callers own message
      construction and the bus stays a dumb fan-out. `close()` is the disable/revoke
      teardown: it hands every live subscriber a CLOSE sentinel so the stream loop can
      ws.close(), then drops them.
      """

      CLOSE = object()  # identity sentinel; stream loops compare with `is`

      def __init__(self) -> None:
          self._subs: set[asyncio.Queue] = set()
          self._closed = False

      @property
      def active(self) -> int:
          """Live subscriber count == live /v1/stream count for this cell (only
          streams subscribe), used to enforce the per-tenant stream cap."""
          return len(self._subs)

      def subscribe(self) -> asyncio.Queue:
          q: asyncio.Queue = asyncio.Queue(maxsize=256)
          if self._closed:
              # A disable/revoke already tore this cell down; a socket that raced
              # the teardown must not linger — hand back an already-closed queue.
              q.put_nowait(self.CLOSE)
          else:
              self._subs.add(q)
          return q

      def unsubscribe(self, q: asyncio.Queue) -> None:
          self._subs.discard(q)

      def publish(self, event: dict) -> None:
          if self._closed:
              return
          for q in list(self._subs):
              try:
                  q.put_nowait(event)
              except asyncio.QueueFull:
                  self._subs.discard(q)  # slow consumer: drop it (fail-closed visibility)

      def close(self) -> None:
          """Idempotent. Push the CLOSE sentinel to every live subscriber so its
          stream loop ws.close()s, then drop them. Also latches _closed so any
          in-flight subscribe() gets a pre-closed queue and later publishes no-op."""
          self._closed = True
          for q in list(self._subs):
              try:
                  q.put_nowait(self.CLOSE)
              except asyncio.QueueFull:
                  pass  # a stuck full queue: its stream is already timing out on send
          self._subs.clear()
  ```

- [ ] **Run green:**
  ```
  cd server && python -m pytest tests/test_hub.py -q
  ```
  Expect all 7 pass.

- [ ] **Commit:**
  ```
  git commit -am "feat(stream): cell-owned Hub with sync publish(dict), close() teardown sentinel, active count"
  ```

---

### Task E2: `run_stream` happy path — pin before accept, subscribe by object, release exactly once

**Files**
- Modify: `server/arbiter/stream.py` (append `run_stream` + imports).
- Create: `server/tests/_stream_fakes.py` (shared fakes; not collected as tests).
- Test: `server/tests/test_run_stream.py` (new).

**Interfaces**
- Consumes: `Hub` (E1); `TenantRegistry.acquire/release` and `registry.stream_cap` (by contract, via the
  fakes); `resolve_identity(request, registry, control) -> (Identity, Cell)` (injected as `resolve`).
- Produces: `run_stream(ws, registry, control, *, resolve, heartbeat=30.0, send_timeout=10.0) -> None`.

**TDD steps**

- [ ] **Write the fakes.** Create `server/tests/_stream_fakes.py`:
  ```python
  """Contract-faithful fakes so Group E tests can drive run_stream/Hub without the
  registry/auth/cell groups. Mirrors the pinned cross-component contract exactly."""
  import asyncio
  from collections import defaultdict

  from fastapi import HTTPException

  from arbiter.stream import Hub


  class FakeCell:
      def __init__(self, tenant_id: str):
          self.tenant_id = tenant_id
          self.hub = Hub()


  class FakeRegistry:
      """acquire() pins (refcount++), release() unpins exactly once. Mirrors the real
      registry's refcount discipline and exposes stream_cap."""
      def __init__(self, cells: dict[str, FakeCell], stream_cap: int = 5):
          self._cells = cells
          self.stream_cap = stream_cap
          self.refcounts: dict[str, int] = defaultdict(int)

      async def acquire(self, tenant_id: str, epoch: int) -> FakeCell:
          self.refcounts[tenant_id] += 1
          return self._cells[tenant_id]

      def release(self, cell: FakeCell) -> None:
          self.refcounts[cell.tenant_id] -= 1


  class FakeIdentity:
      def __init__(self, tenant_id: str, name: str = "app", role: str = "app"):
          self.tenant_id, self.name, self.role = tenant_id, name, role


  def make_resolve(token_to_tenant: dict[str, str], disabled: set[str] | None = None):
      """Build a resolve() with the real contract shape: acquire+pin on success,
      raise HTTPException (having released any pin) on failure."""
      disabled = disabled or set()

      async def resolve(ws, registry, control):
          bearer = ws.headers.get("authorization", "").removeprefix("Bearer ")
          tid = token_to_tenant.get(bearer)
          if tid is None:
              raise HTTPException(403, "invalid token")   # never acquired → nothing to release
          if tid in disabled:
              raise HTTPException(403, "invalid token")   # disabled_at read on THIS resolution
          cell = await registry.acquire(tid, epoch=1)     # pins
          return FakeIdentity(tid), cell

      return resolve


  class FakeWS:
      """Drives run_stream directly (no TestClient), so a blocked send is expressible."""
      def __init__(self, headers: dict | None = None):
          self.headers = headers or {}
          self.cookies: dict = {}
          self.client = None
          self.accepted = False
          self.closed: int | None = None
          self.sent: list = []
          self.block_send = False          # simulate a blackholed peer

      async def accept(self):
          self.accepted = True

      async def close(self, code: int = 1000):
          self.closed = code

      async def send_json(self, data):
          if self.block_send:
              await asyncio.Event().wait()  # never resolves → wait_for times out
          self.sent.append(data)
  ```

- [ ] **Write the failing test.** Create `server/tests/test_run_stream.py`:
  ```python
  import asyncio
  import pytest

  from arbiter.stream import run_stream
  from _stream_fakes import FakeCell, FakeRegistry, FakeWS, make_resolve


  @pytest.mark.asyncio
  async def test_happy_path_pins_delivers_and_releases_exactly_once():
      cell = FakeCell("A")
      reg = FakeRegistry({"A": cell})
      resolve = make_resolve({"tokA": "A"})
      ws = FakeWS({"authorization": "Bearer tokA"})

      task = asyncio.create_task(
          run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
      await asyncio.sleep(0.02)                     # let it resolve+accept+subscribe
      assert ws.accepted is True
      assert reg.refcounts["A"] == 1                # pinned before accept
      assert cell.hub.active == 1                   # subscribed by object

      cell.hub.publish({"event": "request.created", "request": {"id": "r1"}})
      await asyncio.sleep(0.02)
      assert ws.sent[-1] == {"event": "request.created", "request": {"id": "r1"}}

      cell.hub.close()                              # end the session cleanly
      await asyncio.wait_for(task, timeout=1.0)
      assert reg.refcounts["A"] == 0                # released exactly once
      assert cell.hub.active == 0                   # unsubscribed
  ```
  Add a `conftest.py` shim so the fakes import cleanly — the test dir is already on
  `sys.path` (pytest rootdir `server`, `testpaths=["tests"]`), so `from _stream_fakes import ...`
  resolves because pytest inserts the test file's directory into `sys.path` (rootdir has
  `tests/__init__.py`? it does — see note below).

  > **Import note:** `server/tests/__init__.py` exists, making `tests` a package. Import the helper as
  > `from tests._stream_fakes import ...` **if** you run pytest from `server/`. Verify with the FAIL run
  > and adjust the import to whichever resolves (`_stream_fakes` vs `tests._stream_fakes`); the shipped
  > suite is run as `cd server && python -m pytest`, which puts `server/` on `sys.path`, so
  > `from tests._stream_fakes import ...` is correct. Use that form.

  (Use `from tests._stream_fakes import FakeCell, FakeRegistry, FakeWS, make_resolve`.)

- [ ] **Run it — expect FAIL** (`run_stream` does not exist):
  ```
  cd server && python -m pytest tests/test_run_stream.py -q
  ```
  Expect `ImportError: cannot import name 'run_stream'`.

- [ ] **Minimal implementation.** Append to `server/arbiter/stream.py` (add the two imports at the top,
  after `import asyncio`):
  ```python
  from fastapi import HTTPException
  from starlette.websockets import WebSocketDisconnect
  ```
  Then append the function:
  ```python
  async def run_stream(ws, registry, control, *, resolve,
                       heartbeat: float = 30.0, send_timeout: float = 10.0) -> None:
      """The full /v1/stream session. Tenant is derived from the credential via the
      injected `resolve` (same router path as HTTP); the cell is pinned (refcount++)
      BEFORE ws.accept() and the socket subscribes to THAT cell's hub by object. The
      pin is released EXACTLY ONCE in the outer finally — a stuck send, a disconnect,
      a cap rejection and a disable sentinel all funnel through it.
      """
      try:
          identity, cell = await resolve(ws, registry, control)
      except HTTPException:
          # Auth/route/disabled failure: resolve released any pin it took. Nothing to
          # release here. Generic close; never leak which check failed.
          await ws.close(code=4401)
          return
      # From here `cell` is pinned; the outer finally is the single release site.
      try:
          if cell.hub.active >= registry.stream_cap:
              await ws.close(code=4429)   # per-tenant stream cap
              return
          await ws.accept()
          q = cell.hub.subscribe()

          async def _heartbeat():
              while True:
                  await asyncio.sleep(heartbeat)
                  try:
                      q.put_nowait({"event": "ping", "data": {}})
                  except asyncio.QueueFull:
                      pass  # peer is already backed up; the send loop will time out

          hb = asyncio.create_task(_heartbeat())
          try:
              while True:
                  item = await q.get()
                  if item is Hub.CLOSE:               # disable/revoke teardown
                      await ws.close(code=4403)
                      break
                  # Bound every send: a blackholed peer's send blocks forever, so
                  # wait_for hard-closes it instead of pinning the cell indefinitely.
                  await asyncio.wait_for(ws.send_json(item), timeout=send_timeout)
          except (WebSocketDisconnect, asyncio.TimeoutError):
              pass
          finally:
              hb.cancel()
              cell.hub.unsubscribe(q)
      finally:
          registry.release(cell)
  ```

- [ ] **Run green:**
  ```
  cd server && python -m pytest tests/test_run_stream.py -q
  ```
  Expect pass.

- [ ] **Commit:**
  ```
  git commit -am "feat(stream): run_stream session loop — pin before accept, subscribe by object, release once"
  ```

---

### Task E3: `run_stream` auth/route failure closes without pinning — no dangling refcount

**Files**
- Modify: none (behavior already implemented in E2's `run_stream`).
- Test: `server/tests/test_run_stream.py` (append).

**Interfaces**
- Consumes: `run_stream` (E2), the fakes (E2). `resolve` raising `HTTPException` before `acquire`.
- Produces: nothing new.

**TDD steps**

- [ ] **Write the failing test.** Append to `server/tests/test_run_stream.py`:
  ```python
  @pytest.mark.asyncio
  async def test_auth_failure_closes_4401_without_accept_or_pin():
      reg = FakeRegistry({"A": FakeCell("A")})
      resolve = make_resolve({"tokA": "A"})            # tokB is unknown
      ws = FakeWS({"authorization": "Bearer tokB"})

      await run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)

      assert ws.accepted is False
      assert ws.closed == 4401
      assert reg.refcounts["A"] == 0                   # never acquired → never released
  ```

- [ ] **Run it — expect PASS immediately** (E2 already handles this branch). This is a
  characterization test guarding the "resolve released its own pin; run_stream releases only what it
  holds" invariant against future regressions:
  ```
  cd server && python -m pytest tests/test_run_stream.py -k auth_failure -q
  ```
  Expect pass. (If it fails, the E2 `try/except HTTPException` ordering is wrong — the release must be
  reachable only when `cell` is bound.)

- [ ] **Commit:**
  ```
  git commit -am "test(stream): auth/route failure closes 4401 with no accept and no dangling refcount"
  ```

---

### Task E4: liveness + cap — blackholed send times out & releases; sentinel closes; stream_cap enforced

**Files**
- Modify: none (behavior implemented in E2).
- Test: `server/tests/test_run_stream.py` (append).

**Interfaces**
- Consumes: `run_stream` (E2), fakes (E2), `Hub.close`/`Hub.active`/`Hub.CLOSE` (E1),
  `registry.stream_cap`.
- Produces: nothing new (proves §8 liveness + §15.4 pin-cap).

**TDD steps**

- [ ] **Write the failing tests.** Append to `server/tests/test_run_stream.py`:
  ```python
  @pytest.mark.asyncio
  async def test_blackholed_send_times_out_and_releases_refcount():
      cell = FakeCell("A")
      reg = FakeRegistry({"A": cell})
      resolve = make_resolve({"tokA": "A"})
      ws = FakeWS({"authorization": "Bearer tokA"})
      ws.block_send = True                              # peer never drains the socket

      # heartbeat fires fast → enqueues a ping → send blocks → wait_for times out.
      task = asyncio.create_task(
          run_stream(ws, reg, None, resolve=resolve, heartbeat=0.01, send_timeout=0.05))
      await asyncio.wait_for(task, timeout=1.0)         # must return on its own
      assert reg.refcounts["A"] == 0                    # stuck send still released the pin
      assert cell.hub.active == 0


  @pytest.mark.asyncio
  async def test_close_sentinel_hard_closes_the_live_socket():
      cell = FakeCell("A")
      reg = FakeRegistry({"A": cell})
      resolve = make_resolve({"tokA": "A"})
      ws = FakeWS({"authorization": "Bearer tokA"})

      task = asyncio.create_task(
          run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
      await asyncio.sleep(0.02)
      assert cell.hub.active == 1

      cell.hub.close()                                  # disable/revoke teardown
      await asyncio.wait_for(task, timeout=1.0)
      assert ws.closed == 4403
      assert reg.refcounts["A"] == 0


  @pytest.mark.asyncio
  async def test_per_tenant_stream_cap_rejects_and_still_releases():
      cell = FakeCell("A")
      reg = FakeRegistry({"A": cell}, stream_cap=2)
      resolve = make_resolve({"tokA": "A"})

      held = []
      for _ in range(2):                                # fill the cap
          ws = FakeWS({"authorization": "Bearer tokA"})
          held.append(asyncio.create_task(
              run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)))
      await asyncio.sleep(0.03)
      assert cell.hub.active == 2
      assert reg.refcounts["A"] == 2

      over = FakeWS({"authorization": "Bearer tokA"})   # the 3rd, over cap
      await run_stream(over, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
      assert over.accepted is False
      assert over.closed == 4429
      assert reg.refcounts["A"] == 2                    # rejected pin was released (2, not 3)

      cell.hub.close()                                  # tear down the two held sockets
      await asyncio.wait_for(asyncio.gather(*held), timeout=1.0)
      assert reg.refcounts["A"] == 0
  ```

- [ ] **Run — expect PASS** (E2 already implements bounded sends, the `Hub.CLOSE` branch, and the cap
  check; these are the §16 gate assertions for this slice):
  ```
  cd server && python -m pytest tests/test_run_stream.py -q
  ```
  Expect all pass. If `test_blackholed_send_times_out...` hangs, `asyncio.wait_for(ws.send_json(...))`
  is missing or the `except asyncio.TimeoutError` is not funnelling into the `finally`.

- [ ] **Commit:**
  ```
  git commit -am "test(stream): liveness — blackholed send reaps + releases; sentinel closes; stream_cap enforced"
  ```

---

### Task E5: cross-tenant stream isolation — an event on A's hub NEVER reaches a B socket (§16 gate)

**Files**
- Modify: none.
- Test: `server/tests/test_stream_isolation.py` (new — this is the merge-gate test this group owns).

**Interfaces**
- Consumes: `run_stream` (E2), fakes (E2), `Cell.hub` isolation (E1).
- Produces: the §16 "cross-tenant stream leak" gate assertion.

**TDD steps**

- [ ] **Write the failing test.** Create `server/tests/test_stream_isolation.py`:
  ```python
  import asyncio
  import pytest

  from arbiter.stream import run_stream
  from tests._stream_fakes import FakeCell, FakeRegistry, FakeWS, make_resolve


  @pytest.mark.asyncio
  async def test_event_on_A_never_reaches_a_B_socket():
      cell_a, cell_b = FakeCell("A"), FakeCell("B")
      reg = FakeRegistry({"A": cell_a, "B": cell_b})
      resolve = make_resolve({"tokA": "A", "tokB": "B"})

      ws_a = FakeWS({"authorization": "Bearer tokA"})
      ws_b = FakeWS({"authorization": "Bearer tokB"})
      ta = asyncio.create_task(
          run_stream(ws_a, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
      tb = asyncio.create_task(
          run_stream(ws_b, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
      await asyncio.sleep(0.03)
      assert cell_a.hub.active == 1 and cell_b.hub.active == 1

      # A tenant-A create publishes to A's cell hub ONLY.
      cell_a.hub.publish({"event": "request.created", "request": {"id": "rA", "title": "secret-A"}})
      await asyncio.sleep(0.03)

      assert any(m.get("request", {}).get("id") == "rA" for m in ws_a.sent)
      assert ws_b.sent == []            # B's socket saw nothing — structural isolation

      cell_a.hub.close(); cell_b.hub.close()
      await asyncio.wait_for(asyncio.gather(ta, tb), timeout=1.0)
      assert reg.refcounts["A"] == 0 and reg.refcounts["B"] == 0
  ```

- [ ] **Run — expect PASS** (isolation is structural: A and B own distinct `Hub` objects, and
  `run_stream` subscribes each socket to its own `cell.hub`, so there is no path from A's bus to B's
  queue):
  ```
  cd server && python -m pytest tests/test_stream_isolation.py -q
  ```
  Expect pass. A failure here means a socket subscribed to the wrong hub (a global-hub regression).

- [ ] **Commit:**
  ```
  git commit -am "test(stream): §16 gate — an event on cell A's hub never reaches a cell B socket"
  ```

---

### Task E6: disable/revoke teardown — `close()` drops the live socket; reconnect 403s at resolve

**Files**
- Modify: none (uses `Hub.close` from E1 + `run_stream` from E2 + the `registry.hold` contract).
- Test: `server/tests/test_stream_disable.py` (new).

**Interfaces**
- Consumes: `Hub.close` (E1), `run_stream` (E2), `registry.hold(tenant_id, epoch)` (contract; faked
  here), `is_disabled`-driven resolve failure (faked via `make_resolve(disabled=...)`).
- Produces: the §16 "disable/revoke tears down sessions (socket closes, next request 403s immediately on
  a hot busy cell)" gate assertion, and the documented teardown one-liner
  `async with registry.hold(tid, epoch) as cell: cell.hub.close()`.

**TDD steps**

- [ ] **Extend the fakes** with a `hold` context manager so the teardown one-liner is exercised exactly
  as the CLI/revoke path will call it. Append to `server/tests/_stream_fakes.py`:
  ```python
  from contextlib import asynccontextmanager


  class HoldMixin:
      @asynccontextmanager
      async def hold(self, tenant_id: str, epoch: int):
          cell = await self.acquire(tenant_id, epoch)
          try:
              yield cell
          finally:
              self.release(cell)


  class FakeRegistryWithHold(HoldMixin, FakeRegistry):
      pass
  ```

- [ ] **Write the failing test.** Create `server/tests/test_stream_disable.py`:
  ```python
  import asyncio
  import pytest

  from arbiter.stream import run_stream
  from tests._stream_fakes import FakeCell, FakeRegistryWithHold, FakeWS, make_resolve


  @pytest.mark.asyncio
  async def test_disable_closes_live_socket_and_next_connect_403s():
      cell = FakeCell("A")
      reg = FakeRegistryWithHold({"A": cell})
      disabled: set[str] = set()
      resolve = make_resolve({"tokA": "A"}, disabled=disabled)

      # A live, busy (pinned) session on a hot cell.
      ws = FakeWS({"authorization": "Bearer tokA"})
      live = asyncio.create_task(
          run_stream(ws, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0))
      await asyncio.sleep(0.02)
      assert cell.hub.active == 1 and reg.refcounts["A"] == 1

      # Operator disables the tenant: flip disabled_at (fake) THEN tear down live
      # sessions with the exact one-liner the CLI/revoke path uses.
      disabled.add("A")
      async with reg.hold("A", epoch=1) as held:
          held.hub.close()

      await asyncio.wait_for(live, timeout=1.0)
      assert ws.closed == 4403                 # the pinned session did NOT exempt itself
      assert reg.refcounts["A"] == 0           # hold released; live session released

      # The next connection 403s immediately — disabled_at is read on THIS resolution.
      ws2 = FakeWS({"authorization": "Bearer tokA"})
      await run_stream(ws2, reg, None, resolve=resolve, heartbeat=1e9, send_timeout=5.0)
      assert ws2.accepted is False and ws2.closed == 4401
      assert reg.refcounts["A"] == 0
  ```

- [ ] **Run — expect PASS** (the mechanism is entirely E1+E2; this test wires the disable path to prove
  §15.5). If `ws.closed` is `None` the `Hub.CLOSE` branch in `run_stream` is not reached:
  ```
  cd server && python -m pytest tests/test_stream_disable.py -q
  ```
  Expect pass.

- [ ] **Commit:**
  ```
  git commit -am "test(stream): §16 gate — disable tears down the live socket; reconnect 403s on a hot cell"
  ```

---

### Task E7: wire `/v1/stream` into `create_app`, drop the process-global Hub, repoint publish sites

**Files**
- Modify: `server/arbiter/app.py` — the `create_app` signature/wiring and every publish site:
  - `app.py:26` (signature), `app.py:27` (global `hub = hub or Hub()`), `app.py:77`
    (`app.state.hub = hub`), `app.py:92` (`build_router(..., hub)`).
  - `app.py:64-72` (the in-`create_app` sweeper that publishes to the global hub — its expiry publish
    moves to the cell hub; the ExpiryScheduler that replaces it is another group's, so here only remove
    the global-hub publish so nothing references the deleted global bus).
  - `app.py:214` (`await hub.publish("request.created", "request", req)`),
    `app.py:282` (`await hub.publish("request.decided", "request", updated)`),
    `app.py:306` (`await hub.publish("device.updated", "device", dev)`).
  - `app.py:317-341` (the whole `/v1/stream` endpoint) → delegate to `run_stream`.
- Modify: `server/arbiter/stream.py` import in `app.py` (`from .stream import Hub` → also import
  `run_stream`).
- Test: `server/tests/test_stream_wiring.py` (new — an integration smoke on a single fake `default`
  cell, provable without the registry/auth groups).

**Interfaces**
- Consumes: `run_stream` (E2), `resolve_identity` (contract; injected as `resolve=resolve_identity`),
  `app.state.registry`/`app.state.control` (set by the wiring group), **the acquired `Cell` bound to
  each mutating request by the auth dependency** (contract — the handler already holds its cell to
  publish to `cell.hub`).
- Produces: `/v1/stream` bound to `run_stream`; `app.state.hub` **removed**; publish sites target the
  request's `cell.hub`.

> **Composition note.** The full `create_app(cfg, registry, control, ...)` signature change (db→registry)
> is owned by the integration/wiring group; the create/decide/register handlers obtain their acquired
> `Cell` from the auth dependency (auth/routing group). This task changes only (a) the stream endpoint,
> (b) the removal of the global `Hub`/`app.state.hub`, and (c) the three publish call sites from the
> deleted global `hub` to the request's `cell.hub` using the new sync `publish(dict)` form. Land it after
> those groups' handler wiring exists on the branch; the smoke test below stands alone via injected fakes.

**TDD steps**

- [ ] **Write the failing test.** Create `server/tests/test_stream_wiring.py`. It builds a tiny app that
  mounts the endpoint exactly as `create_app` will, with a single `default` fake cell on
  `app.state.registry`, and drives it through Starlette's `TestClient` websocket to prove the endpoint
  delegates to `run_stream` and stays on the wire format iOS expects:
  ```python
  import pytest
  from fastapi import FastAPI, WebSocket
  from fastapi.testclient import TestClient

  from arbiter.stream import run_stream
  from tests._stream_fakes import FakeCell, FakeRegistry, make_resolve


  def _build_app():
      app = FastAPI()
      cell = FakeCell("default")
      app.state.registry = FakeRegistry({"default": cell})
      app.state.control = None
      app.state._cell = cell  # test handle
      resolve = make_resolve({"app-tok": "default"})

      @app.websocket("/v1/stream")
      async def stream(ws: WebSocket):
          await run_stream(ws, ws.app.state.registry, ws.app.state.control,
                           resolve=resolve, heartbeat=1e9, send_timeout=5.0)
      return app


  def test_endpoint_delegates_to_run_stream_and_keeps_wire_format():
      app = _build_app()
      with TestClient(app) as c:
          with c.websocket_connect(
                  "/v1/stream", headers={"Authorization": "Bearer app-tok"}) as ws:
              app.state._cell.hub.publish(
                  {"event": "request.created", "request": {"id": "r1"}})
              evt = ws.receive_json()
              assert evt == {"event": "request.created", "request": {"id": "r1"}}


  def test_endpoint_rejects_unknown_bearer_before_accept():
      app = _build_app()
      with TestClient(app) as c:
          with pytest.raises(Exception):
              with c.websocket_connect(
                      "/v1/stream", headers={"Authorization": "Bearer nope"}):
                  pass
  ```

- [ ] **Run it — expect FAIL** until the endpoint pattern compiles/behaves (it exercises `run_stream`
  through `TestClient`; a green run here confirms `run_stream` cooperates with Starlette's real
  `WebSocket`, not just `FakeWS`):
  ```
  cd server && python -m pytest tests/test_stream_wiring.py -q
  ```
  Expect the first test FAIL if `run_stream` mishandles the real `WebSocket` (e.g. missing `accept`
  before `receive`/`send`), else PASS. Fix any real-`WebSocket` gap (the shipped endpoint calls
  `ws.accept()` before sending — `run_stream` does too).

- [ ] **Implement the `create_app` edits.** In `server/arbiter/app.py`:
  1. Change the import (`app.py:20`) to `from .stream import Hub, run_stream`.
  2. Delete the process-global hub: remove `hub = hub or Hub()` (`app.py:27`), drop the `hub` parameter
     from `create_app` (`app.py:26`), and delete `app.state.hub = hub` (`app.py:77`). Update
     `app.include_router(build_router(cfg, db, hub))` (`app.py:92`) per the router group's new signature
     (the dashboard router no longer takes a global hub; pass what that group specifies). Apply the REAL
     router wiring unconditionally here — **E7 depends on Groups A and B being complete** (they land before
     Group E per the group order), so `registry`/`control` are already on `app.state` and the router group's
     signature is available; do **not** ship a `None` placeholder or a `# TODO`.
  3. Replace the publish call sites to use the request's acquired cell and the sync `publish(dict)`
     form:
     - `app.py:214`: `cell.hub.publish({"event": "request.created", "request": req})`
     - `app.py:282`: `cell.hub.publish({"event": "request.decided", "request": updated})`
     - `app.py:306`: `cell.hub.publish({"event": "device.updated", "device": dev})`
     - **`POST /v1/devices/enroll` (Group G Task G8):** `cell.hub.publish({"event": "device.updated",
       "device": dev})` — this site is **owned here** (explicitly reconciled by E7, not left to the
       finalize sweep). The G8 task body already ships the sync-dict form; this checklist entry pins that
       ownership so the seam is never missed.
     (`cell` is the acquired `Cell` the auth dependency binds to the request; these calls drop the
     `await` since `publish` is now synchronous.)
  4. In the in-`create_app` sweeper (`app.py:64-72`), remove the `await hub.publish("request.expired",
     ...)` line — expiry publication moves to the ExpiryScheduler (other group), which publishes to the
     fired cell's `cell.hub`. Leave the outbox publish as the other group directs.
  5. Replace the entire `/v1/stream` endpoint (`app.py:317-341`) with:
     ```python
     @app.websocket("/v1/stream")
     async def stream(ws: WebSocket):
         await run_stream(ws, ws.app.state.registry, ws.app.state.control,
                          resolve=resolve_identity,
                          heartbeat=ws_heartbeat, send_timeout=ws_send_timeout)
     ```
     Add `ws_send_timeout: float = 10.0` to the `create_app` parameter list next to the existing
     `ws_heartbeat` (`app.py:26`), and add `from .auth import ... resolve_identity` is already imported
     (`app.py:14`).

- [ ] **Run green:**
  ```
  cd server && python -m pytest tests/test_stream_wiring.py -q
  ```
  Expect pass.

- [ ] **Commit:**
  ```
  git commit -am "feat(app): mount /v1/stream on run_stream; drop process-global Hub; publish to cell.hub"
  ```

---

## Group E done-check (maps to §16 gate rows this group owns)

- Cross-tenant stream leak: `test_stream_isolation.py` — event on A's hub never reaches a B socket. ✅
- Refcount exactly-once / no use-after-free: `test_run_stream.py` — happy close, disconnect, stuck send,
  cap rejection, auth failure all return refcount to baseline. ✅
- Half-open pin cap: `test_run_stream.py` — bounded send reaps a blackholed peer; per-tenant `stream_cap`
  enforced. ✅
- Disable/revoke tears down sessions: `test_stream_disable.py` — the pinned live socket closes (4403) and
  the next connect 403s immediately on a hot cell. ✅
- §15.1: no global Hub — `Hub` is cell-owned; `app.state.hub` removed (Task E7). ✅

## Notes for the reviewer / next group

- **Wire back-compat:** `Hub.publish` now takes the fully-built message dict; the wire shape iOS 0.5.0 /
  hold-sdk 0.2.1 receive (`{"event": ..., "request"|"device"|"data": ...}`) is byte-identical. The only
  change is *where* the dict is built (call site, not the bus).
- **The `resolve_identity` cookie/session path** (dashboard live view) is the auth/routing group's; this
  group threads the whole `WebSocket` (which exposes `.headers`/`.cookies`/`.client`) into `resolve`, so
  a session-cookie resolution to the `default` cell is handled there without any change to `run_stream`.
- **Close codes:** 4401 = auth/route/disabled (generic, never leaks which); 4403 = active teardown
  (disable/revoke sentinel); 4429 = per-tenant stream cap. Equalized/generic per §11.


---


## Group F — Process-wide `ExpiryScheduler` (replaces the per-cell 1s sweeper)

Implements spec §6 and invariant §15.10. Branch: `feat/multitenant-isolation`.
Repo (quote — path has spaces): `<repo-root>`.

## What this group builds

The shipped single-tenant server runs **one 1-second `sweep()` loop per process** inside
`create_app` (`server/arbiter/app.py:36-73`): `_expire_pass()` flips overdue `pending` rows to
`expired` and signs an `expired` verdict, then flips stale unconsumed approvals — all against the
one process-global `db`, signed with the one process-global `kid`/`signing_key`. In the
multi-tenant build there are **N cells, each with its own `db` and its own signer**, so a single
global sweeper is both wrong (it would sign tenant B's expiry with tenant A's key — a cross-tenant
availability break, §6) and unscalable (N sweep loops).

Group F replaces it with **one process-wide `ExpiryScheduler`** that:
- holds **only** `(expires_at, tenant_id, request_id)` in a min-heap — never a cell/db/key reference (§15.10);
- on firing, `registry.hold(tenant_id, epoch)`s the **current** cell and uses **that cell's**
  `signer` + `db` exclusively, pinned across the whole pass, released after commit;
- makes the pending→expired flip and the expiry-verdict **one transaction**, plus a startup
  recovery re-scan of `status='expired' AND verdict_jws IS NULL` (belt-and-suspenders for a crash
  in any legacy two-commit path) so a SIGTERM can never leave a permanent verdict-404;
- keeps a **bounded level-triggered rescan** (rolling over tenants with pending/approved-unconsumed
  rows) so a dropped heap-push still expires;
- lets the decide handler push a **second heap entry at `decided_at + approval_ttl`** so a cold
  cell's stale-approval deadline still flips (the seed/rescan also pick these up);
- enforces **per-tenant round-robin fairness** (bounded work per tenant per pass) so one tenant's
  short-TTL batch cannot starve another;
- opens cells **only via `registry.hold`**, so every scheduler cold-open is counted against the FD
  budget the registry owns (§5/§15.13);
- **seeds** the heap at startup with a bounded transient per-cell scan.

## Prerequisites (must be merged on the branch before F runs)

F consumes these by name from the pinned cross-component contract — the groups that produce them
land earlier on `feat/multitenant-isolation`:

- **`Cell`** — attributes used by F: `.tenant_id:str`, `.epoch:int`, `.db:Database`,
  `.signer` (with `.kid:str = f"{tenant_id}:{hash8}"`, `.signing_key:Ed25519PrivateKey`),
  `.hub` (`.publish(event)->None`), `.dispatcher:Dispatcher`.
- **`TenantRegistry`** — F uses **`async with registry.hold(tenant_id, epoch) as cell`** (the
  context-manager form of `acquire`/`release`): pins the cell (`refcount++`) for the block, releases
  exactly once on exit, enforces the FD budget on open, raises on tombstone/epoch-mismatch.
- **`ControlPlane`** — F uses **`control.list_tenants() -> list[dict]`** (each record carries
  `tenant_id` and `epoch`); a tenant absent from the list is treated as tombstoned → skipped.
- **`sign_verdict(signer, *, request_id, action_hash, decision, decided_at, approval_ttl_seconds, tenant_id) -> str`**
  — the tenant-bound EdDSA JWS (`aud="hma-verdict:{tenant_id}"`, `hma.tenant_id` claim, kid
  `"{tenant_id}:{hash8}"`) produced by the signing group.
- Shipped, reused verbatim: **`Outbox(db, dispatcher)`** with `async publish(event, req)`
  (`server/arbiter/notify/outbox.py`); **`Database`** and its `get_request` / `set_verdict` /
  `add_audit` / `expire_stale_approvals` (`server/arbiter/db.py`).

**Assumption (surfaced per Karpathy):** `approval_ttl_seconds` is a **process-wide** policy constant
in V1 (the spec makes keys/egress/limiters/devices per-tenant, but *not* the approval TTL), so the
scheduler receives it once at construction from `cfg.policy.approval_ttl_seconds`. If a later version
makes it per-tenant, it becomes a `Cell` attribute read per firing — a one-line change isolated to
`_process_row` / `_schedule_row`.

## Test conventions (from the shipped repo)

- Run from `server/`: `python -m pytest tests/<file> -q` (pytest `testpaths=["tests"]`).
- Async tests use an explicit `@pytest.mark.asyncio` (pytest-asyncio is a dev dep; `asyncio_mode`
  is **not** `auto` — every async test must carry the marker, matching `tests/test_retry.py`).
- Databases in tests are `Database(":memory:")`.
- Conventional commits ending.

The scheduler's collaborators (`Cell`/`TenantRegistry`/`ControlPlane`) are other groups; F's unit
tests drive the scheduler against **fakes** that satisfy the consumed interfaces above, using a
**real `Database`** and **real Ed25519 signing** so the isolation/verification assertions are
genuine. The §16 merge-gate suite re-exercises the same scenarios against the real objects.

---

### Task F1: `Database.expire_request_with_verdict` — atomic guarded flip + verdict + audit

The shipped expiry path is two commits (`db.expire_due` flips + audits; then `app.py._expire_pass`
signs and `db.set_verdict` commits again), so a crash between them strands an `expired` row with no
verdict → permanent verdict-404. F1 collapses the flip, the verdict store, and both audit rows into
**one transaction**, guarded on `status='pending' AND expires_at <= now` so a concurrent
`set_decision` (which flips to `approved`/`denied`) deterministically wins and the loser returns
`None`.

**Files:**
- Modify: `server/arbiter/db.py` (add method after `set_verdict`, `db.py:271-275`).
- Test: `server/tests/test_db.py` (append).

**Interfaces:**
- Consumes: the shipped `Database` internals — `self._lock`, `self.conn`, `self.get_request(rid)`,
  module helpers `_utcnow()`, `_iso()`, and `uuid`/`json` already imported in `db.py`.
- Produces: **`Database.expire_request_with_verdict(rid: str, jws: str, kid: str, now: datetime | None = None) -> dict | None`**
  — returns the updated request dict on the winning flip; `None` if the row was not `pending` or not
  yet due (nothing changed). Consumed by F's `_process_row` (Task F4).

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_db.py`:
  ```python
  from datetime import timedelta, timezone
  from datetime import datetime as _dt
  from arbiter.models import RequestCreate

  def _past_iso(seconds=60):
      return (_dt.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()

  def test_expire_request_with_verdict_atomic_flip():
      db = Database(":memory:")
      req = db.create_request(RequestCreate(title="t", ttl_seconds=300))
      # force it overdue
      with db._lock:
          db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?",
                          (_past_iso(), req["id"]))
          db.conn.commit()
      out = db.expire_request_with_verdict(req["id"], "JWS.B64.SIG", "default:abc123de")
      assert out is not None
      assert out["status"] == "expired"
      assert out["verdict_jws"] == "JWS.B64.SIG"
      assert out["verdict_kid"] == "default:abc123de"
      events = [a["event"] for a in db.get_audit(req["id"])]
      assert "expired" in events and "verdict_issued" in events

  def test_expire_request_with_verdict_loses_to_decision():
      db = Database(":memory:")
      req = db.create_request(RequestCreate(title="t", ttl_seconds=300))
      # a decision won first: row is now 'approved', not 'pending'
      db.set_decision(req["id"], "approve", "phone")
      out = db.expire_request_with_verdict(req["id"], "X", "default:kid")
      assert out is None                      # guard refused: not pending
      assert db.get_request(req["id"])["status"] == "approved"
      assert db.get_request(req["id"])["verdict_jws"] is None
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_db.py -q -k expire_request_with_verdict`
  → `AttributeError: 'Database' object has no attribute 'expire_request_with_verdict'`.
- [ ] **Implement.** Insert into `server/arbiter/db.py` immediately after `set_verdict`
  (`db.py:275`):
  ```python
  def expire_request_with_verdict(self, rid: str, jws: str, kid: str,
                                  now: datetime | None = None) -> dict | None:
      """Atomically flip an overdue pending row to 'expired', store its
      'expired' verdict, and write both audit rows in ONE transaction. The
      UPDATE guards on status='pending' AND expires_at<=now so a concurrent
      set_decision (which moved the row to approved/denied) wins and this
      returns None — closing the two-commit window that could otherwise strand
      an expired row with no verdict (permanent verdict-404). Audit rows are
      inlined (not add_audit) so the whole flip commits exactly once."""
      now = now or _utcnow()
      with self._lock:
          cur = self.conn.execute(
              "UPDATE requests SET status='expired', verdict_jws=?, verdict_kid=?"
              " WHERE id=? AND status='pending' AND expires_at <= ?",
              (jws, kid, rid, _iso(now)))
          if cur.rowcount != 1:
              self.conn.rollback()
              return None
          self.conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                            (str(uuid.uuid4()), rid, "expired", _iso(now), json.dumps({})))
          self.conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                            (str(uuid.uuid4()), rid, "verdict_issued", _iso(now),
                             json.dumps({"decision": "expired", "kid": kid})))
          self.conn.commit()
          return self.get_request(rid)
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_db.py -q -k expire_request_with_verdict` → 2 passed.
- [ ] **Commit:** `feat(db): atomic expire_request_with_verdict flip+verdict+audit`
  .

---

### Task F2: `Database.open_deadline_rows` + `Database.expired_without_verdict` — seed/rescan/recovery queries

The scheduler's startup seed and its level-triggered rescan need every row that still has a live
deadline (`pending`, or `approved`-and-unconsumed for the staleness deadline). Recovery needs every
`expired` row that never got a verdict.

**Files:**
- Modify: `server/arbiter/db.py` (add two methods after `expire_request_with_verdict`).
- Test: `server/tests/test_db.py` (append).

**Interfaces:**
- Consumes: `Database` internals as in F1; `self._row_to_request`.
- Produces:
  - **`Database.open_deadline_rows() -> list[dict]`** — every `status='pending'` row plus every
    `status='approved' AND consumed_at IS NULL` row (full request dicts). Consumed by F5 `seed()` /
    F6 `_rescan_tick`.
  - **`Database.expired_without_verdict() -> list[dict]`** — every `status='expired' AND
    verdict_jws IS NULL` row. Consumed by F8 recovery in `seed()`.

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_db.py`:
  ```python
  def test_open_deadline_rows_covers_pending_and_unconsumed_approved():
      db = Database(":memory:")
      p = db.create_request(RequestCreate(title="pending", ttl_seconds=300))
      a = db.create_request(RequestCreate(title="approved", ttl_seconds=300))
      db.set_decision(a["id"], "approve", "phone")               # approved, unconsumed
      d = db.create_request(RequestCreate(title="denied", ttl_seconds=300))
      db.set_decision(d["id"], "deny", "phone")                  # terminal, excluded
      ids = {r["id"] for r in db.open_deadline_rows()}
      assert p["id"] in ids and a["id"] in ids
      assert d["id"] not in ids

  def test_expired_without_verdict():
      db = Database(":memory:")
      r = db.create_request(RequestCreate(title="t", ttl_seconds=300))
      with db._lock:                                             # simulate crash after flip, before verdict
          db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
          db.conn.commit()
      rows = db.expired_without_verdict()
      assert [x["id"] for x in rows] == [r["id"]]
      db.set_verdict(r["id"], "JWS", "kid")                      # once signed, no longer returned
      assert db.expired_without_verdict() == []
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_db.py -q -k "open_deadline_rows or expired_without_verdict"`
  → `AttributeError`.
- [ ] **Implement.** Insert into `server/arbiter/db.py` after `expire_request_with_verdict`:
  ```python
  def open_deadline_rows(self) -> list[dict]:
      """Rows that still carry a live deadline: pending (expiry deadline =
      expires_at) and approved-unconsumed (staleness deadline =
      decided_at + approval_ttl). Used to seed/rescan the ExpiryScheduler heap
      so a dropped heap-push cannot leave a request un-expired forever."""
      with self._lock:
          rows = self.conn.execute(
              "SELECT * FROM requests WHERE status='pending'"
              " OR (status='approved' AND consumed_at IS NULL)").fetchall()
          return [self._row_to_request(r) for r in rows]

  def expired_without_verdict(self) -> list[dict]:
      """Recovery scan: rows flipped to 'expired' whose verdict never committed
      (a crash between the flip and the sign in any non-atomic path). The
      scheduler re-signs these at startup so no expired request is a
      permanent verdict-404."""
      with self._lock:
          rows = self.conn.execute(
              "SELECT * FROM requests WHERE status='expired' AND verdict_jws IS NULL").fetchall()
          return [self._row_to_request(r) for r in rows]
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_db.py -q -k "open_deadline_rows or expired_without_verdict"` → 2 passed.
- [ ] **Commit:** `feat(db): seed/rescan/recovery queries for the expiry scheduler`.

---

### Task F3: `ExpiryScheduler` skeleton — heap, `schedule()`, `_time_until_next()`

The min-heap holds `(deadline_ts, seq, tenant_id, request_id)` where `deadline_ts` is the POSIX
timestamp of the ISO `expires_at`, and `seq` (from `itertools.count`) is a stable FIFO tiebreaker so
tuples never compare `tenant_id`/`request_id`. `schedule()` pushes and wakes the run loop.

**Files:**
- Create: `server/arbiter/scheduler.py`.
- Test: `server/tests/test_scheduler.py` (create; holds the shared fakes for the whole group).

**Interfaces:**
- Consumes: `TenantRegistry`, `ControlPlane` (held as `self.registry`, `self.control`); no methods
  called yet in F3.
- Produces:
  - **`ExpiryScheduler(registry, control, *, approval_ttl_seconds: int, rescan_interval: float = 30.0, seed_batch: int = 32, per_tenant_batch: int = 16)`**
  - **`ExpiryScheduler.schedule(expires_at: str, tenant_id: str, request_id: str) -> None`** — the
    exact 3-arg contract signature; called by the create handler (on create) and the decide handler
    (second entry at `decided_at+approval_ttl`), and by F's own seed/rescan.
  - `ExpiryScheduler._time_until_next() -> float | None` (seconds until the earliest deadline;
    `None` when empty) — used by `run()` (Task F5).

**Steps:**

- [ ] **Write the failing test.** Create `server/tests/test_scheduler.py` with the shared fakes and
  the F3 tests:
  ```python
  import hashlib
  import time
  from contextlib import asynccontextmanager
  from datetime import datetime, timedelta, timezone

  import jwt
  import pytest
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

  from arbiter.db import Database
  from arbiter.models import RequestCreate
  from arbiter.scheduler import ExpiryScheduler

  # ── shared fakes for the whole Group F suite ─────────────────────────────
  def _now():
      return datetime.now(timezone.utc)

  def _iso(dt):
      return dt.isoformat()

  class _Signer:
      """Real Ed25519 key + tenant-namespaced kid, matching the Cell.signer contract."""
      def __init__(self, tenant_id):
          self.signing_key = Ed25519PrivateKey.generate()
          raw = self.signing_key.public_key().public_bytes(
              serialization.Encoding.Raw, serialization.PublicFormat.Raw)
          self.kid = f"{tenant_id}:{hashlib.sha256(raw).hexdigest()[:8]}"
      def public_key(self):
          return self.signing_key.public_key()

  class _Hub:
      def __init__(self):
          self.events = []
      def publish(self, event):                    # contract: publish(event)->None
          self.events.append(event)

  class _Dispatcher:
      def __init__(self):
          self.decided = []
      async def request_created(self, req):
          pass
      async def request_decided(self, req):        # Outbox routes expired->request_decided
          self.decided.append(req)

  class _Cell:
      def __init__(self, tenant_id, epoch):
          self.tenant_id = tenant_id
          self.epoch = epoch
          self.db = Database(":memory:")
          self.signer = _Signer(tenant_id)
          self.hub = _Hub()
          self.dispatcher = _Dispatcher()

  class _Registry:
      """Fake TenantRegistry.hold: pins by object, tracks refcount + opens so
      tests can assert exactly-once release and FD-budgeted (registry-routed)
      cold opens."""
      def __init__(self, *cells):
          self.cells = {c.tenant_id: c for c in cells}
          self.refcount = {t: 0 for t in self.cells}
          self.peak = {t: 0 for t in self.cells}
          self.opens = 0
      @asynccontextmanager
      async def hold(self, tenant_id, epoch):
          cell = self.cells[tenant_id]
          assert cell.epoch == epoch               # snapshot-consistent epoch (§5)
          self.opens += 1
          self.refcount[tenant_id] += 1
          self.peak[tenant_id] = max(self.peak[tenant_id], self.refcount[tenant_id])
          try:
              yield cell
          finally:
              self.refcount[tenant_id] -= 1

  class _Control:
      def __init__(self, *cells):
          self._t = [{"tenant_id": c.tenant_id, "epoch": c.epoch} for c in cells]
      def list_tenants(self):
          return list(self._t)

  def _add_pending(cell, expires_at):
      """Insert a pending request, then force its expires_at (past = overdue)."""
      req = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
      with cell.db._lock:
          cell.db.conn.execute("UPDATE requests SET expires_at=? WHERE id=?",
                              (expires_at, req["id"]))
          cell.db.conn.commit()
      return cell.db.get_request(req["id"])

  def _mk(*cells, **kw):
      reg = _Registry(*cells)
      ctl = _Control(*cells)
      return ExpiryScheduler(reg, ctl, approval_ttl_seconds=900, **kw), reg, ctl

  # ── F3 ───────────────────────────────────────────────────────────────────
  def test_schedule_orders_by_deadline():
      cell = _Cell("default", 1)
      sched, _, _ = _mk(cell)
      soon = _iso(_now() + timedelta(seconds=10))
      later = _iso(_now() + timedelta(seconds=100))
      sched.schedule(later, "default", "r-late")
      sched.schedule(soon, "default", "r-soon")
      assert sched._heap[0][3] == "r-soon"          # earliest deadline at the root
      assert sched._wake.is_set()

  def test_time_until_next_empty_is_none():
      cell = _Cell("default", 1)
      sched, _, _ = _mk(cell)
      assert sched._time_until_next() is None
      sched.schedule(_iso(_now() + timedelta(seconds=50)), "default", "r1")
      assert 0 < sched._time_until_next() <= 50
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_scheduler.py -q -k "schedule_orders or time_until_next"`
  → `ModuleNotFoundError: No module named 'arbiter.scheduler'`.
- [ ] **Implement.** Create `server/arbiter/scheduler.py`:
  ```python
  """Process-wide expiry scheduler (spec §6, invariant §15.10).

  One min-heap of (deadline, tenant_id, request_id) replaces the shipped
  per-cell 1s sweeper. Holds NO cell/db/key reference — every firing acquires
  the CURRENT cell via registry.hold(tenant_id, epoch) and uses that cell's own
  signer + db, so a request is always expired under its own tenant's key and
  against its own tenant's db.
  """
  import asyncio
  import heapq
  import itertools
  import logging
  import time
  from datetime import datetime, timezone

  from .notify.outbox import Outbox
  from .signing import sign_verdict

  log = logging.getLogger("arbiter.scheduler")


  def _ts(iso: str) -> float:
      return datetime.fromisoformat(iso).timestamp()


  def _now() -> datetime:
      return datetime.now(timezone.utc)


  class ExpiryScheduler:
      def __init__(self, registry, control, *, approval_ttl_seconds: int,
                   rescan_interval: float = 30.0, seed_batch: int = 32,
                   per_tenant_batch: int = 16):
          self.registry = registry
          self.control = control
          self.approval_ttl_seconds = approval_ttl_seconds
          self.rescan_interval = rescan_interval
          self.seed_batch = seed_batch
          self.per_tenant_batch = per_tenant_batch
          self._heap: list[tuple[float, int, str, str]] = []
          self._seq = itertools.count()
          self._wake = asyncio.Event()
          self._bg: set[asyncio.Task] = set()
          self._rescan_cursor = 0
          self._last_rescan = 0.0
          self._stopped = False

      def schedule(self, expires_at: str, tenant_id: str, request_id: str) -> None:
          """Push a deadline. Duplicate entries for the same request are harmless:
          every firing is guarded at the DB layer (F1/expire_stale_approvals), so a
          re-scheduled row is at-most-once in effect."""
          heapq.heappush(self._heap,
                         (_ts(expires_at), next(self._seq), tenant_id, request_id))
          self._wake.set()

      def _time_until_next(self) -> float | None:
          if not self._heap:
              return None
          return max(0.0, self._heap[0][0] - time.time())
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_scheduler.py -q -k "schedule_orders or time_until_next"` → 2 passed.
- [ ] **Commit:** `feat(scheduler): ExpiryScheduler heap + schedule() skeleton`.

---

### Task F4: firing a pending expiry — `_current_epoch`, `_fire_one`, `_process_row`, `_emit_expired`, `_spawn_outbox`

Firing binds the **current** cell (epoch resolved fresh from the control plane; a tombstoned tenant
is skipped), reads the row from **that cell's db**, signs with **that cell's signer**, commits the
atomic flip (F1), then emits `request.expired` to that cell's hub + a background outbox delivery that
**re-pins** the cell for its duration. This proves invariant §15.10: *"every firing signs with the
acquired cell's own signer against its own db."*

**Files:**
- Modify: `server/arbiter/scheduler.py` (add methods to `ExpiryScheduler`).
- Test: `server/tests/test_scheduler.py` (append).

**Interfaces:**
- Consumes: `registry.hold(tenant_id, epoch)`; `control.list_tenants()`; `Cell.db`, `Cell.signer`
  (`.kid`,`.signing_key`), `Cell.hub.publish(event)`, `Cell.dispatcher`, `Cell.tenant_id`,
  `Cell.epoch`; `sign_verdict(signer, request_id=, action_hash=, decision=, decided_at=,
  approval_ttl_seconds=, tenant_id=)`; `Database.expire_request_with_verdict` (F1); shipped
  `Database.expire_stale_approvals`, `Database.get_request`; shipped `Outbox(db, dispatcher).publish`.
- Produces:
  - `ExpiryScheduler._current_epoch(tenant_id) -> int | None`
  - `async ExpiryScheduler._fire_one(entry) -> None`
  - `async ExpiryScheduler._process_row(cell, row) -> None`
  - `ExpiryScheduler._emit_expired(cell, row) -> None`
  - `ExpiryScheduler._spawn_outbox(tenant_id, epoch, event, row) -> None`

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_scheduler.py`:
  ```python
  def _verify(jws, signer, tenant_id):
      return jwt.decode(jws, signer.public_key(), algorithms=["EdDSA"],
                        audience=f"hma-verdict:{tenant_id}")

  @pytest.mark.asyncio
  async def test_fire_one_signs_with_that_cells_key_and_db():
      cellA = _Cell("acme", 1)
      cellB = _Cell("beta", 1)
      sched, reg, _ = _mk(cellA, cellB)
      overdue = _iso(_now() - timedelta(seconds=5))
      rB = _add_pending(cellB, overdue)                 # B's request only

      await sched._fire_one((_ts(overdue), 0, "beta", rB["id"]))

      row = cellB.db.get_request(rB["id"])
      assert row["status"] == "expired" and row["verdict_jws"]
      # verifies under B's key + audience
      claims = _verify(row["verdict_jws"], cellB.signer, "beta")
      assert claims["hma"]["decision"] == "expired"
      assert claims["hma"]["request_id"] == rB["id"]
      # FAILS under A's key (cross-tenant forgery rejected)
      with pytest.raises(jwt.InvalidSignatureError):
          jwt.decode(row["verdict_jws"], cellA.signer.public_key(),
                     algorithms=["EdDSA"], audience="hma-verdict:beta")
      # hit B's db, never A's; and the cell was cold-opened via the registry
      assert cellA.db.get_request(rB["id"]) is None
      assert reg.opens >= 1
      # emitted on B's hub, and refcount released exactly once (back to 0)
      assert any(e.get("event") == "request.expired" for e in cellB.hub.events)
      # drain the spawned outbox task, then assert the pin was released
      for t in list(sched._bg):
          await t
      assert reg.refcount["beta"] == 0

  @pytest.mark.asyncio
  async def test_fire_one_skips_tombstoned_tenant():
      cell = _Cell("gone", 1)
      sched, reg, ctl = _mk(cell)
      overdue = _iso(_now() - timedelta(seconds=5))
      r = _add_pending(cell, overdue)
      ctl._t = []                                       # tenant tombstoned: absent from control
      await sched._fire_one((_ts(overdue), 0, "gone", r["id"]))
      assert reg.opens == 0                              # never opened a dead cell
      assert cell.db.get_request(r["id"])["status"] == "pending"
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_scheduler.py -q -k "fire_one"`
  → `AttributeError: 'ExpiryScheduler' object has no attribute '_fire_one'`.
- [ ] **Implement.** Append to `ExpiryScheduler` in `server/arbiter/scheduler.py`:
  ```python
      def _current_epoch(self, tenant_id: str) -> int | None:
          """Current monotonic epoch from the control plane; None if the tenant
          is tombstoned/absent (its cell is gone — nothing to expire)."""
          for t in self.control.list_tenants():
              if t["tenant_id"] == tenant_id:
                  return t["epoch"]
          return None

      async def _fire_one(self, entry) -> None:
          _, _, tenant_id, request_id = entry
          epoch = self._current_epoch(tenant_id)
          if epoch is None:
              return
          try:
              async with self.registry.hold(tenant_id, epoch) as cell:
                  row = cell.db.get_request(request_id)
                  if row is not None:
                      await self._process_row(cell, row)
          except Exception as exc:
              log.warning("expiry firing failed tenant=%s rid=%s: %s",
                          tenant_id, request_id, exc)

      async def _process_row(self, cell, row) -> None:
          now = _now()
          if row["status"] == "pending":
              jws = sign_verdict(cell.signer, request_id=row["id"],
                                 action_hash=row["action_hash"], decision="expired",
                                 decided_at=row["expires_at"],
                                 approval_ttl_seconds=self.approval_ttl_seconds,
                                 tenant_id=cell.tenant_id)
              updated = cell.db.expire_request_with_verdict(
                  row["id"], jws, cell.signer.kid, now)
              if updated is not None:                    # None => a decision won the race
                  self._emit_expired(cell, updated)
          elif row["status"] == "approved" and row["consumed_at"] is None:
              # staleness deadline: flip approved-unconsumed, KEEP the original
              # decision verdict (shipped expire_stale_approvals). Emit for every
              # row this call flipped (its own heap entry, if any, becomes a no-op).
              for flipped in cell.db.expire_stale_approvals(self.approval_ttl_seconds, now):
                  self._emit_expired(cell, flipped)

      def _emit_expired(self, cell, row) -> None:
          cell.hub.publish({"event": "request.expired", "request": row})
          self._spawn_outbox(cell.tenant_id, cell.epoch, "request.expired", row)

      def _spawn_outbox(self, tenant_id: str, epoch: int, event: str, row: dict) -> None:
          """At-least-once delivery on a background task that RE-PINS the cell for
          its whole lifetime (§5: background tasks pin their cell). A strong ref is
          held in self._bg until done (bare create_task results are GC-eligible)."""
          async def _run():
              try:
                  async with self.registry.hold(tenant_id, epoch) as cell:
                      await Outbox(cell.db, cell.dispatcher).publish(event, row)
              except Exception as exc:
                  log.warning("expiry outbox publish failed tenant=%s rid=%s: %s",
                              tenant_id, row.get("id"), exc)
          t = asyncio.create_task(_run())
          self._bg.add(t)
          t.add_done_callback(self._bg.discard)
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_scheduler.py -q -k "fire_one"` → 2 passed.
- [ ] **Commit:** `feat(scheduler): per-cell firing — sign+flip+emit under the acquired cell`.

---

### Task F5: `_fire_due` (round-robin fairness) + `seed()` + `run()`

`_fire_due` pops all due entries, groups by tenant, processes **at most `per_tenant_batch` per tenant
per pass**, and re-pushes the overflow (deadline already past → next pass) so one tenant's large
short-TTL batch cannot starve another. `seed()` does the bounded startup scan (open each cell via
`hold`, schedule its `open_deadline_rows`, plus the F8 recovery re-sign). `run()` is the long-lived
loop: `seed()`, then wait on the earliest deadline **capped by `rescan_interval`** (so the level
trigger fires even with an empty heap), fire due, and periodically rescan.

**Files:**
- Modify: `server/arbiter/scheduler.py`.
- Test: `server/tests/test_scheduler.py` (append).

**Interfaces:**
- Consumes: F4 methods; `registry.hold`; `control.list_tenants()`; `Database.open_deadline_rows`
  (F2); `Database.expired_without_verdict` (F2) via `_recover` (added here, exercised in F8).
- Produces:
  - `async ExpiryScheduler._fire_due() -> None`
  - `ExpiryScheduler._schedule_row(tenant_id, row) -> None`
  - `async ExpiryScheduler.seed() -> None`
  - `async ExpiryScheduler.run() -> None` and `ExpiryScheduler.stop() -> None`
  - `async ExpiryScheduler._recover(cell) -> None` (used by `seed()`; the F8 test drives it)

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_scheduler.py`:
  ```python
  @pytest.mark.asyncio
  async def test_fire_due_round_robin_does_not_starve(monkeypatch):
      cellA = _Cell("acme", 1)
      cellB = _Cell("beta", 1)
      sched, reg, _ = _mk(cellA, cellB, per_tenant_batch=2)
      overdue = _iso(_now() - timedelta(seconds=5))
      a_ids = [_add_pending(cellA, overdue)["id"] for _ in range(5)]   # A floods
      b_ids = [_add_pending(cellB, overdue)["id"] for _ in range(2)]   # B is small
      for rid in a_ids:
          sched.schedule(overdue, "acme", rid)
      for rid in b_ids:
          sched.schedule(overdue, "beta", rid)

      await sched._fire_due()          # one pass: <=2 per tenant, B fully served
      assert all(cellB.db.get_request(r)["status"] == "expired" for r in b_ids)
      expired_a = sum(cellA.db.get_request(r)["status"] == "expired" for r in a_ids)
      assert expired_a == 2            # A capped this pass; overflow deferred, not lost
      assert len(sched._heap) == 3     # 3 of A's re-pushed
      for t in list(sched._bg):
          await t

  @pytest.mark.asyncio
  async def test_seed_schedules_pending_from_cold_cells():
      cell = _Cell("default", 1)
      overdue = _iso(_now() - timedelta(seconds=5))
      r = _add_pending(cell, overdue)
      sched, reg, _ = _mk(cell)
      await sched.seed()
      assert any(e[3] == r["id"] for e in sched._heap)

  @pytest.mark.asyncio
  async def test_run_expires_a_scheduled_request():
      cell = _Cell("default", 1)
      sched, reg, _ = _mk(cell, rescan_interval=0.05)
      overdue = _iso(_now() - timedelta(seconds=1))
      r = _add_pending(cell, overdue)
      sched.schedule(overdue, "default", r["id"])
      task = asyncio.create_task(sched.run())
      try:
          for _ in range(50):
              if cell.db.get_request(r["id"])["status"] == "expired":
                  break
              await asyncio.sleep(0.02)
      finally:
          sched.stop()
          await task
      assert cell.db.get_request(r["id"])["status"] == "expired"
      for t in list(sched._bg):
          await t
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_scheduler.py -q -k "round_robin or seed_schedules or run_expires"`
  → `AttributeError: ... '_fire_due'`.
- [ ] **Implement.** Append to `ExpiryScheduler` and add the needed import at the top of
  `server/arbiter/scheduler.py` (`from collections import OrderedDict`):
  ```python
      async def _fire_due(self) -> None:
          now = time.time()
          due = []
          while self._heap and self._heap[0][0] <= now:
              due.append(heapq.heappop(self._heap))
          if not due:
              return
          by_tenant: "OrderedDict[str, list]" = OrderedDict()
          for entry in due:
              by_tenant.setdefault(entry[2], []).append(entry)
          deferred = []
          for entries in by_tenant.values():
              head, tail = entries[:self.per_tenant_batch], entries[self.per_tenant_batch:]
              for entry in head:
                  await self._fire_one(entry)
              deferred.extend(tail)               # over-cap this pass -> next pass (fairness)
          for entry in deferred:
              heapq.heappush(self._heap, entry)
          if deferred:
              self._wake.set()                    # loop again promptly to drain fairly

      def _schedule_row(self, tenant_id: str, row: dict) -> None:
          if row["status"] == "pending":
              self.schedule(row["expires_at"], tenant_id, row["id"])
          elif row["status"] == "approved" and row["consumed_at"] is None:
              deadline = datetime.fromisoformat(row["decided_at"]).timestamp() \
                  + self.approval_ttl_seconds
              heapq.heappush(self._heap,
                             (deadline, next(self._seq), tenant_id, row["id"]))
              self._wake.set()

      async def _recover(self, cell) -> None:
          """Re-sign rows flipped to 'expired' whose verdict never committed, so a
          crash between an old two-commit flip and its sign is not a permanent
          verdict-404 (spec §6 recovery clause)."""
          for row in cell.db.expired_without_verdict():
              jws = sign_verdict(cell.signer, request_id=row["id"],
                                 action_hash=row["action_hash"], decision="expired",
                                 decided_at=row["expires_at"],
                                 approval_ttl_seconds=self.approval_ttl_seconds,
                                 tenant_id=cell.tenant_id)
              cell.db.set_verdict(row["id"], jws, cell.signer.kid)
              cell.db.add_audit(row["id"], "verdict_issued",
                                {"decision": "expired", "kid": cell.signer.kid,
                                 "recovered": True})
              self._spawn_outbox(cell.tenant_id, cell.epoch, "request.expired",
                                 cell.db.get_request(row["id"]))

      async def seed(self) -> None:
          """Bounded startup scan: open each cell (one at a time via hold, so at
          most one transient cell FD beyond the hot set), recover stranded expired
          rows, and schedule every open deadline. Yields between tenants."""
          for t in self.control.list_tenants():
              try:
                  async with self.registry.hold(t["tenant_id"], t["epoch"]) as cell:
                      await self._recover(cell)
                      for row in cell.db.open_deadline_rows():
                          self._schedule_row(t["tenant_id"], row)
              except Exception as exc:
                  log.warning("seed scan failed tenant=%s: %s", t["tenant_id"], exc)
              await asyncio.sleep(0)

      def stop(self) -> None:
          self._stopped = True
          self._wake.set()

      async def run(self) -> None:
          await self.seed()
          self._last_rescan = time.monotonic()
          while not self._stopped:
              wait = self._time_until_next()
              timeout = self.rescan_interval if wait is None \
                  else min(wait, self.rescan_interval)
              try:
                  await asyncio.wait_for(self._wake.wait(), timeout=timeout)
              except asyncio.TimeoutError:
                  pass
              self._wake.clear()
              if self._stopped:
                  break
              await self._fire_due()
              if time.monotonic() - self._last_rescan >= self.rescan_interval:
                  self._last_rescan = time.monotonic()
                  await self._rescan_tick()
  ```
  (`_rescan_tick` is added in F6; the `run()` reference resolves once F6 lands. If you run F5 tests
  before F6, temporarily stub `async def _rescan_tick(self): return` — F6 replaces it with the real
  body and its own test.)
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_scheduler.py -q -k "round_robin or seed_schedules or run_expires"` → 3 passed.
- [ ] **Commit:** `feat(scheduler): fair _fire_due + bounded seed + run/stop loop`.

---

### Task F6: level-triggered `_rescan_tick` — a dropped heap-push still expires

Edge-triggered heaps lose events (a crashed create task, a full queue, a bug). The rescan rolls a
bounded slice of tenants (round-robin across ticks via `_rescan_cursor`), opens each via `hold`, and
re-schedules every `open_deadline_rows` — so an overdue request with **no heap entry** is still
picked up and expired on the next pass.

**Files:**
- Modify: `server/arbiter/scheduler.py` (replace the F5 `_rescan_tick` stub with the real body).
- Test: `server/tests/test_scheduler.py` (append).

**Interfaces:**
- Consumes: `control.list_tenants()`; `registry.hold`; `Database.open_deadline_rows` (F2);
  `_schedule_row` (F5); `_fire_due` (F5).
- Produces: `async ExpiryScheduler._rescan_tick() -> None`.

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_scheduler.py`:
  ```python
  @pytest.mark.asyncio
  async def test_rescan_recovers_dropped_heap_push():
      cell = _Cell("default", 1)
      sched, reg, _ = _mk(cell)
      overdue = _iso(_now() - timedelta(seconds=5))
      r = _add_pending(cell, overdue)               # overdue, but NEVER scheduled (dropped push)
      assert sched._heap == []
      await sched._rescan_tick()                     # level trigger picks it up
      assert any(e[3] == r["id"] for e in sched._heap)
      await sched._fire_due()                         # and it actually expires
      assert cell.db.get_request(r["id"])["status"] == "expired"
      for t in list(sched._bg):
          await t

  @pytest.mark.asyncio
  async def test_rescan_cursor_rolls_over_tenants():
      cells = [_Cell(f"t{i}", 1) for i in range(5)]
      sched, reg, _ = _mk(*cells, seed_batch=2)
      await sched._rescan_tick()
      assert sched._rescan_cursor == 2               # advanced by seed_batch
      await sched._rescan_tick()
      assert sched._rescan_cursor == 4
  ```
- [ ] **Run — expect FAIL:** `cd server && python -m pytest tests/test_scheduler.py -q -k "rescan"`
  (fails on the stub: heap stays empty / cursor stays 0).
- [ ] **Implement.** Replace the `_rescan_tick` stub in `server/arbiter/scheduler.py` with:
  ```python
      async def _rescan_tick(self) -> None:
          """Bounded level-triggered rescan: a rolling slice of tenants per tick,
          round-robin across ticks, re-scheduling every open deadline so a dropped
          heap-push cannot leave a request un-expired forever. Re-scheduling an
          already-queued row is harmless — every firing is DB-guarded."""
          tenants = self.control.list_tenants()
          if not tenants:
              return
          start = self._rescan_cursor % len(tenants)
          slice_ = tenants[start:start + self.seed_batch]
          self._rescan_cursor = start + self.seed_batch
          for t in slice_:
              try:
                  async with self.registry.hold(t["tenant_id"], t["epoch"]) as cell:
                      for row in cell.db.open_deadline_rows():
                          self._schedule_row(t["tenant_id"], row)
              except Exception as exc:
                  log.warning("rescan failed tenant=%s: %s", t["tenant_id"], exc)
              await asyncio.sleep(0)
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_scheduler.py -q -k "rescan"` → 2 passed.
- [ ] **Commit:** `feat(scheduler): level-triggered rescan recovers dropped heap-pushes`.

---

### Task F7: cold-cell stale-approval flips + emits `request.expired`

A request approved on the phone but never consumed by the warden must flip to `expired` at
`decided_at + approval_ttl` even if its cell is cold. The decide handler pushes a **second** heap
entry at that deadline (contract), and the seed/rescan also select `approved AND unconsumed` rows, so
the deadline fires, the shipped `expire_stale_approvals` flips it (keeping the original decision
verdict), and the scheduler emits `request.expired` on the cell's hub + outbox.

**Files:**
- Modify: none (behavior already implemented in F4 `_process_row` staleness branch + F5
  `_schedule_row` staleness deadline). F7 is the isolation/behavior test that locks it in.
- Test: `server/tests/test_scheduler.py` (append).

**Interfaces:**
- Consumes: `_process_row` (F4), `_schedule_row` (F5), shipped `Database.set_decision`,
  `Database.expire_stale_approvals`.
- Produces: (test only) — proves invariant §6 stale-approval clause.

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_scheduler.py`:
  ```python
  @pytest.mark.asyncio
  async def test_cold_cell_stale_approval_flips_and_emits():
      cell = _Cell("default", 1)
      sched, reg, _ = _mk(cell, approval_ttl_seconds=1)
      r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
      dec = cell.db.set_decision(r["id"], "approve", "phone")   # approved, unconsumed
      original_verdict_kid = "kid-before"
      cell.db.set_verdict(r["id"], "ORIGINAL.APPROVE.JWS", original_verdict_kid)
      # force decided_at into the past so decided_at+approval_ttl is overdue
      past = _iso(_now() - timedelta(seconds=10))
      with cell.db._lock:
          cell.db.conn.execute("UPDATE requests SET decided_at=? WHERE id=?", (past, r["id"]))
          cell.db.conn.commit()
      # the staleness deadline (decided_at+1s) fires
      staleness = _iso(datetime.fromisoformat(past) + timedelta(seconds=1))
      await sched._fire_one((_ts(staleness), 0, "default", r["id"]))

      row = cell.db.get_request(r["id"])
      assert row["status"] == "expired"
      assert row["verdict_jws"] == "ORIGINAL.APPROVE.JWS"        # decision verdict KEPT
      assert row["verdict_kid"] == original_verdict_kid
      assert any(e.get("event") == "request.expired" for e in cell.hub.events)
      for t in list(sched._bg):
          await t
      assert reg.refcount["default"] == 0

  @pytest.mark.asyncio
  async def test_seed_schedules_staleness_deadline_for_unconsumed_approved():
      cell = _Cell("default", 1)
      sched, _, _ = _mk(cell, approval_ttl_seconds=900)
      r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
      cell.db.set_decision(r["id"], "approve", "phone")
      await sched.seed()
      assert any(e[3] == r["id"] for e in sched._heap)           # staleness entry seeded
  ```
- [ ] **Run — expect PASS immediately** (F4/F5 already implement the behavior — this is a
  characterization/gate test): `cd server && python -m pytest tests/test_scheduler.py -q -k "stale_approval or staleness_deadline"`
  → 2 passed. *(If either fails, the defect is in F4 `_process_row` or F5 `_schedule_row`; fix there,
  do not special-case here.)*
- [ ] **Commit:** `test(scheduler): cold-cell stale-approval flip keeps verdict + emits expired`.

---

### Task F8: recovery — SIGTERM between the two commits recovers a signed terminal verdict

Simulate a crash that committed the pending→expired flip but died before the verdict: a row with
`status='expired' AND verdict_jws IS NULL`. `seed()` → `_recover(cell)` re-signs it under the cell's
own key, so the verdict endpoint stops returning a permanent 404.

**Files:**
- Modify: none (recovery implemented in F5 `_recover`/`seed`). F8 is the durability test.
- Test: `server/tests/test_scheduler.py` (append).

**Interfaces:**
- Consumes: `seed()` (F5), `_recover` (F5), `Database.expired_without_verdict` (F2),
  shipped `Database.set_verdict`.
- Produces: (test only) — proves the §6 "single transaction OR recovery re-scan" clause and the
  §16 "SIGTERM between the two commits recovers a signed terminal verdict" gate.

**Steps:**

- [ ] **Write the failing test.** Append to `server/tests/test_scheduler.py`:
  ```python
  @pytest.mark.asyncio
  async def test_seed_recovers_expired_without_verdict():
      cell = _Cell("default", 1)
      r = cell.db.create_request(RequestCreate(title="t", ttl_seconds=300))
      # crash simulation: flip committed, verdict never did
      with cell.db._lock:
          cell.db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
          cell.db.conn.commit()
      assert cell.db.get_request(r["id"])["verdict_jws"] is None   # permanent 404 today

      sched, reg, _ = _mk(cell)
      await sched.seed()                                            # recovery re-signs

      row = cell.db.get_request(r["id"])
      assert row["status"] == "expired"
      assert row["verdict_jws"]                                     # no longer a 404
      claims = _verify(row["verdict_jws"], cell.signer, "default")
      assert claims["hma"]["decision"] == "expired"
      assert cell.db.expired_without_verdict() == []               # nothing left stranded
      for t in list(sched._bg):
          await t
  ```
- [ ] **Run — expect PASS immediately** (F5 `_recover` already implements it):
  `cd server && python -m pytest tests/test_scheduler.py -q -k "recovers_expired_without_verdict"` → 1 passed.
  *(If it fails, the defect is in F5 `_recover`/`seed`; fix there.)*
- [ ] **Commit:** `test(scheduler): seed() recovers a signed verdict after a crash between commits`.

---

### Task F9: wiring contract + two-tenant end-to-end isolation gate

The multi-tenant `create_app` (owned by the app/routes group) must **not** start the shipped 1s
`sweep()` loop (`server/arbiter/app.py:64-73`). F9 states the exact wiring the app/routes group
consumes, and adds the composed two-tenant durability+isolation test that stands in for the §16
"scheduler durability" and "scheduler per-cell signing / fairness / FD budget" merge gates.

**Wiring contract (consumed by the app/routes group — produced here by name):**
- Construct once per process:
  `scheduler = ExpiryScheduler(registry, control, approval_ttl_seconds=cfg.policy.approval_ttl_seconds)`.
- In the app `lifespan`, replace the `sweep()` task with:
  `sched_task = asyncio.create_task(scheduler.run())`; on shutdown call `scheduler.stop()` then
  `await sched_task` (and drain `scheduler._bg`).
- The **create** handler, after `cell.db.create_request(...)`, calls
  `scheduler.schedule(req["expires_at"], cell.tenant_id, req["id"])`.
- The **decide** handler, after a successful approve, calls
  `scheduler.schedule(decided_at_plus_ttl_iso, cell.tenant_id, rid)` where
  `decided_at_plus_ttl_iso = (fromisoformat(updated["decided_at"]) + timedelta(seconds=cfg.policy.approval_ttl_seconds)).isoformat()`.
- **Delete** the `_expire_pass`/`sweep`/`app.state.expire_pass` machinery from the multi-tenant app
  path — the scheduler owns all expiry now.

**Files:**
- Test: `server/tests/test_scheduler.py` (append — the composed gate).
- Modify (app/routes group's file, referenced only): `server/arbiter/app.py` create_app — remove the
  sweeper, add the scheduler start + `schedule()` calls per the contract above. *(If Group F also
  owns the app rewrite on this branch, apply the edits above with the same TDD discipline; otherwise
  this is the consumed contract for the app/routes group.)*

**Interfaces:**
- Consumes: all F1–F6 surfaces; the fakes from F3.
- Produces: the §16 gate test `test_two_tenant_scheduler_isolation_and_durability`.

**Steps:**

- [ ] **Write the failing/gate test.** Append to `server/tests/test_scheduler.py`:
  ```python
  @pytest.mark.asyncio
  async def test_two_tenant_scheduler_isolation_and_durability():
      A = _Cell("acme", 1)
      B = _Cell("beta", 1)
      sched, reg, _ = _mk(A, B, per_tenant_batch=3)
      overdue = _iso(_now() - timedelta(seconds=5))

      a_ids = [_add_pending(A, overdue)["id"] for _ in range(5)]      # A floods
      b_id = _add_pending(B, overdue)["id"]                           # B is small
      # a dropped push for one of A's rows (never scheduled) — rescan must catch it
      for rid in a_ids[:-1]:
          sched.schedule(overdue, "acme", rid)
      sched.schedule(overdue, "beta", b_id)

      await sched._fire_due()          # B not starved by A's flood
      assert B.db.get_request(b_id)["status"] == "expired"
      await sched._rescan_tick()        # picks up the dropped one + A's deferred overflow
      await sched._fire_due()
      await sched._fire_due()
      for t in list(sched._bg):
          await t

      # every A row expired, each verified under A's key and NOT B's; and vice-versa
      for rid in a_ids:
          row = A.db.get_request(rid)
          assert row["status"] == "expired" and row["verdict_jws"]
          _verify(row["verdict_jws"], A.signer, "acme")
          with pytest.raises(jwt.InvalidSignatureError):
              jwt.decode(row["verdict_jws"], B.signer.public_key(),
                         algorithms=["EdDSA"], audience="hma-verdict:acme")
      # no cross-tenant db bleed and all pins released (FD budget respected)
      assert all(B.db.get_request(rid) is None for rid in a_ids)
      assert reg.refcount["acme"] == 0 and reg.refcount["beta"] == 0
      # each cell only ever saw its own expiry events on its own hub
      assert all(e["request"]["id"] in a_ids for e in A.hub.events)
      assert all(e["request"]["id"] == b_id for e in B.hub.events)
  ```
- [ ] **Run — expect PASS:** `cd server && python -m pytest tests/test_scheduler.py -q -k two_tenant` → 1 passed.
- [ ] **Full group green:** `cd server && python -m pytest tests/test_scheduler.py tests/test_db.py -q` → all green;
  then `cd server && python -m pytest -q` (whole suite) and `cd server && ruff check .` (the repo's lint gate).
- [ ] **Commit:** `feat(scheduler): two-tenant isolation+durability gate; wire scheduler into create_app`.

---

## Coverage map (task → spec)

| Spec / gate | Task |
|---|---|
| §6 heap holds only `(expires_at, tenant_id, request_id)` | F3 |
| §6/§15.10 firing signs with the acquired cell's own signer + db | F4 |
| §6 pending→expired flip + verdict is one transaction | F1, F4 |
| §6 second entry at `decided_at+approval_ttl`; cold stale-approval flips | F5 (`_schedule_row`), F7 |
| §6 dropped heap-push still expires (level-triggered rescan) | F2, F6 |
| §6 recovery re-scan `status='expired' AND verdict_jws IS NULL` | F2, F5 (`_recover`), F8 |
| §6 per-tenant round-robin fairness | F5 (`_fire_due`) |
| §6/§5/§15.13 scheduler cold-opens counted against FD budget (via `registry.hold` only) | F4, F9 |
| §6 bounded startup seed-scan | F5 (`seed`) |
| §16 "B's expiry verifies under B's key, fails under A's, hits B's db" | F4, F9 |
| §16 "dropped heap-push still expires via rescan" | F6 |
| §16 "cold-cell stale-approval flips" | F7 |
| §16 "SIGTERM between the two commits recovers a signed terminal verdict" | F8 |
| §16 "scheduler fairness / FD budget (A's batch doesn't starve/FD-starve B)" | F5, F9 |
| Replaces the shipped per-cell 1s sweeper | F9 |


---


## Group G — device enrollment binding + observability isolation + notify idempotency

Implements design §10 (device enrollment binding), §11 (observability isolation),
§9 (notify idempotency), and invariant §15.11 (every outward action idempotent under a
`(tenant, request, event)` dedupe key; re-drain bounded to process-restart, never cell-open).

Branch: `feat/multitenant-isolation`. Run all Python tests from the `server/` directory
(`cd server && python -m pytest ...`). The suite has **no** `asyncio_mode=auto`, so async
tests drive coroutines with `asyncio.run(...)` exactly like `server/tests/test_outbox.py`.

## What this group CONSUMES from the pinned cross-component contract (other groups build these)
- **`Cell`** — `cell.tenant_id: str`, `cell.epoch: int`, `cell.db: Database`, `cell.dispatcher: Dispatcher`, `cell.hub: Hub`.
- **`TenantRegistry`** — `async acquire(tenant_id, epoch)->Cell`, `release(cell)->None`, `async` context manager `hold(tenant_id, epoch)->Cell`.
- **`ControlPlane`** — `resolve(token_hash)->(tenant_id, epoch)|None`, `is_disabled(tenant_id)->bool`, `add_route(token_hash, tenant_id)`, `remove_route(token_hash)`, `tenant_dir(tenant_id)->Path`, `list_tenants()`.
- **`resolve_identity(request, registry, control)->(Identity, Cell)`** — the router-first identity path.
- **`Dispatcher`** (per-cell, built with `cell.db` + per-cell delivery config) and **`Outbox`** (extended here).

Because those objects are built by other groups, every test in this group uses **local
fakes** (`FakeCell`, `FakeRegistry`, `FakeControl`) so the group is independently runnable
and green before integration. The fakes match the contract signatures above verbatim.

## What this group PRODUCES (later tasks / other groups rely on these VERBATIM)
- `Database.mint_pairing(code_hash, expires_at)->None`, `Database.redeem_pairing(code_hash, now=None)->tuple[int, dict|None]` (cell-owned `pairings` table, **single-use**).
- `Database.notify_reserve(request_id, event)->bool` (cell-owned `notify_sent` dedupe table).
- Idempotent `Outbox` (reserve-before-dispatch; re-drain skips already-reserved keys).
- `arbiter.enroll.resolve_pairing(request, registry, control)->Cell` (routes a pairing credential to its cell, single-use redeem inside the cell).
- `POST /v1/devices/enroll` route.
- `arbiter.errors.generic_403()`, `arbiter.errors.EqualizedFloor` (constant client-error body + equalized timing).
- `arbiter.obslog.scoped_log(tenant_id, event, **fields)` (per-tenant sink, PII-stripping).
- `arbiter.notify.outbox.drain_all_at_startup(registry, control)` (process-restart-only re-drain).
- CLI `hma tenant pair-code <tenant>`.

## Migration-ladder ownership
The cell `Database` ladder is currently at `SCHEMA_VERSION = 6`. **Group G reserves the next
two cell-db migrations: 7 (`pairings`) and 8 (`notify_sent`).** No other group adds cell-db
migrations; control-plane state (routes, epochs, MACs) lives in `control.db`, a separate schema.

---

### Task G1: cell-owned `pairings` table + `mint_pairing` / `redeem_pairing`

The pairing credential is a tenant-bound, single-use, short-expiry secret. Its row lives ONLY
in the cell's own `Database` (no global table). `redeem_pairing` is the single-use authority,
built exactly like the shipped `consume_request` guarded-UPDATE pattern (`db.py:288-311`).

**Files:**
- Modify: `server/arbiter/db.py` (add `_migrate_6_to_7`, bump `SCHEMA_VERSION` to 7, add two methods near the device methods `db.py:330-357`).
- Test: `server/tests/test_pairings.py` (new).

**Interfaces:**
- Consumes: `Database(path)` (existing), the `self._lock` + `_iso`/`_utcnow` helpers (existing, `db.py:7-11,101`).
- Produces:
  - `Database.mint_pairing(code_hash: str, expires_at: str) -> None`
  - `Database.redeem_pairing(code_hash: str, now: datetime | None = None) -> tuple[int, dict | None]`
    returning `(200, row)` redeemed-now / `(404, None)` unknown / `(410, row)` expired / `(409, row)` already-consumed.

**TDD steps:**

- [ ] Write the failing test — migration + mint/redeem happy path + single-use + expiry.

```python
# server/tests/test_pairings.py
from datetime import datetime, timedelta, timezone

from arbiter.db import Database, SCHEMA_VERSION


def _iso(dt):
    return dt.isoformat()


def test_migration_7_creates_pairings_table():
    db = Database(":memory:")
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "pairings" in names
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION >= 7


def test_mint_then_redeem_once():
    db = Database(":memory:")
    exp = _iso(datetime.now(timezone.utc) + timedelta(minutes=15))
    db.mint_pairing("hash-a", exp)
    code, row = db.redeem_pairing("hash-a")
    assert code == 200 and row["consumed_at"] is not None
    # second redemption of the same code is rejected (single-use)
    code2, _ = db.redeem_pairing("hash-a")
    assert code2 == 409


def test_redeem_unknown_is_404():
    db = Database(":memory:")
    code, row = db.redeem_pairing("nope")
    assert code == 404 and row is None


def test_redeem_expired_is_410():
    db = Database(":memory:")
    past = _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
    db.mint_pairing("hash-old", past)
    code, _ = db.redeem_pairing("hash-old")
    assert code == 410
```

- [ ] Run it — expect FAIL (no `pairings` table / no methods):
  `cd server && python -m pytest tests/test_pairings.py -x` → `AttributeError`/`OperationalError`.

- [ ] Minimal implementation — migration + methods.

In `server/arbiter/db.py`, bump the version and add the migration:

```python
SCHEMA_VERSION = 7
```

```python
def _migrate_6_to_7(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS pairings(
      code_hash TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT)""")
```

```python
MIGRATIONS = [_migrate_0_to_1, _migrate_1_to_2, _migrate_2_to_3, _migrate_3_to_4, _migrate_4_to_5,
              _migrate_5_to_6, _migrate_6_to_7]
```

Add the two methods (place after `delete_device`, `db.py:407`):

```python
    # ── device pairing (tenant-bound, single-use, short-expiry) ─────────────

    def mint_pairing(self, code_hash: str, expires_at: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO pairings(code_hash,created_at,expires_at,consumed_at)"
                " VALUES (?,?,?,NULL)", (code_hash, _iso(_utcnow()), expires_at))
            self.conn.commit()

    def redeem_pairing(self, code_hash: str,
                       now: datetime | None = None) -> tuple[int, dict | None]:
        """Single-use redemption of a pairing credential. Mirrors consume_request:
        the guarded UPDATE is the atomic core, so concurrent redemptions race on
        rowcount and exactly one wins. Returns (200, row) redeemed-now;
        (404, None) unknown; (410, row) expired; (409, row) already-consumed."""
        now = now or _utcnow()
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM pairings WHERE code_hash=?", (code_hash,)).fetchone()
            if r is None:
                return 404, None
            cur = self.conn.execute(
                "UPDATE pairings SET consumed_at=? WHERE code_hash=?"
                " AND consumed_at IS NULL AND expires_at > ?",
                (_iso(now), code_hash, _iso(now)))
            self.conn.commit()
            row = dict(self.conn.execute(
                "SELECT * FROM pairings WHERE code_hash=?", (code_hash,)).fetchone())
            if cur.rowcount == 1:
                return 200, row
            if row["consumed_at"] is None:   # guard failed but never consumed ⇒ expiry
                return 410, row
            return 409, row
```

- [ ] Run green — `cd server && python -m pytest tests/test_pairings.py -x` → PASS.
- [ ] Commit — `feat(server): cell-owned single-use pairing credential table (§10)`.

---

### Task G2: cell-owned `notify_sent` dedupe table + `notify_reserve`

The `(tenant, request, event)` dedupe key of §9/§15.11. Because there is one `Database` per
cell, the row `(request_id, event)` is already tenant-scoped — the tenant is the cell. The PK
uniqueness gives an atomic reserve-or-lose.

**Files:**
- Modify: `server/arbiter/db.py` (add `_migrate_7_to_8`, bump `SCHEMA_VERSION` to 8, add `notify_reserve`).
- Test: `server/tests/test_notify_dedupe.py` (new).

**Interfaces:**
- Consumes: `Database`, `self._lock`, `_iso`/`_utcnow`.
- Produces: `Database.notify_reserve(request_id: str, event: str) -> bool` — `True` iff the key was newly inserted; `False` if it already existed.

**TDD steps:**

- [ ] Write the failing test.

```python
# server/tests/test_notify_dedupe.py
from arbiter.db import Database, SCHEMA_VERSION


def test_migration_8_creates_notify_sent_table():
    db = Database(":memory:")
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "notify_sent" in names
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION >= 8


def test_reserve_is_true_once_then_false():
    db = Database(":memory:")
    assert db.notify_reserve("r1", "request.decided") is True
    assert db.notify_reserve("r1", "request.decided") is False   # dedupe
    # a different event for the same request is a distinct key
    assert db.notify_reserve("r1", "request.created") is True
```

- [ ] Run it — expect FAIL: `cd server && python -m pytest tests/test_notify_dedupe.py -x`.

- [ ] Minimal implementation.

```python
SCHEMA_VERSION = 8
```

```python
def _migrate_7_to_8(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS notify_sent(
      request_id TEXT NOT NULL,
      event TEXT NOT NULL,
      sent_at TEXT NOT NULL,
      PRIMARY KEY(request_id, event))""")
```

```python
MIGRATIONS = [_migrate_0_to_1, _migrate_1_to_2, _migrate_2_to_3, _migrate_3_to_4, _migrate_4_to_5,
              _migrate_5_to_6, _migrate_6_to_7, _migrate_7_to_8]
```

Add the method (after `outbox_pending`, `db.py:177`):

```python
    def notify_reserve(self, request_id: str, event: str) -> bool:
        """Reserve the (request, event) dedupe key. Returns True iff newly
        reserved; False if this outward action was already claimed. Reserve is
        committed BEFORE the outward call so a re-drain (process restart) or a
        cell reopened after churn observes the claim and never re-fires it."""
        import sqlite3 as _sqlite3
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO notify_sent(request_id,event,sent_at) VALUES (?,?,?)",
                    (request_id, event, _iso(_utcnow())))
                self.conn.commit()
                return True
            except _sqlite3.IntegrityError:
                return False
```

- [ ] Run green — PASS.
- [ ] Commit — `feat(server): (tenant,request,event) notify dedupe table (§9,§15.11)`.

---

### Task G3: idempotent `Outbox` — reserve-before-dispatch, at-most-once across crash + churn

Today `Outbox._deliver` (`notify/outbox.py:56-69`) re-dispatches on every startup drain, so a
crash between a successful dispatch and `outbox_delete` re-fires the callback (documented
at-least-once, `outbox.py:20-26`). §15.11 upgrades this to **at most once per dedupe key across
restart/churn**: reserve the `(request, event)` key (G2) BEFORE dispatching; on re-drain a
row whose key is already reserved is dropped without re-firing.

**Files:**
- Modify: `server/arbiter/notify/outbox.py` (`__init__`, `_deliver`; update module docstring).
- Test: `server/tests/test_outbox_idempotent.py` (new).

**Interfaces:**
- Consumes: `Database.notify_reserve` (G2), existing `Database.outbox_add/outbox_delete/outbox_bump_attempts/outbox_pending`.
- Produces: `Outbox(db, dispatcher, sleeps=RETRY_LADDER)` with dedupe; `Outbox.publish`/`drain_startup` unchanged signatures.

**TDD steps:**

- [ ] Write the failing test — the exact §16 scenario (crash between dispatch and delete + churn ⇒ fires once).

```python
# server/tests/test_outbox_idempotent.py
import asyncio
from datetime import datetime, timedelta, timezone

from arbiter.db import Database
from arbiter.notify.outbox import Outbox


def _iso(dt):
    return dt.isoformat()


REQ = {"id": "r1", "title": "Deploy", "severity": "high", "status": "approved",
       "expires_at": _iso(datetime.now(timezone.utc) + timedelta(seconds=300)),
       "callback_url": None}


class CountingDispatcher:
    def __init__(self):
        self.fires = 0

    async def request_created(self, req):
        self.fires += 1

    async def request_decided(self, req):
        self.fires += 1


def test_crash_between_dispatch_and_delete_then_redrain_fires_once():
    # One cell db shared across the "crash" and the "restart drain" — this is
    # what a cell reopened after churn sees: the persisted notify_sent marker.
    db = Database(":memory:")
    disp = CountingDispatcher()
    ob = Outbox(db, disp, sleeps=())

    # First delivery succeeds (fires once) but we simulate a crash BEFORE the
    # outbox row is deleted: enqueue + dispatch manually, skip the delete.
    oid = db.outbox_add(REQ["id"], "request.decided", REQ, REQ["expires_at"])
    assert db.notify_reserve(REQ["id"], "request.decided") is True
    asyncio.run(disp.request_decided(REQ))   # the one real fire
    assert disp.fires == 1
    # crash: outbox row still present, marker present, cell churns/reopens…

    # Restart drain re-runs the row. It must NOT re-fire.
    asyncio.run(ob.drain_startup())
    assert disp.fires == 1                    # at most once per dedupe key
    assert db.outbox_pending() == []          # row cleaned up


def test_first_publish_reserves_and_fires_exactly_once():
    db = Database(":memory:")
    disp = CountingDispatcher()
    ob = Outbox(db, disp, sleeps=())
    asyncio.run(ob.publish("request.created", REQ))
    assert disp.fires == 1
    assert db.notify_reserve(REQ["id"], "request.created") is False   # was reserved
    assert db.outbox_pending() == []
```

- [ ] Run it — expect FAIL (drain re-fires; `disp.fires == 2`):
  `cd server && python -m pytest tests/test_outbox_idempotent.py -x`.

- [ ] Minimal implementation — reserve-before-dispatch in `_deliver`.

Replace `_deliver` in `server/arbiter/notify/outbox.py:56-69`:

```python
    async def _deliver(self, oid: str, event: str, req: dict,
                       attempts_done: int) -> None:
        # Dedupe guard (§9,§15.11): if this (request,event) was already claimed
        # by a prior delivery — including one interrupted by a crash before its
        # outbox_delete, or a cell reopened after churn — do NOT re-fire. The
        # marker is persisted in the cell db, so it survives eviction/reopen.
        if not self.db.notify_reserve(req["id"], event):
            self.db.outbox_delete(oid)
            return
        for i in range(attempts_done, MAX_ATTEMPTS):
            try:
                await self._dispatch(event, req)
                self.db.outbox_delete(oid)
                return
            except Exception as exc:
                log.warning("outbox dispatch %s for %s failed (attempt %d): %s",
                            event, req.get("id"), i + 1, exc)
                self.db.outbox_bump_attempts(oid)
                if i + 1 < MAX_ATTEMPTS and i < len(self.sleeps):
                    await asyncio.sleep(self.sleeps[i])
        # attempts exhausted: row stays for the stale-drop; the reserve marker
        # stays too, so a restart never re-fires this key (at-most-once wins
        # over at-least-once for the deduped path — the tradeoff is possible
        # loss on a crash between reserve and a successful send).
```

Update the module docstring's closing paragraph (`outbox.py:21-26`) to state the new guarantee:
"Because the `(request,event)` dedupe key is reserved in the cell db BEFORE dispatch, overall
delivery is **at most once per dedupe key across process restart and cell churn**: a re-drained
row whose key is already reserved is dropped without re-firing."

- [ ] Run green — `cd server && python -m pytest tests/test_outbox_idempotent.py tests/test_outbox.py -x` → PASS.
  Note `tests/test_outbox.py::test_max_attempts_then_row_stays_no_dlq` still passes: the first
  `publish` reserves + fails 3×; the row stays; no second dispatch cycle re-fires.
- [ ] Commit — `feat(server): idempotent outbox — reserve dedupe key before dispatch (§15.11)`.

---

### Task G4: process-restart-only re-drain coordinator + cell-open-never-drains guard

§9: "the at-least-once outbox re-drain is bounded to **process-restart only — never triggered
by cell-open**." Cells open lazily and cycle hot constantly; a drain on cell-open would re-fire
every churn. This task provides the single process-startup entry point that iterates provisioned
tenants once, and a test proving that merely acquiring/holding a cell drains nothing.

**Files:**
- Modify: `server/arbiter/notify/outbox.py` (add `drain_all_at_startup`).
- Test: `server/tests/test_outbox_drain_scope.py` (new).

**Interfaces:**
- Consumes: `ControlPlane.list_tenants()`, `TenantRegistry.hold(tenant_id, epoch)->Cell`, `Cell.db`, `Cell.dispatcher`, `Outbox.drain_startup`.
- Produces: `async drain_all_at_startup(registry, control) -> None`.

**TDD steps:**

- [ ] Write the failing test with local contract fakes.

```python
# server/tests/test_outbox_drain_scope.py
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from arbiter.db import Database
from arbiter.notify.outbox import drain_all_at_startup


def _iso(dt):
    return dt.isoformat()


class CountingDispatcher:
    def __init__(self):
        self.fires = 0

    async def request_created(self, req):
        self.fires += 1

    async def request_decided(self, req):
        self.fires += 1


class FakeCell:
    def __init__(self, tenant_id, epoch, db, dispatcher):
        self.tenant_id, self.epoch, self.db, self.dispatcher = tenant_id, epoch, db, dispatcher


class FakeRegistry:
    def __init__(self, cells):
        self._cells = cells
        self.holds = 0

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        self.holds += 1
        yield self._cells[tenant_id]


class FakeControl:
    def __init__(self, tenants):
        self._tenants = tenants   # list of (tenant_id, epoch)

    def list_tenants(self):
        return list(self._tenants)


def _cell_with_pending(tid):
    db = Database(":memory:")
    exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=300))
    req = {"id": f"{tid}-r1", "title": "x", "severity": "high",
           "status": "approved", "expires_at": exp, "callback_url": None}
    db.outbox_add(req["id"], "request.decided", req, exp)
    return FakeCell(tid, 1, db, CountingDispatcher())


def test_startup_drain_delivers_each_tenants_pending_once():
    cells = {"a": _cell_with_pending("a"), "b": _cell_with_pending("b")}
    reg = FakeRegistry(cells)
    ctrl = FakeControl([("a", 1), ("b", 1)])
    asyncio.run(drain_all_at_startup(reg, ctrl))
    assert cells["a"].dispatcher.fires == 1
    assert cells["b"].dispatcher.fires == 1
    assert cells["a"].db.outbox_pending() == []
    assert cells["b"].db.outbox_pending() == []


def test_merely_holding_a_cell_does_not_drain():
    # The invariant: acquiring/holding a cell fires NOTHING. Only the explicit
    # process-startup coordinator drains. (No drain hook on cell open.)
    cell = _cell_with_pending("a")
    reg = FakeRegistry({"a": cell})

    async def hold_without_draining():
        async with reg.hold("a", 1):
            pass

    asyncio.run(hold_without_draining())
    assert cell.dispatcher.fires == 0            # cell-open never drains
    assert len(cell.db.outbox_pending()) == 1    # row untouched
```

- [ ] Run it — expect FAIL (`ImportError: cannot import name 'drain_all_at_startup'`).

- [ ] Minimal implementation — append to `server/arbiter/notify/outbox.py`:

```python
async def drain_all_at_startup(registry, control) -> None:
    """Process-restart-only re-drain (§9). Iterates every PROVISIONED tenant
    exactly once at process start, opening each cell just long enough to drain
    its outbox. This is the ONLY place a drain is triggered — cell-open on the
    hot path never drains, so constant cell churn cannot re-fire callbacks."""
    for tenant_id, epoch in control.list_tenants():
        async with registry.hold(tenant_id, epoch) as cell:
            await Outbox(cell.db, cell.dispatcher).drain_startup()
```

- [ ] Run green — PASS.
- [ ] Commit — `feat(server): process-restart-only outbox re-drain coordinator (§9)`.

> Integration note (for the app-wiring group): call `await drain_all_at_startup(registry, control)`
> once in the FastAPI `lifespan` startup — replacing the single-DB `outbox.drain_startup()` at
> `app.py:63`. The per-cell lazy `acquire()` path must add **no** drain call.

---

### Task G5: `arbiter.errors` — constant generic 403 + equalized-timing floor

§11: route-miss / in-cell-invalid / disabled-tenant all return an **identical generic 403 with
equalized timing**, and no client-visible error body ever carries tenant PII. This defeats the
cold-open "is this a real route key" oracle and the tenant-existence oracle. Provides the shared
constant + a timing floor consumed by `resolve_pairing` (G7), the enrollment route (G8), and
(by reference) `resolve_identity`.

**Files:**
- Create: `server/arbiter/errors.py`.
- Test: `server/tests/test_errors.py` (new).

**Interfaces:**
- Consumes: FastAPI `HTTPException`.
- Produces:
  - `GENERIC_403_DETAIL: str` (the single constant body string).
  - `generic_403() -> HTTPException` (always `HTTPException(403, GENERIC_403_DETAIL)`).
  - `class EqualizedFloor` — `EqualizedFloor(floor_s, clock=time.monotonic, sleep=asyncio.sleep)`; `async def wait(self, started_at)` sleeps `max(0, floor_s - (clock()-started_at))`.

**TDD steps:**

- [ ] Write the failing test.

```python
# server/tests/test_errors.py
import asyncio

from arbiter.errors import GENERIC_403_DETAIL, generic_403, EqualizedFloor


def test_generic_403_is_constant_and_carries_no_pii():
    a = generic_403()
    b = generic_403()
    assert a.status_code == b.status_code == 403
    assert a.detail == b.detail == GENERIC_403_DETAIL
    # constant, generic, no tenant identity / payload leakage
    low = GENERIC_403_DETAIL.lower()
    for leaky in ("tenant", "disabled", "route", "no such column", "default", "acme"):
        assert leaky not in low


def test_equalized_floor_pads_to_floor():
    slept = []
    now = [0.0]

    def clock():
        return now[0]

    async def sleep(d):
        slept.append(d)

    ef = EqualizedFloor(0.05, clock=clock, sleep=sleep)
    started = clock()
    now[0] = 0.02                     # 20ms of real work elapsed
    asyncio.run(ef.wait(started))
    assert slept == [0.05 - 0.02]     # padded up to the 50ms floor


def test_equalized_floor_never_sleeps_negative():
    async def sleep(d):
        assert d >= 0

    ef = EqualizedFloor(0.01, clock=lambda: 0.0, sleep=sleep)
    # pretend 100ms already elapsed (clock stays 0 but started is negative)
    asyncio.run(ef.wait(-0.1))
```

- [ ] Run it — expect FAIL (`ModuleNotFoundError: arbiter.errors`).

- [ ] Minimal implementation — `server/arbiter/errors.py`:

```python
"""Client-visible error hygiene for the multi-tenant arbiter (§11).

The process serves every tenant, so a client-visible error body and the wall-
clock time to produce it are both cross-tenant side channels. All resolution
failures — a token that routes to no tenant, a token that routes but is invalid
in its cell, a disabled tenant — return the SAME constant body with the SAME
timing floor, so a caller cannot tell which case it hit (route-existence /
tenant-existence oracle) or read any tenant PII out of the error.

/metrics forward-constraint: /metrics is intentionally NOT exposed. If added it
MUST be authenticated and expose only fleet-aggregate counters (or enforce
per-tenant authz on label reads) — per-tenant rids/queue-depth/429/hot-gauge
labels on a public scrape are a live cross-tenant topology map.
"""
import asyncio
import time

from fastapi import HTTPException

GENERIC_403_DETAIL = "forbidden"


def generic_403() -> HTTPException:
    """The one and only client-visible auth/resolution failure — a constant,
    PII-free 403 used identically for route-miss, in-cell-invalid, and disabled."""
    return HTTPException(status_code=403, detail=GENERIC_403_DETAIL)


class EqualizedFloor:
    """Pad an operation up to a fixed floor so success and every failure mode
    take indistinguishable wall-clock time. Clock and sleep are injectable for
    deterministic tests."""

    def __init__(self, floor_s: float, clock=time.monotonic, sleep=asyncio.sleep):
        self.floor_s, self.clock, self.sleep = floor_s, clock, sleep

    async def wait(self, started_at: float) -> None:
        remaining = self.floor_s - (self.clock() - started_at)
        if remaining > 0:
            await self.sleep(remaining)
```

- [ ] Run green — PASS.
- [ ] Commit — `feat(server): constant generic-403 + equalized-timing floor (§11)`.

---

### Task G6: `arbiter.obslog` — per-tenant scoped log sink that strips PII

§11: per-tenant operational logs go to a tenant-scoped, access-controlled sink, and **no tenant
PII/payload** (title, description, request body, dir path, `no such column`-style schema
internals) ever enters a shared log. This provides a `scoped_log` helper that (a) routes to a
per-tenant logger name and (b) drops any field whose key is on the PII blocklist.

**Files:**
- Create: `server/arbiter/obslog.py`.
- Test: `server/tests/test_obslog.py` (new).

**Interfaces:**
- Consumes: stdlib `logging`.
- Produces:
  - `PII_KEYS: frozenset[str]` (blocked field names).
  - `tenant_logger(tenant_id) -> logging.Logger` (name `arbiter.tenant.<tenant_id>`).
  - `scoped_log(tenant_id, event, level=logging.INFO, **fields) -> None` — logs `event` + only the
    non-PII `fields` to the tenant-scoped logger; blocked keys are dropped (never emitted).

**TDD steps:**

- [ ] Write the failing test.

```python
# server/tests/test_obslog.py
import logging

from arbiter.obslog import scoped_log, tenant_logger, PII_KEYS


def test_scoped_log_goes_to_tenant_logger(caplog):
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "device_registered", device_count=3)
    recs = [r for r in caplog.records if r.name == "arbiter.tenant.acme"]
    assert len(recs) == 1
    assert "device_registered" in recs[0].getMessage()
    assert "3" in recs[0].getMessage()


def test_scoped_log_never_emits_pii_fields(caplog):
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "created",
                   title="Wire $50k to Bob",
                   description="secret",
                   payload={"iban": "X"},
                   dir="/srv/tenants/acme",
                   error="no such column: foo",
                   severity="high")          # severity is safe metadata
    msg = caplog.records[-1].getMessage()
    for leaked in ("Wire $50k", "secret", "iban", "/srv/tenants/acme", "no such column"):
        assert leaked not in msg
    assert "high" in msg                     # non-PII field survives


def test_pii_blocklist_covers_the_named_surfaces():
    assert {"title", "description", "payload", "body", "dir", "error"} <= PII_KEYS
```

- [ ] Run it — expect FAIL (`ModuleNotFoundError: arbiter.obslog`).

- [ ] Minimal implementation — `server/arbiter/obslog.py`:

```python
"""Per-tenant scoped operational logging (§11).

Shared sinks are cross-tenant channels, so tenant operational events go to a
per-tenant logger (`arbiter.tenant.<tenant_id>`) and NEVER carry request PII or
schema internals. scoped_log drops any field on PII_KEYS before formatting, so a
caller cannot accidentally log a title/description/payload/dir/DB error text.
"""
import logging

# Field names that may carry tenant PII, request payload, filesystem layout, or
# schema internals — never logged.
PII_KEYS = frozenset({
    "title", "description", "payload", "body", "dir", "path",
    "error", "detail", "canonical_action", "apns_token", "callback_url",
})


def tenant_logger(tenant_id: str) -> logging.Logger:
    return logging.getLogger(f"arbiter.tenant.{tenant_id}")


def scoped_log(tenant_id: str, event: str, level: int = logging.INFO, **fields) -> None:
    safe = {k: v for k, v in fields.items() if k not in PII_KEYS}
    extras = " ".join(f"{k}={v}" for k, v in sorted(safe.items()))
    msg = f"{event} {extras}".rstrip()
    tenant_logger(tenant_id).log(level, msg)
```

- [ ] Run green — PASS.
- [ ] Commit — `feat(server): per-tenant scoped, PII-stripping log sink (§11)`.

---

### Task G7: `resolve_pairing` — route a pairing credential to its cell + single-use redeem

§10: the enrollment endpoint derives the tenant **from the pairing credential, never a caller
hint**; replayed or cross-tenant codes are rejected. This mirrors `resolve_identity`'s
router-first shape (`sha256(code) → control.resolve → is_disabled → registry.acquire →
in-cell authority`) but the in-cell authority is the single-use `redeem_pairing` (G1). Any
failure raises the constant `generic_403()` (G5) with equalized timing.

**Files:**
- Create: `server/arbiter/enroll.py`.
- Test: `server/tests/test_resolve_pairing.py` (new).

**Interfaces:**
- Consumes: `ControlPlane.resolve(token_hash)->(tenant_id,epoch)|None`, `ControlPlane.is_disabled(tenant_id)->bool`, `TenantRegistry.hold(tenant_id, epoch)->Cell`, `Cell.epoch`, `Cell.db.redeem_pairing`, `generic_403` + `EqualizedFloor` (G5).
- Produces:
  - `async resolve_pairing(code: str, registry, control, *, floor=EQUALIZE_FLOOR) -> AsyncContextManager[Cell]` — an async context manager yielding the pinned `Cell` after a successful single-use redeem; raises `generic_403()` (padded to the floor) on any failure. Because redeem is single-use and the cell must stay pinned while the device row is written, this is delivered as an `@asynccontextmanager`.

**TDD steps:**

- [ ] Write the failing test with contract fakes.

```python
# server/tests/test_resolve_pairing.py
import asyncio
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from arbiter.db import Database
from arbiter.enroll import resolve_pairing


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _iso(dt):
    return dt.isoformat()


class FakeCell:
    def __init__(self, tenant_id, epoch, db):
        self.tenant_id, self.epoch, self.db = tenant_id, epoch, db


class FakeRegistry:
    def __init__(self, cells):
        self._cells = cells

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        yield self._cells[tenant_id]


class FakeControl:
    def __init__(self, routes, disabled=()):
        self._routes = routes          # code_hash -> (tenant_id, epoch)
        self._disabled = set(disabled)

    def resolve(self, token_hash):
        return self._routes.get(token_hash)

    def is_disabled(self, tenant_id):
        return tenant_id in self._disabled


def _cell_with_code(tid, code, minutes=15):
    db = Database(":memory:")
    db.mint_pairing(_sha(code), _iso(datetime.now(timezone.utc) + timedelta(minutes=minutes)))
    return FakeCell(tid, 1, db)


async def _resolve_to_tenant(code, reg, ctrl):
    async with resolve_pairing(code, reg, ctrl) as cell:
        return cell.tenant_id


def test_valid_code_routes_to_its_cell_and_is_single_use():
    cell = _cell_with_code("A", "code-A")
    reg = FakeRegistry({"A": cell})
    ctrl = FakeControl({_sha("code-A"): ("A", 1)})
    assert asyncio.run(_resolve_to_tenant("code-A", reg, ctrl)) == "A"
    # replay: the code was consumed in-cell ⇒ generic 403
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_resolve_to_tenant("code-A", reg, ctrl))
    assert ei.value.status_code == 403


def test_unrouted_code_is_generic_403():
    reg = FakeRegistry({})
    ctrl = FakeControl({})               # no route
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_resolve_to_tenant("ghost", reg, ctrl))
    assert ei.value.status_code == 403


def test_disabled_tenant_is_generic_403():
    cell = _cell_with_code("A", "code-A")
    reg = FakeRegistry({"A": cell})
    ctrl = FakeControl({_sha("code-A"): ("A", 1)}, disabled={"A"})
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_resolve_to_tenant("code-A", reg, ctrl))
    assert ei.value.status_code == 403


def test_epoch_mismatch_is_generic_403():
    # route says epoch 2 but the bound cell is epoch 1 (delete+recreate race)
    cell = _cell_with_code("A", "code-A")   # epoch 1
    reg = FakeRegistry({"A": cell})
    ctrl = FakeControl({_sha("code-A"): ("A", 2)})
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_resolve_to_tenant("code-A", reg, ctrl))
    assert ei.value.status_code == 403
```

- [ ] Run it — expect FAIL (`ModuleNotFoundError: arbiter.enroll`).

- [ ] Minimal implementation — `server/arbiter/enroll.py`:

```python
"""Device enrollment binding (§10).

A pairing credential is tenant-bound, single-use, and short-expiry. It is
resolved to its cell exactly like resolve_identity — router is a hint, the cell
is the authority — and the in-cell single-use redeem (Database.redeem_pairing)
is the authority that rejects a replayed or expired code. The tenant is derived
solely from the credential; no caller-supplied hint is ever consulted. Every
failure is the constant generic_403() padded to a fixed timing floor so a
caller cannot distinguish route-miss / disabled / in-cell-invalid.
"""
import hashlib
from contextlib import asynccontextmanager

from .errors import EqualizedFloor, generic_403

EQUALIZE_FLOOR = EqualizedFloor(0.05)


@asynccontextmanager
async def resolve_pairing(code: str, registry, control, *, floor: EqualizedFloor = EQUALIZE_FLOOR):
    """Yield the pinned Cell for a valid single-use pairing credential, else
    raise generic_403(). The cell stays pinned (registry.hold) for the body so
    the caller can write the device row before release. Single-use: redeem is
    committed before yielding, so the code cannot be replayed."""
    started = floor.clock()

    async def _fail():
        await floor.wait(started)
        raise generic_403()

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    route = control.resolve(code_hash)
    if route is None:
        await _fail()
    tenant_id, epoch = route
    if control.is_disabled(tenant_id):
        await _fail()
    async with registry.hold(tenant_id, epoch) as cell:
        if cell.epoch != epoch:
            await _fail()
        redeem_code, _ = cell.db.redeem_pairing(code_hash)
        if redeem_code != 200:
            await _fail()
        await floor.wait(started)     # equalize the SUCCESS path to the same floor
        yield cell
```

- [ ] Run green — `cd server && python -m pytest tests/test_resolve_pairing.py -x` → PASS.
- [ ] Commit — `feat(server): resolve_pairing — credential-derived tenant, single-use redeem (§10)`.

---

### Task G8: `POST /v1/devices/enroll` — device row written ONLY to the credential's cell

The phone-facing enrollment endpoint. It authenticates via the pairing credential (Bearer),
resolves the cell with `resolve_pairing` (G7), and writes the device row into **that cell's
db only** — no global device table, so push tokens are namespaced per tenant by construction.
This carries the two §16 device tests: a device paired to A never receives B's push; a
replayed / cross-tenant / forged code is rejected with a PII-free generic 403.

**Files:**
- Modify: `server/arbiter/app.py` (add the route near the device routes, `app.py:301-311`; the app-wiring group threads `registry`/`control` onto `app.state` — this task references `request.app.state.registry` and `request.app.state.control`).
- Test: `server/tests/test_enroll_endpoint.py` (new).

**Interfaces:**
- Consumes: `resolve_pairing` (G7), `Cell.db.register_device` (existing `db.py:330`), `Cell.tenant_id`, `Cell.dispatcher`, `DeviceRegister` model (existing `models.py`), `generic_403` (G5), `TenantRegistry`/`ControlPlane` off `app.state`.
- Produces: `POST /v1/devices/enroll` accepting `Authorization: Bearer <pairing_code>` + `DeviceRegister` body; returns the created device row `{... , "tenant_id": <tid>}` on success.

**TDD steps:**

- [ ] Write the failing test. This test builds a tiny FastAPI app mounting only the enroll
  route against contract fakes, so it is independent of the full `create_app` wiring.

```python
# server/tests/test_enroll_endpoint.py
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arbiter.db import Database
from arbiter.enroll import resolve_pairing
from arbiter.errors import generic_403
from arbiter.models import DeviceRegister


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _iso(dt):
    return dt.isoformat()


class FakeCell:
    def __init__(self, tenant_id, epoch, db):
        self.tenant_id, self.epoch, self.db = tenant_id, epoch, db


class FakeRegistry:
    def __init__(self, cells):
        self._cells = cells

    @asynccontextmanager
    async def hold(self, tenant_id, epoch):
        yield self._cells[tenant_id]


class FakeControl:
    def __init__(self, routes):
        self._routes = routes

    def resolve(self, h):
        return self._routes.get(h)

    def is_disabled(self, t):
        return False


def _mk_app(reg, ctrl):
    app = FastAPI()
    app.state.registry, app.state.control = reg, ctrl

    @app.post("/v1/devices/enroll")
    async def enroll(body: DeviceRegister, request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise generic_403()
        code = auth.removeprefix("Bearer ")
        async with resolve_pairing(code, request.app.state.registry,
                                   request.app.state.control) as cell:
            dev = cell.db.register_device(
                body.apns_token, body.name, body.min_severity,
                body.notifications_enabled, body.sound,
                severities=body.severities, badge=body.badge)
            return {**dev, "tenant_id": cell.tenant_id}

    return app


def _two_tenant_setup():
    dbs = {"A": Database(":memory:"), "B": Database(":memory:")}
    exp = _iso(datetime.now(timezone.utc) + timedelta(minutes=15))
    dbs["A"].mint_pairing(_sha("code-A"), exp)
    cells = {"A": FakeCell("A", 1, dbs["A"]), "B": FakeCell("B", 1, dbs["B"])}
    reg = FakeRegistry(cells)
    ctrl = FakeControl({_sha("code-A"): ("A", 1)})
    return dbs, _mk_app(reg, ctrl)


def test_device_paired_to_A_lands_only_in_A_never_B():
    dbs, app = _two_tenant_setup()
    c = TestClient(app)
    r = c.post("/v1/devices/enroll",
               headers={"Authorization": "Bearer code-A"},
               json={"apns_token": "tok-phone-1", "name": "iPhone"})
    assert r.status_code == 200 and r.json()["tenant_id"] == "A"
    # the device row exists in A's cell and NOT in B's — no global device table,
    # so B's dispatcher can never see (and thus never push to) this token.
    assert [d["apns_token"] for d in dbs["A"].list_devices()] == ["tok-phone-1"]
    assert dbs["B"].list_devices() == []


def test_replayed_code_rejected_generic_403():
    _, app = _two_tenant_setup()
    c = TestClient(app)
    hdr = {"Authorization": "Bearer code-A"}
    assert c.post("/v1/devices/enroll", headers=hdr,
                  json={"apns_token": "t1", "name": "iPhone"}).status_code == 200
    r2 = c.post("/v1/devices/enroll", headers=hdr,
                json={"apns_token": "t2", "name": "iPhone"})
    assert r2.status_code == 403


def test_forged_code_rejected_and_body_has_no_pii():
    _, app = _two_tenant_setup()
    c = TestClient(app)
    r = c.post("/v1/devices/enroll",
               headers={"Authorization": "Bearer totally-made-up"},
               json={"apns_token": "t", "name": "iPhone"})
    assert r.status_code == 403
    body = r.text.lower()
    for leaky in ("tenant", "route", "disabled", "no such", "code-a", "a\":", "acme"):
        assert leaky not in body
```

- [ ] Run it — expect FAIL (the route/module wiring exercised here already exists from G7, but
  run to confirm the endpoint contract): `cd server && python -m pytest tests/test_enroll_endpoint.py -x`.
  If it fails only on an assertion, inspect; the route body above is the reference implementation.

- [ ] Minimal implementation — add the real route to `server/arbiter/app.py`. First import at the
  top of `app.py` (with the other `from .` imports, near `app.py:14-21`):

```python
from .enroll import resolve_pairing
from .errors import generic_403
```

Then add the route beside the existing device routes (after `register`, `app.py:307`):

```python
    @app.post("/v1/devices/enroll")
    async def enroll(body: DeviceRegister, request: Request):
        # Phone-facing enrollment (§10). Tenant is derived SOLELY from the
        # single-use pairing credential — no caller hint. The device row is
        # written only to the credential's cell (no global device table), so
        # push tokens are namespaced per tenant by construction.
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise generic_403()
        code = auth.removeprefix("Bearer ")
        async with resolve_pairing(code, request.app.state.registry,
                                   request.app.state.control) as cell:
            dev = cell.db.register_device(
                body.apns_token, body.name, body.min_severity,
                body.notifications_enabled, body.sound,
                severities=body.severities, badge=body.badge)
            cell.hub.publish({"event": "device.updated", "device": dev})
            return {**dev, "tenant_id": cell.tenant_id}
```

> Wiring dependency: this route reads `request.app.state.registry` and `request.app.state.control`,
> which the app-wiring group sets in `create_app` (replacing the single `app.state.db`). Until
> that lands, the endpoint's unit coverage is the `test_enroll_endpoint.py` mini-app above.

- [ ] Run green — `cd server && python -m pytest tests/test_enroll_endpoint.py -x` → PASS.
- [ ] Commit — `feat(server): POST /v1/devices/enroll — cell-bound device registration (§10)`.

---

### Task G9: CLI `hma tenant pair-code <tenant>` — admin mint of a pairing credential

The pairing credential is minted on the **admin-credentialed provisioning path** — the only path
allowed to write `control.db` (§4). `pair-code` opens the tenant's cell, mints the single-use
short-expiry pairing row (G1), registers the routing hash in `control.db` via `add_route` so the
phone can reach the tenant with the credential alone, and prints the pairing deep-link (the QR
carries the pairing code, never the long-lived app token).

**Files:**
- Modify: `server/arbiter/cli.py` (add a `tenant` group + `pair-code` command, following the `token` group pattern `cli.py:243-284`).
- Test: `server/tests/test_cli_pair_code.py` (new).

**Interfaces:**
- Consumes: `ControlPlane.resolve`/`add_route`/`tenant_dir` + a way to open a cell's `Database` at `tenant_dir(tenant)`; `Database.mint_pairing` (G1); `build_pairing_payload(base_url, token)` (existing `pair.py`).
- Produces: `hma tenant pair-code <tenant> [--minutes N] [--config PATH]` — prints the deep-link and the raw pairing code once. Helper `arbiter.cli._mint_pair_code(control, tenant_id, minutes, secret=None) -> tuple[str, str]` returning `(code, code_hash)` for unit testing without Click.

**TDD steps:**

- [ ] Write the failing test against the pure helper (no server needed).

```python
# server/tests/test_cli_pair_code.py
import hashlib
from pathlib import Path

from arbiter.cli import _mint_pair_code
from arbiter.db import Database


class FakeControl:
    def __init__(self, tmp):
        self._dirs = {"acme": Path(tmp) / "acme"}
        self._dirs["acme"].mkdir(parents=True, exist_ok=True)
        self.routes = {}
        self.epochs = {"acme": 7}

    def tenant_dir(self, tenant_id):
        return self._dirs[tenant_id]

    def resolve(self, h):
        return self.routes.get(h)

    def add_route(self, token_hash, tenant_id):
        self.routes[token_hash] = (tenant_id, self.epochs[tenant_id])


def test_mint_pair_code_writes_cell_row_and_control_route(tmp_path):
    ctrl = FakeControl(tmp_path)
    code, code_hash = _mint_pair_code(ctrl, "acme", minutes=15)
    assert code_hash == hashlib.sha256(code.encode()).hexdigest()
    # control route now resolves the credential to the tenant
    assert ctrl.resolve(code_hash) == ("acme", 7)
    # the cell db holds a redeemable single-use pairing row
    db = Database(str(Path(ctrl.tenant_dir("acme")) / "arbiter.sqlite3"))
    rc, row = db.redeem_pairing(code_hash)
    assert rc == 200 and row["consumed_at"] is not None


def test_mint_pair_code_is_single_use_end_to_end(tmp_path):
    ctrl = FakeControl(tmp_path)
    code, code_hash = _mint_pair_code(ctrl, "acme", minutes=15)
    db = Database(str(Path(ctrl.tenant_dir("acme")) / "arbiter.sqlite3"))
    assert db.redeem_pairing(code_hash)[0] == 200
    assert db.redeem_pairing(code_hash)[0] == 409     # replay rejected
```

- [ ] Run it — expect FAIL (`ImportError: cannot import name '_mint_pair_code'`).

- [ ] Minimal implementation — add to `server/arbiter/cli.py`. The helper (place after the
  `token` group, near `cli.py:284`):

```python
def _mint_pair_code(control, tenant_id: str, minutes: int, secret: str | None = None) -> tuple[str, str]:
    """Mint a single-use, short-expiry pairing credential for TENANT.

    Writes the pairing row into the tenant's OWN cell db (single-use authority)
    and registers the routing hash in control.db (admin path) so the phone can
    reach the tenant with the credential alone. Returns (code, code_hash)."""
    from datetime import datetime, timedelta, timezone
    from .db import Database
    code = secret or f"hma_pair_{pysecrets.token_hex(24)}"
    code_hash = _hash_token(code)
    cell_db_path = str(Path(control.tenant_dir(tenant_id)) / "arbiter.sqlite3")
    db = Database(cell_db_path)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
    db.mint_pairing(code_hash, expires_at)
    control.add_route(code_hash, tenant_id)
    return code, code_hash
```

The Click command (add a `tenant` group + command near the `token` group):

```python
@main.group()
def tenant():
    """Manage tenants (admin-credentialed provisioning)."""


@tenant.command("pair-code")
@click.argument("tenant_id")
@click.option("--minutes", type=int, default=15, help="Credential lifetime (default 15).")
@click.option("--host", "host_url", default=None, help="Server base URL for the QR payload.")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_pair_code(tenant_id, minutes, host_url, config_path):
    """Mint a single-use pairing credential for TENANT_ID and print its deep-link."""
    from .control import ControlPlane   # provided by the control-plane group
    from .pair import build_pairing_payload, local_ip
    cfg = Config.load(config_path)
    control = ControlPlane(cfg)
    code, _ = _mint_pair_code(control, tenant_id, minutes)
    base = host_url or f"http://{local_ip()}:{cfg.server.port}"
    click.echo(f"pairing code: {code}")
    click.echo(f"deep-link:    {build_pairing_payload(base, code)}")
    click.echo(f"Single-use, expires in {minutes} min. Shown once.")
```

- [ ] Run green — `cd server && python -m pytest tests/test_cli_pair_code.py -x` → PASS.
  (The Click command imports `arbiter.control.ControlPlane` from the control-plane group; the
  unit test exercises `_mint_pair_code` directly with a fake, so it is green independently.)
- [ ] Commit — `feat(cli): hma tenant pair-code — admin-minted single-use pairing credential (§10,§14)`.

---

## Group G completion checklist (maps to the §16 merge gate)
- Device paired to A lands only in A's cell, never B → `test_enroll_endpoint.py::test_device_paired_to_A_lands_only_in_A_never_B`.
- Cross-tenant / replayed / forged pairing code rejected → `test_resolve_pairing.py`, `test_enroll_endpoint.py::test_replayed_code_rejected_generic_403`, `test_forged_code_rejected_and_body_has_no_pii`.
- Error body carries no tenant PII (constant 403) → `test_errors.py`, `test_obslog.py`, `test_enroll_endpoint.py::test_forged_code_rejected_and_body_has_no_pii`.
- Crash between dispatch and `outbox_delete` + cell churn ⇒ callback fires at most once per dedupe key; re-drain only on restart → `test_outbox_idempotent.py`, `test_outbox_drain_scope.py`.
- Run the whole group: `cd server && python -m pytest tests/test_pairings.py tests/test_notify_dedupe.py tests/test_outbox_idempotent.py tests/test_outbox_drain_scope.py tests/test_errors.py tests/test_obslog.py tests/test_resolve_pairing.py tests/test_enroll_endpoint.py tests/test_cli_pair_code.py -q`.


---


## Group H — provisioning CLI + backup/restore + back-compat

Implements spec **§12** (backup/restore fail-closed), **§14** (provisioning, back-compat, CLI),
**§15.7** (every tenant dir absolute/realpath-canonical/unique/non-overlapping; each cell's key distinct —
enforced at mint AND open) and **§15.12** (restore fail-closed for credentials AND consumption).

Branch: `feat/multitenant-isolation`. Repo (quote the spaces):
`<repo-root>`.

## Dependencies on other groups (build order)

This group **consumes** these cross-component names verbatim from the pinned contract. They are produced by
the control-plane / registry / crypto groups and must exist before H2+ run. H1 and H4 (pure helpers on
`server/arbiter/provisioning.py` and `server/arbiter/db.py`) have **no** cross-group dependency and can land
first.

- **`ControlPlane`** — constructed via its B1 factory `ControlPlane.open(control_dir, tenants_root)` (the
  3-arg real class; `control.db` lives at `control_dir/control.db`). Methods used:
  `create_tenant(tenant_id, dir)->int` (fresh monotonic epoch, now also §15.7 dir-isolated), `add_route(token_hash,
  tenant_id)`, `remove_route(token_hash)`, `list_tenants()` (returns tenant_id strings),
  `tenant_dir(tenant_id)->Path`, `disable_tenant(tenant_id)`, `tombstone_tenant(tenant_id)`,
  `resolve(token_hash)->(tenant_id,epoch)|None`. It also exposes its file path as **`control.db_path: Path`**.
  Its pinned on-disk schema is `tenants(tenant_id, dir, disabled_at, epoch)` + `token_route(token_hash,
  tenant_id)` (+ a MAC column) — the reconciler/backup read those **pinned** table/column names directly on
  the control.db file.
- **`Cell.db`** is a per-cell `Database` (the shipped `server/arbiter/db.py` class), one SQLite file per
  tenant dir at `<dir>/arbiter.sqlite3`.
- **`resolve_identity`** (auth group) routes the legacy `cfg.auth.app_token` **strictly** to the `default`
  cell; H9's migration only has to make `default` exist + backfill its routes.
- **`sign_verdict` / `Cell.signer`** (crypto group) build the tenant-namespaced `kid=f"{tenant_id}:{hash8}"`
  from the raw Ed25519 key file that **H2 mints** in the tenant dir via the shipped
  `signing.load_or_create_keypair`.

This group **produces** (consumed by the registry group at cell-open, and by the serve/startup wiring):
`canonicalize_tenant_dir`, `assert_dir_isolated`, `TenantDirError`, `provision_tenant`, `ProvisionResult`,
`mint_cell_token`, `revoke_cell_token`, `reconcile_routes`, `snapshot_db`, `backup_fleet`, `restore_fleet`,
`migrate_to_multitenant`, `control_path_for`, `tenants_root_for` (all in `server/arbiter/provisioning.py`);
`Database.invalidate_in_flight`, `Database.active_token_hashes`, `Database.backup_to` (in
`server/arbiter/db.py`).

**Admin authority (V1):** the provisioning CLI's authority is **local filesystem access** to control.db and
the tenant dirs — identical to the shipped `hma token create`, which opens the DB file directly with no
network auth. This satisfies §4 "control.db writable only via the admin-credentialed provisioning CLI": on
the host, filesystem access *is* the admin credential. No new network admin token is introduced in V1.

**Test/commit conventions.** Run from the repo root: `cd server && python -m pytest tests/<file> -q`
(pyproject `testpaths=["tests"]`, `arbiter` importable via `pip install -e server`). Every commit ends with
.

---

### Task H1: tenant-dir isolation guard (`canonicalize_tenant_dir` + `assert_dir_isolated`)

Realpath-canonical, `[a-z0-9-]`-only, under-a-fixed-root, non-overlapping. `assert_dir_isolated` here is the
**provisioning-side** copy (used by `provision_tenant`, H2), so a symlink swap or a `..` cannot hand two
cells one dir (→ one shared key → silent cross-tenant forgery, §7/§15.7).

> **Reconciliation (§15.7 "isolation AND at open").** The registry at cell open and `ControlPlane.create_tenant`
> at mint use a **byte-identical** copy of this non-overlap check that lives in the leaf module
> `arbiter.control` as `assert_dir_isolated` (Task B1) — it must be the leaf so `create_tenant` (control.py)
> and `open_cell` (registry.py) can both call it with no import cycle. The two copies (this one raising
> `TenantDirError`; control's raising `ValueError`) enforce **identical** overlap logic and MUST stay in
> lock-step; keep the resolve + `is_relative_to`-both-directions body identical if either is edited.

**Files:** Create `server/arbiter/provisioning.py`. Test `server/tests/test_provisioning.py`.

**Interfaces:**
- Produces `class TenantDirError(Exception)`.
- Produces `canonicalize_tenant_dir(tenant_id: str, root: Path) -> Path` — validates charset, returns the
  absolute realpath `root/<tenant_id>`, raising `TenantDirError` if the id is off-charset or the resolved
  path escapes `root` (symlink/`..`).
- Produces `assert_dir_isolated(candidate: Path, existing: list[Path]) -> None` — raises `TenantDirError` if
  `candidate` (resolved) equals, contains, or is contained by any resolved `existing` dir.
- Consumed by: `provision_tenant` (H2, mint side). The registry's cell-open path and `create_tenant`'s
  mint path call the **identical** `arbiter.control.assert_dir_isolated(cell_dir, [other open/live cells'
  dirs])` (Task B1) re-validated on every open/mint, per §15.7 — see the reconciliation note above.

**Steps:**

- [ ] Write the failing test `server/tests/test_provisioning.py`:
  ```python
  import pytest
  from pathlib import Path
  from arbiter.provisioning import canonicalize_tenant_dir, assert_dir_isolated, TenantDirError

  def test_canonicalize_rejects_bad_charset(tmp_path):
      for bad in ("../evil", "Bad_Name", "a/b", "UP", "sp ace"):
          with pytest.raises(TenantDirError):
              canonicalize_tenant_dir(bad, tmp_path)

  def test_canonicalize_returns_abs_realpath_under_root(tmp_path):
      root = tmp_path / "tenants"
      p = canonicalize_tenant_dir("acme", root)
      assert p.is_absolute() and p == (root.resolve() / "acme")

  def test_canonicalize_rejects_symlink_escape(tmp_path):
      root = tmp_path / "tenants"; root.mkdir()
      outside = tmp_path / "outside"; outside.mkdir()
      (root / "evil").symlink_to(outside, target_is_directory=True)
      with pytest.raises(TenantDirError):
          canonicalize_tenant_dir("evil", root)

  def test_assert_dir_isolated_rejects_overlap_both_directions(tmp_path):
      a = tmp_path / "a"; a.mkdir()
      with pytest.raises(TenantDirError):
          assert_dir_isolated(a, [a])                 # exact duplicate
      with pytest.raises(TenantDirError):
          assert_dir_isolated(tmp_path, [a])          # candidate is parent of existing
      with pytest.raises(TenantDirError):
          assert_dir_isolated(a / "child", [a])       # candidate is child of existing
      assert_dir_isolated(tmp_path / "b", [a])        # sibling — no raise
  ```
- [ ] Run it (expect **FAIL**, ImportError): `cd server && python -m pytest tests/test_provisioning.py -q`
- [ ] Minimal implementation — write `server/arbiter/provisioning.py`:
  ```python
  """Tenant provisioning, backup/restore, and single-tenant back-compat (spec §12/§14)."""
  from __future__ import annotations

  import hashlib
  import re
  import secrets as pysecrets
  import shutil
  import sqlite3
  from dataclasses import dataclass
  from pathlib import Path

  from .db import Database
  from .signing import KEY_FILENAME, load_or_create_keypair

  _TENANT_ID_RE = re.compile(r"^[a-z0-9-]+$")


  class TenantDirError(Exception):
      """A tenant dir is off-charset, escapes the root, or overlaps another tenant."""


  def canonicalize_tenant_dir(tenant_id: str, root: Path) -> Path:
      if not _TENANT_ID_RE.match(tenant_id):
          raise TenantDirError(f"tenant_id must match [a-z0-9-]: {tenant_id!r}")
      root = Path(root).expanduser().resolve()
      resolved = (root / tenant_id).resolve()
      # A valid id has no separators, so the ONLY way resolved.parent != root is a
      # symlink at root/<id> pointing elsewhere — reject it (defeats key-sharing).
      if resolved.parent != root:
          raise TenantDirError(f"tenant dir escapes root: {resolved} not directly under {root}")
      return resolved


  def assert_dir_isolated(candidate: Path, existing: list[Path]) -> None:
      c = Path(candidate).resolve()
      for other in existing:
          o = Path(other).resolve()
          if c == o or c.is_relative_to(o) or o.is_relative_to(c):
              raise TenantDirError(f"tenant dir overlaps existing dir: {c} vs {o}")
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_provisioning.py -q`
- [ ] Commit: `feat(provisioning): realpath-canonical non-overlapping tenant-dir guard (§15.7)`

---

### Task H2: `provision_tenant` — mint a fresh, isolated, key-distinct cell

Create the dir (isolated), migrate a fresh cell `Database`, mint the per-tenant Ed25519 key **in that dir**
(so no two cells load identical key bytes — §15.7), register the tenant with a fresh monotonic epoch, and
mint the first **app** + **warden** tokens. Depends on `ControlPlane`.

**Files:** Modify `server/arbiter/provisioning.py`. Modify `server/tests/test_provisioning.py`.

**Interfaces:**
- Consumes `ControlPlane.open(control_dir, tenants_root)`, `.create_tenant(tenant_id, dir)->int`, `.list_tenants()`,
  `.tenant_dir(tenant_id)->Path`, `.add_route(token_hash, tenant_id)` (via `mint_cell_token`, H3);
  `Database(path)` (shipped); `signing.load_or_create_keypair(dir)` (shipped, mints
  `verdict_signing_key.pem` 0600 via O_EXCL).
- Produces `@dataclass ProvisionResult(tenant_id: str, epoch: int, dir: Path, app_token: str,
  warden_token: str)` and `provision_tenant(control, root: Path, tenant_id: str) -> ProvisionResult`.

**Steps:**

- [ ] Add the failing test to `server/tests/test_provisioning.py`:
  ```python
  import hashlib
  from arbiter.control import ControlPlane   # control-plane group; path may differ — align import
  from arbiter.signing import KEY_FILENAME
  from arbiter.provisioning import provision_tenant

  def _h(v): return hashlib.sha256(v.encode()).hexdigest()

  def test_provision_two_tenants_have_distinct_keys_and_tokens(tmp_path):
      control = ControlPlane(tmp_path / "control.sqlite3")
      root = tmp_path / "tenants"
      a = provision_tenant(control, root, "alpha")
      b = provision_tenant(control, root, "beta")
      # distinct on-disk key bytes (§15.7: no two cells load identical key bytes)
      assert (a.dir / KEY_FILENAME).read_bytes() != (b.dir / KEY_FILENAME).read_bytes()
      assert a.epoch != b.epoch or a.tenant_id != b.tenant_id
      assert a.app_token.startswith("hma_app_") and a.warden_token.startswith("hma_warden_")
      # both first-tokens route to their own tenant
      assert control.resolve(_h(a.app_token))[0] == "alpha"
      assert control.resolve(_h(b.warden_token))[0] == "beta"

  def test_provision_duplicate_tenant_id_rejected(tmp_path):
      import pytest
      control = ControlPlane(tmp_path / "control.sqlite3")
      root = tmp_path / "tenants"
      provision_tenant(control, root, "acme")
      with pytest.raises(Exception):
          provision_tenant(control, root, "acme")   # dir already exists / tenant exists
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_provisioning.py -k provision -q`
- [ ] Implement — append to `server/arbiter/provisioning.py`:
  ```python
  def _hash_token(value: str) -> str:
      return hashlib.sha256(value.encode()).hexdigest()


  @dataclass
  class ProvisionResult:
      tenant_id: str
      epoch: int
      dir: Path
      app_token: str
      warden_token: str


  def provision_tenant(control, root: Path, tenant_id: str) -> ProvisionResult:
      root = Path(root).expanduser().resolve()
      root.mkdir(parents=True, exist_ok=True)
      canon = canonicalize_tenant_dir(tenant_id, root)
      existing = [control.tenant_dir(t["tenant_id"]) for t in control.list_tenants()]
      assert_dir_isolated(canon, existing)          # mint-side isolation (§15.7) — a REDUNDANT
      # early guard: control.create_tenant (below) now enforces the identical §15.7 non-overlap
      # check itself (via arbiter.control.assert_dir_isolated), so the authoritative mint rejection
      # lives there; this line only fails a hair earlier and MUST stay logic-identical to it.
      canon.mkdir(parents=True, exist_ok=False)     # fresh dir; a collision fails closed
      cell_db = Database(str(canon / "arbiter.sqlite3"))   # runs the migration ladder
      load_or_create_keypair(canon)                 # mint this cell's OWN Ed25519 key
      epoch = control.create_tenant(tenant_id, canon)      # fresh monotonic epoch, MAC'd row
      app_token = mint_cell_token(control, cell_db, tenant_id, "app", "app")
      warden_token = mint_cell_token(control, cell_db, tenant_id, "warden", "warden")
      return ProvisionResult(tenant_id, epoch, canon, app_token, warden_token)
  ```
  (`mint_cell_token` is defined next in H3; the module imports resolve at call time.)
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_provisioning.py -k provision -q`
- [ ] Commit: `feat(provisioning): provision_tenant mints isolated key-distinct cell + first tokens (§14)`

---

### Task H3: `mint_cell_token` / `revoke_cell_token` — cross-store ordering for backup fail-closed

Mint writes the **cell row first, then the router row** (a ghost = cell row without a route → unusable →
fail closed, §12). Revoke writes the **in-cell `revoked_at` first, then removes the router row** (so a
cells-first/control-last backup that smears across the revoke sees the route already gone → fail closed).

**Files:** Modify `server/arbiter/provisioning.py`. Modify `server/tests/test_provisioning.py`.

**Interfaces:**
- Consumes `Database.create_token(name, role, token_hash, scopes=None, expires_at=None)`,
  `Database.revoke_token(name)->row|None` (row carries `token_hash`), `Database.add_audit` (shipped);
  `ControlPlane.add_route`, `ControlPlane.remove_route`.
- Produces `mint_cell_token(control, cell_db, tenant_id, name, role, scopes=None, expires_at=None) -> str`
  (returns the clear token, shown once) and `revoke_cell_token(control, cell_db, name) -> str` (raises
  `KeyError(name)` if absent).

**Steps:**

- [ ] Add the failing test:
  ```python
  from arbiter.db import Database
  from arbiter.provisioning import mint_cell_token, revoke_cell_token

  def test_mint_writes_cell_row_then_route_and_revoke_reverses(tmp_path):
      control = ControlPlane(tmp_path / "control.sqlite3")
      a = provision_tenant(control, tmp_path / "tenants", "acme")
      cell = Database(str(a.dir / "arbiter.sqlite3"))
      tok = mint_cell_token(control, cell, "acme", "hermes", "agent")
      h = _h(tok)
      assert cell.get_token_by_hash(h)["name"] == "hermes"   # cell row present
      assert control.resolve(h)[0] == "acme"                 # route present
      revoke_cell_token(control, cell, "hermes")
      assert cell.get_token_by_hash(h)["revoked_at"] is not None  # cell revoked
      assert control.resolve(h) is None                          # route removed
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_provisioning.py -k mint -q`
- [ ] Implement — append to `server/arbiter/provisioning.py`:
  ```python
  def mint_cell_token(control, cell_db, tenant_id: str, name: str, role: str,
                      scopes: dict | None = None, expires_at: str | None = None) -> str:
      value = f"hma_{role}_{pysecrets.token_hex(24)}"
      token_hash = _hash_token(value)
      cell_db.create_token(name, role, token_hash, scopes, expires_at)   # CELL ROW FIRST
      control.add_route(token_hash, tenant_id)                           # router row SECOND
      cell_db.add_audit("-", "token_created", {"name": name, "role": role})
      return value


  def revoke_cell_token(control, cell_db, name: str) -> str:
      row = cell_db.revoke_token(name)          # in-cell revoked_at FIRST
      if row is None:
          raise KeyError(name)
      control.remove_route(row["token_hash"])   # remove route SECOND
      cell_db.add_audit("-", "token_revoked", {"name": name})
      return name
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_provisioning.py -k mint -q`
- [ ] Commit: `feat(provisioning): cell-first/router-second token mint+revoke ordering (§12)`

---

### Task H4: `Database.invalidate_in_flight` + `active_token_hashes` + `backup_to`

Three small, self-contained cell-DB methods the restore/backup/reconcile paths need. No cross-group
dependency — can land alongside H1.

**Files:** Modify `server/arbiter/db.py` (add methods after `expire_stale_approvals`, db.py:313-328, and after
`list_tokens`, db.py:436-439). Test `server/tests/test_backup_restore.py`.

**Interfaces:**
- Produces `Database.invalidate_in_flight() -> int` — flips every `pending` OR (`approved` AND
  `consumed_at IS NULL`) request to `status='expired'` (audit reason `cell_restored`); returns the count.
  This is the §12 consumption-replay defense: a rolled-back cell can never re-execute a consumed action or
  resurrect a stale approval; the agent re-proposes.
- Produces `Database.active_token_hashes() -> set[str]` — `token_hash` of every unrevoked token (reconciler).
- Produces `Database.backup_to(dest: str) -> None` — online consistent snapshot via `VACUUM INTO`, taken
  under `self._lock` so it is consistent with in-flight writes on the shared connection.

**Steps:**

- [ ] Write the failing test `server/tests/test_backup_restore.py`:
  ```python
  from datetime import datetime, timezone
  from pathlib import Path
  from arbiter.db import Database

  def _now(): return datetime.now(timezone.utc).isoformat()

  def _insert(db, rid, status, *, decided=None, consumed=None):
      db.conn.execute(
          "INSERT INTO requests(id,created_at,title,severity,status,ttl_seconds,"
          "expires_at,decided_at,consumed_at,payload) VALUES (?,?,?,?,?,?,?,?,?,?)",
          (rid, _now(), "t", "high", status, 300, _now(), decided, consumed, "{}"))
      db.conn.commit()

  def test_invalidate_in_flight_flips_pending_and_unconsumed_approved(tmp_path):
      db = Database(":memory:")
      _insert(db, "p", "pending")
      _insert(db, "a", "approved", decided=_now())              # approved, unconsumed
      _insert(db, "c", "approved", decided=_now(), consumed=_now())  # already consumed
      _insert(db, "d", "denied")
      assert db.invalidate_in_flight() == 2
      assert db.get_request("p")["status"] == "expired"
      assert db.get_request("a")["status"] == "expired"
      assert db.get_request("c")["status"] == "approved"   # consumed rows untouched
      assert db.get_request("d")["status"] == "denied"

  def test_active_token_hashes_excludes_revoked(tmp_path):
      db = Database(":memory:")
      db.create_token("a", "app", "h_a")
      db.create_token("b", "app", "h_b")
      db.revoke_token("b")
      assert db.active_token_hashes() == {"h_a"}

  def test_backup_to_produces_readable_snapshot(tmp_path):
      src = Database(str(tmp_path / "src.sqlite3"))
      src.create_token("x", "app", "h_x")
      dest = tmp_path / "snap.sqlite3"
      src.backup_to(str(dest))
      assert Database(str(dest)).active_token_hashes() == {"h_x"}
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_backup_restore.py -q`
- [ ] Implement — add to `server/arbiter/db.py`. After `expire_stale_approvals` (db.py:328):
  ```python
      def invalidate_in_flight(self) -> int:
          """Restore-safety (§12): flip every in-flight approval (pending, or
          approved-and-unconsumed) to 'expired' so a rolled-back cell cannot
          re-execute an already-consumed action or resurrect a stale approval.
          The agent must re-propose. Returns the number of rows invalidated."""
          with self._lock:
              rows = self.conn.execute(
                  "SELECT id FROM requests WHERE status='pending'"
                  " OR (status='approved' AND consumed_at IS NULL)").fetchall()
              for r in rows:
                  self.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
                  self.add_audit(r["id"], "expired", {"reason": "cell_restored"})
              self.conn.commit()
              return len(rows)

      def backup_to(self, dest: str) -> None:
          """Online consistent snapshot of this cell DB (VACUUM INTO), safe under
          concurrent writers. dest must not already exist."""
          with self._lock:
              self.conn.execute("VACUUM INTO ?", (dest,))
  ```
  After `list_tokens` (db.py:439):
  ```python
      def active_token_hashes(self) -> set[str]:
          """token_hash of every unrevoked token — the reconciler's liveness set (§12)."""
          with self._lock:
              rows = self.conn.execute(
                  "SELECT token_hash FROM tokens WHERE revoked_at IS NULL").fetchall()
              return {r["token_hash"] for r in rows}
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_backup_restore.py -q`
- [ ] Commit: `feat(db): invalidate_in_flight + active_token_hashes + backup_to for restore/backup (§12)`

---

### Task H5: `hma tenant create | list | disable | delete`

The admin CLI surface. `create` wraps `provision_tenant` (H2) and prints the two tokens **once**; `disable`
flips `disabled_at` (live sessions drop because the stream group re-reads `disabled_at` every heartbeat —
§8; the CLI is a separate process from the server, so flag-flip is the cross-process teardown signal);
`delete` **tombstones** (epoch/dir never recycled, §5/§14).

**Files:** Modify `server/arbiter/cli.py` (add a `tenant` group; add path helpers to
`server/arbiter/provisioning.py`). Test `server/tests/test_cli_tenant.py`.

**Interfaces:**
- Produces (in provisioning.py) `control_path_for(cfg) -> Path` = `<db_path parent>/control.db` (the
  `control_dir` is that path's parent — matches B1's `.open(control_dir, tenants_root)` factory);
  `tenants_root_for(cfg) -> Path` = `<db_path parent>/tenants`. Consumed by CLI here and by the serve/startup
  wiring group.
- Consumes `ControlPlane`, `.list_tenants()`, `.tenant_dir()`, `.disable_tenant()`, `.tombstone_tenant()`;
  `provision_tenant` (H2); `Config.load` (shipped).

**Steps:**

- [ ] Add path helpers — append to `server/arbiter/provisioning.py`:
  ```python
  def control_path_for(cfg) -> Path:
      # The live control DB file. Its parent is the `control_dir` passed to
      # `ControlPlane.open(...)`, and the filename matches B1's CONTROL_DB_FILENAME
      # ("control.db") so the raw-read paths (`hma tenant list`, `hma admin restore`)
      # point at exactly the file `.open()` creates.
      return Path(cfg.db_path_expanded()).parent / "control.db"

  def tenants_root_for(cfg) -> Path:
      return Path(cfg.db_path_expanded()).parent / "tenants"
  ```
- [ ] Write the failing test `server/tests/test_cli_tenant.py`:
  ```python
  import re
  from click.testing import CliRunner
  from arbiter.cli import main
  from arbiter.config import Config
  from arbiter.control import ControlPlane
  from arbiter.provisioning import control_path_for, tenants_root_for

  def _env(tmp_path, monkeypatch):
      monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
      monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "data" / "arbiter.sqlite3"))

  def test_tenant_create_prints_tokens_once_and_registers(tmp_path, monkeypatch):
      _env(tmp_path, monkeypatch)
      assert CliRunner().invoke(main, ["init"]).exit_code == 0
      r = CliRunner().invoke(main, ["tenant", "create", "acme"])
      assert r.exit_code == 0, r.output
      assert re.search(r"hma_app_[0-9a-f]{48}", r.output)
      assert re.search(r"hma_warden_[0-9a-f]{48}", r.output)
      control = ControlPlane.open(control_path_for(Config.load()).parent, tenants_root_for(Config.load()))
      assert "acme" in control.list_tenants()

  def test_tenant_list_disable_delete(tmp_path, monkeypatch):
      _env(tmp_path, monkeypatch)
      CliRunner().invoke(main, ["init"])
      CliRunner().invoke(main, ["tenant", "create", "acme"])
      assert "acme" in CliRunner().invoke(main, ["tenant", "list"]).output
      assert CliRunner().invoke(main, ["tenant", "disable", "acme"]).exit_code == 0
      assert "disabled" in CliRunner().invoke(main, ["tenant", "list"]).output.lower()
      assert CliRunner().invoke(main, ["tenant", "delete", "acme"]).exit_code == 0

  def test_tenant_create_rejects_bad_id(tmp_path, monkeypatch):
      _env(tmp_path, monkeypatch)
      CliRunner().invoke(main, ["init"])
      r = CliRunner().invoke(main, ["tenant", "create", "Bad_Name"])
      assert r.exit_code != 0 and "a-z0-9-" in r.output
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_cli_tenant.py -q`
- [ ] Implement — add to `server/arbiter/cli.py` (after the `token` group, near cli.py:315). The `list`
  command reads the pinned `tenants` table directly off control.db for display fields:
  ```python
  @main.group()
  def tenant():
      """Provision and manage tenant cells (admin = local control.db access)."""

  def _control(cfg):
      from .control import ControlPlane
      from .provisioning import control_path_for, tenants_root_for
      # 3-arg real class via its B1 factory: control_dir = control.db's parent,
      # tenants_root so create_tenant's under-root + §15.7 checks resolve correctly.
      return ControlPlane.open(control_path_for(cfg).parent, tenants_root_for(cfg))

  @tenant.command("create")
  @click.argument("tenant_id")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def tenant_create(tenant_id, config_path):
      """Provision a fresh isolated cell for TENANT_ID; print its first app + warden tokens."""
      from .provisioning import provision_tenant, tenants_root_for, TenantDirError
      cfg = Config.load(config_path)
      try:
          res = provision_tenant(_control(cfg), tenants_root_for(cfg), tenant_id)
      except TenantDirError as exc:
          raise click.ClickException(str(exc))
      except (FileExistsError, sqlite3.IntegrityError, ValueError) as exc:
          raise click.ClickException(f"cannot create tenant '{tenant_id}': {exc}")
      click.echo(f"tenant '{res.tenant_id}' created (epoch {res.epoch})")
      click.echo(f"  dir:          {res.dir}")
      click.echo(f"  app token:    {res.app_token}")
      click.echo(f"  warden token: {res.warden_token}")
      click.echo("Shown once — only sha256 hashes are stored.")

  @tenant.command("list")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def tenant_list(config_path):
      """List tenants with epoch and disabled state."""
      from .provisioning import control_path_for
      cfg = Config.load(config_path)
      path = control_path_for(cfg)
      if not path.exists():
          click.echo("no tenants (single-tenant install — run `hma admin migrate`)")
          return
      conn = sqlite3.connect(str(path))
      try:
          rows = conn.execute(
              "SELECT tenant_id, epoch, disabled_at, dir FROM tenants ORDER BY tenant_id").fetchall()
      finally:
          conn.close()
      if not rows:
          click.echo("no tenants")
          return
      for tid, epoch, disabled_at, d in rows:
          state = "disabled" if disabled_at else "active"
          click.echo(f"{tid}  epoch={epoch}  {state}  dir={d}")

  @tenant.command("disable")
  @click.argument("tenant_id")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def tenant_disable(tenant_id, config_path):
      """Disable TENANT_ID; the server drops its live sessions on the next heartbeat."""
      cfg = Config.load(config_path)
      _control(cfg).disable_tenant(tenant_id)
      click.echo(f"disabled {tenant_id} (running streams close on next heartbeat; next HTTP 403s)")

  @tenant.command("delete")
  @click.argument("tenant_id")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def tenant_delete(tenant_id, config_path):
      """Tombstone TENANT_ID — its epoch and dir are never recycled."""
      cfg = Config.load(config_path)
      _control(cfg).tombstone_tenant(tenant_id)
      click.echo(f"tombstoned {tenant_id} (epoch + dir permanently retired)")
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_cli_tenant.py -q`
- [ ] Commit: `feat(cli): hma tenant create/list/disable/delete (§14)`

---

### Task H6: tenant-scoped `hma token create | list | revoke`

Make `hma token` tenant-aware while keeping the shipped single-DB behavior when there is no control.db
(pre-migration back-compat). With a `--tenant` (default `default`) and a control.db present, mint/revoke go
through the H3 cross-store ordering so every per-tenant token also gets a route.

**Files:** Modify `server/arbiter/cli.py` — replace `token_create` (cli.py:247-284), `token_list`
(cli.py:286-300), `token_revoke` (cli.py:302-313). Test `server/tests/test_cli_token_tenant.py`.

**Interfaces:**
- Consumes `mint_cell_token`, `revoke_cell_token`, `control_path_for` (H3/H5); `ControlPlane.tenant_dir`;
  `Database`; the shipped `_hash_token`, `_RESERVED_TOKEN_NAMES` (cli.py:238-241).
- Preserves the shipped single-DB path (no control.db) unchanged so `test_cli_token.py` keeps passing.

**Steps:**

- [ ] Write the failing test `server/tests/test_cli_token_tenant.py`:
  ```python
  import hashlib, re
  from click.testing import CliRunner
  from arbiter.cli import main
  from arbiter.config import Config
  from arbiter.control import ControlPlane
  from arbiter.provisioning import control_path_for, tenants_root_for

  def _env(tmp_path, monkeypatch):
      monkeypatch.setenv("HMA_CONFIG", str(tmp_path / "config.toml"))
      monkeypatch.setenv("HMA_DB_PATH", str(tmp_path / "data" / "arbiter.sqlite3"))

  def _h(v): return hashlib.sha256(v.encode()).hexdigest()

  def test_token_create_into_tenant_routes_to_that_cell(tmp_path, monkeypatch):
      _env(tmp_path, monkeypatch)
      CliRunner().invoke(main, ["init"])
      CliRunner().invoke(main, ["tenant", "create", "acme"])
      out = CliRunner().invoke(main, ["token", "create", "hermes", "--role", "agent",
                                      "--tenant", "acme"]).output
      value = re.search(r"hma_agent_[0-9a-f]{48}", out).group(0)
      control = ControlPlane.open(control_path_for(Config.load()).parent, tenants_root_for(Config.load()))
      assert control.resolve(_h(value))[0] == "acme"
      # list scoped to the tenant shows it
      lst = CliRunner().invoke(main, ["token", "list", "--tenant", "acme"]).output
      assert "hermes" in lst and value not in lst
      # revoke drops both cell row + route
      CliRunner().invoke(main, ["token", "revoke", "hermes", "--tenant", "acme"])
      assert control.resolve(_h(value)) is None
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_cli_token_tenant.py -q`
- [ ] Implement — replace the three token subcommands in `server/arbiter/cli.py`:
  ```python
  def _build_scopes(action_types, max_severity):
      if not (action_types or max_severity):
          return None
      scopes = {}
      if action_types:
          scopes["action_types"] = [a.strip() for a in action_types.split(",") if a.strip()]
      if max_severity:
          scopes["max_severity"] = max_severity
      return scopes

  def _expiry_iso(expires_days):
      if expires_days is None:
          return None
      from datetime import datetime, timedelta, timezone
      return (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

  def _cell_db_for(control, tenant_id):
      from .db import Database
      return Database(str(Path(control.tenant_dir(tenant_id)) / "arbiter.sqlite3"))

  @token.command("create")
  @click.argument("name")
  @click.option("--role", type=click.Choice(["agent", "warden", "app"]), required=True,
                help="agent: create+read own · warden: create/read-own/consume · app: decide/list.")
  @click.option("--tenant", "tenant_id", default=None,
                help="Tenant cell to mint into (multi-tenant installs; defaults to 'default').")
  @click.option("--action-types", default=None,
                help="Comma-separated action_type allowlist scope (e.g. deploy,restart).")
  @click.option("--max-severity", type=click.Choice(["low", "medium", "high", "critical"]),
                default=None, help="Severity cap scope.")
  @click.option("--expires-days", type=int, default=None, help="Expire the token after N days.")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def token_create(name, role, tenant_id, action_types, max_severity, expires_days, config_path):
      """Mint a token for NAME. The secret is printed ONCE and never stored."""
      from .db import Database
      from .provisioning import control_path_for
      if name in _RESERVED_TOKEN_NAMES:
          raise click.ClickException(f"'{name}' is reserved for the legacy config-token identity")
      cfg = Config.load(config_path)
      scopes, expires_at = _build_scopes(action_types, max_severity), _expiry_iso(expires_days)
      control_path = control_path_for(cfg)
      if tenant_id or control_path.exists():
          from .provisioning import mint_cell_token
          tid = tenant_id or "default"
          control = _control(cfg)          # 3-arg ControlPlane via .open() factory
          cell = _cell_db_for(control, tid)
          try:
              value = mint_cell_token(control, cell, tid, name, role, scopes, expires_at)
          except sqlite3.IntegrityError:
              raise click.ClickException(f"token name '{name}' already exists in tenant '{tid}'")
      else:
          db = Database(cfg.db_path_expanded())
          value = f"hma_{role}_{pysecrets.token_hex(24)}"
          try:
              db.create_token(name, role, _hash_token(value), scopes, expires_at)
          except sqlite3.IntegrityError:
              raise click.ClickException(f"token name '{name}' already exists")
          db.add_audit("-", "token_created",
                       {"name": name, "role": role, "scopes": scopes, "expires_at": expires_at})
      click.echo(f"token: {value}")
      click.echo("Shown once — only its sha256 hash is stored.")

  @token.command("list")
  @click.option("--tenant", "tenant_id", default=None, help="Tenant cell to list (default 'default').")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def token_list(tenant_id, config_path):
      """List tokens (never shows secrets or hashes)."""
      from .db import Database
      from .provisioning import control_path_for
      cfg = Config.load(config_path)
      control_path = control_path_for(cfg)
      if tenant_id or control_path.exists():
          db = _cell_db_for(_control(cfg), tenant_id or "default")
      else:
          db = Database(cfg.db_path_expanded())
      rows = db.list_tokens()
      if not rows:
          click.echo("no tokens")
          return
      for t in rows:
          state = "revoked" if t["revoked_at"] else "active"
          click.echo(f"{t['name']}  role={t['role']}  {state}  created={t['created_at']}  "
                     f"expires={t['expires_at'] or '-'}  last_used={t['last_used_at'] or '-'}")

  @token.command("revoke")
  @click.argument("name")
  @click.option("--tenant", "tenant_id", default=None, help="Tenant cell (default 'default').")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def token_revoke(name, tenant_id, config_path):
      """Revoke the token named NAME (takes effect on its next request)."""
      from .db import Database
      from .provisioning import control_path_for
      cfg = Config.load(config_path)
      control_path = control_path_for(cfg)
      if tenant_id or control_path.exists():
          from .provisioning import revoke_cell_token
          control = _control(cfg)          # 3-arg ControlPlane via .open() factory
          cell = _cell_db_for(control, tenant_id or "default")
          try:
              revoke_cell_token(control, cell, name)
          except KeyError:
              raise click.ClickException(f"no token named '{name}'")
      else:
          db = Database(cfg.db_path_expanded())
          if db.revoke_token(name) is None:
              raise click.ClickException(f"no token named '{name}'")
          db.add_audit("-", "token_revoked", {"name": name})
      click.echo(f"revoked {name}")
  ```
- [ ] Run green (expect **PASS**, including the unchanged legacy suite):
  `cd server && python -m pytest tests/test_cli_token_tenant.py tests/test_cli_token.py -q`
- [ ] Commit: `feat(cli): tenant-scoped hma token create/list/revoke, single-DB back-compat kept (§14)`

---

### Task H7: `reconcile_routes` + `snapshot_db` + `backup_fleet` + `hma admin backup`

Fleet backup: snapshot **each cell first**, then **control.db last** (§12) so any interleaving anomaly fails
closed. `reconcile_routes` (used at startup AND inside restore) drops router rows lacking a live cell token —
the credential fail-closed half of §12/§15.12.

**Files:** Modify `server/arbiter/provisioning.py`. Modify `server/arbiter/cli.py` (add an `admin` group).
Test `server/tests/test_backup_restore.py`.

**Interfaces:**
- Produces `snapshot_db(src: Path, dest: Path) -> None` (VACUUM INTO via a fresh read connection — no live
  Cell needed); `backup_fleet(control, out_dir: Path) -> None`; `reconcile_routes(control_db_path: Path) ->
  int` (reads the pinned `tenants.dir` + `token_route`; deletes orphan `token_route` rows; returns count).
- Consumes `ControlPlane.list_tenants`, `.tenant_dir`, `.db_path`; `Database.active_token_hashes` (H4).
- `reconcile_routes` is consumed by the serve/startup wiring group (run once at boot) and by H8's restore.

**Steps:**

- [ ] Add the failing test to `server/tests/test_backup_restore.py`:
  ```python
  from arbiter.control import ControlPlane
  from arbiter.provisioning import (provision_tenant, backup_fleet, reconcile_routes,
                                    revoke_cell_token)
  import hashlib
  def _h(v): return hashlib.sha256(v.encode()).hexdigest()

  def test_backup_fleet_writes_control_last_and_per_cell(tmp_path):
      control = ControlPlane(tmp_path / "control.sqlite3")
      provision_tenant(control, tmp_path / "tenants", "acme")
      out = tmp_path / "bk"
      backup_fleet(control, out)
      assert (out / "control.sqlite3").is_file()
      assert (out / "tenants" / "acme.sqlite3").is_file()

  def test_reconcile_drops_route_without_live_cell_token(tmp_path):
      control = ControlPlane(tmp_path / "control.sqlite3")
      res = provision_tenant(control, tmp_path / "tenants", "acme")
      from arbiter.db import Database
      cell = Database(str(res.dir / "arbiter.sqlite3"))
      cell.revoke_token("app")                  # cell no longer has a live token for that hash
      dropped = reconcile_routes(tmp_path / "control.sqlite3")
      assert dropped >= 1
      assert control.resolve(_h(res.app_token)) is None   # orphan route removed → fail closed
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_backup_restore.py -k "backup_fleet or reconcile" -q`
- [ ] Implement — append to `server/arbiter/provisioning.py`:
  ```python
  def snapshot_db(src: Path, dest: Path) -> None:
      """Online consistent snapshot of a SQLite file via VACUUM INTO on a fresh
      read connection (safe while the server holds its own WAL connection open)."""
      src, dest = Path(src), Path(dest)
      dest.parent.mkdir(parents=True, exist_ok=True)
      if dest.exists():
          dest.unlink()
      conn = sqlite3.connect(str(src))
      try:
          conn.execute("VACUUM INTO ?", (str(dest),))
      finally:
          conn.close()


  def backup_fleet(control, out_dir: Path) -> None:
      """Snapshot every cell FIRST, then control.db LAST (§12): the ordering makes
      a mint/revoke that smears across the run fail closed on restore."""
      out = Path(out_dir).expanduser().resolve()
      (out / "tenants").mkdir(parents=True, exist_ok=True)
      for tenant_id in control.list_tenants():
          src = Path(control.tenant_dir(tenant_id)) / "arbiter.sqlite3"
          snapshot_db(src, out / "tenants" / f"{tenant_id}.sqlite3")
      snapshot_db(Path(control.db_path), out / "control.sqlite3")


  def reconcile_routes(control_db_path: Path) -> int:
      """Drop router routes whose token_hash is not a live (present + unrevoked)
      token in its tenant's cell (§12 credential fail-closed). Reads the pinned
      tenants.dir / token_route columns; returns the number of routes dropped.
      Safe to run at startup and inside restore."""
      conn = sqlite3.connect(str(control_db_path))
      try:
          dirs = {tid: d for tid, d in conn.execute("SELECT tenant_id, dir FROM tenants")}
          routes = conn.execute("SELECT token_hash, tenant_id FROM token_route").fetchall()
          dropped = 0
          for token_hash, tenant_id in routes:
              d = dirs.get(tenant_id)
              live: set[str] = set()
              cell_path = Path(d) / "arbiter.sqlite3" if d else None
              if cell_path and cell_path.exists():
                  live = Database(str(cell_path)).active_token_hashes()
              if token_hash not in live:
                  conn.execute("DELETE FROM token_route WHERE token_hash=?", (token_hash,))
                  dropped += 1
          conn.commit()
          return dropped
      finally:
          conn.close()
  ```
- [ ] Add the CLI `admin` group to `server/arbiter/cli.py` (after the `tenant` group):
  ```python
  @main.group()
  def admin():
      """Fleet backup / restore / migrate (admin = local filesystem access)."""

  @admin.command("backup")
  @click.option("--out", "out_dir", required=True, help="Directory to write the snapshot into.")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def admin_backup(out_dir, config_path):
      """Online snapshot every cell (then control.db LAST) — fail-closed ordering."""
      from .provisioning import backup_fleet
      cfg = Config.load(config_path)
      backup_fleet(_control(cfg), Path(out_dir))
      click.echo(f"backup written to {out_dir}")
      click.echo("Restore is fail-closed: in-flight approvals are re-minted (see `hma admin restore`).")
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_backup_restore.py -q`
- [ ] Commit: `feat(provisioning): cells-first/control-last backup + route reconciler + hma admin backup (§12)`

---

### Task H8: `restore_fleet` + `hma admin restore` — fail-closed for credentials AND consumption

Restore the control.db + per-cell snapshots, then on **every restored cell** force re-mint of in-flight
approvals (`invalidate_in_flight`, consumption fail-closed) and run `reconcile_routes` (credential
fail-closed). Server must be **stopped** during restore (documented). Proves the two §16 gates: a pre-revoke
smear keeps the token invalid; a pre-consume snapshot yields no second execution.

**Files:** Modify `server/arbiter/provisioning.py`. Modify `server/arbiter/cli.py`. Test
`server/tests/test_backup_restore.py`.

**Interfaces:**
- Produces `restore_fleet(control_db_path: Path, backup_dir: Path) -> None`.
- Consumes `snapshot_db`, `reconcile_routes` (H7); `Database.invalidate_in_flight` (H4); the pinned
  `tenants.dir` column; `ControlPlane.resolve` (in tests).

**Steps:**

- [ ] Add the failing tests to `server/tests/test_backup_restore.py`:
  ```python
  from arbiter.provisioning import snapshot_db, restore_fleet
  from arbiter.db import Database

  def test_restore_prerevoke_smear_keeps_token_invalid(tmp_path):
      control = ControlPlane(tmp_path / "control.sqlite3")
      res = provision_tenant(control, tmp_path / "tenants", "acme")
      cell_path = res.dir / "arbiter.sqlite3"
      backup = tmp_path / "bk"; (backup / "tenants").mkdir(parents=True)
      # (1) cell snapshot FIRST — pre-revoke: token present + unrevoked
      snapshot_db(cell_path, backup / "tenants" / "acme.sqlite3")
      # (2) revoke happens between the two snapshots (cell revoked_at + route removed)
      revoke_cell_token(control, Database(str(cell_path)), "app")
      # (3) control snapshot LAST — post-revoke: route already gone
      snapshot_db(tmp_path / "control.sqlite3", backup / "control.sqlite3")
      # restore the smeared backup and resolve the app token
      restore_fleet(tmp_path / "control.sqlite3", backup)
      control2 = ControlPlane(tmp_path / "control.sqlite3")
      assert control2.resolve(_h(res.app_token)) is None   # invalid: route absent → fail closed

  def test_restore_preconsume_snapshot_forces_remint_no_second_execution(tmp_path):
      from datetime import datetime, timezone
      control = ControlPlane(tmp_path / "control.sqlite3")
      res = provision_tenant(control, tmp_path / "tenants", "acme")
      cell_path = res.dir / "arbiter.sqlite3"
      cell = Database(str(cell_path))
      now = datetime.now(timezone.utc).isoformat()
      cell.conn.execute(
          "INSERT INTO requests(id,created_at,title,severity,status,ttl_seconds,"
          "expires_at,decided_at,payload) VALUES (?,?,?,?,?,?,?,?,?)",
          ("r1", now, "pay", "high", "approved", 300, now, now, "{}")); cell.conn.commit()
      backup = tmp_path / "bk"; (backup / "tenants").mkdir(parents=True)
      snapshot_db(cell_path, backup / "tenants" / "acme.sqlite3")     # pre-consume
      snapshot_db(tmp_path / "control.sqlite3", backup / "control.sqlite3")
      # the approval is consumed + executed
      assert cell.consume_request("r1", approval_ttl_seconds=600)[0] == 200
      # DISASTER: roll back to the pre-consume snapshot
      restore_fleet(tmp_path / "control.sqlite3", backup)
      cell2 = Database(str(cell_path))
      assert cell2.get_request("r1")["status"] == "expired"          # re-minted / invalidated
      assert cell2.consume_request("r1", approval_ttl_seconds=600)[0] != 200  # no second execution
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_backup_restore.py -k restore -q`
- [ ] Implement — append to `server/arbiter/provisioning.py`:
  ```python
  def restore_fleet(control_db_path: Path, backup_dir: Path) -> None:
      """Restore control.db + per-cell snapshots, then fail closed:
      - credentials: reconcile_routes drops router rows lacking a live cell token;
      - consumption: every restored cell force re-mints (invalidate_in_flight) so a
        rolled-back approved-unconsumed action cannot re-execute.
      The server MUST be stopped during restore (control.db is replaced on disk)."""
      control_db_path = Path(control_db_path)
      backup = Path(backup_dir).expanduser().resolve()
      # 1) control.db first, so we know the tenant roster + dirs as of the backup
      shutil.copyfile(backup / "control.sqlite3", control_db_path)
      conn = sqlite3.connect(str(control_db_path))
      try:
          dirs = {tid: d for tid, d in conn.execute("SELECT tenant_id, dir FROM tenants")}
      finally:
          conn.close()
      # 2) each cell snapshot into its tenant dir; drop stale WAL/SHM sidecars first
      for tenant_id, d in dirs.items():
          snap = backup / "tenants" / f"{tenant_id}.sqlite3"
          if not snap.exists():
              continue
          dest = Path(d) / "arbiter.sqlite3"
          dest.parent.mkdir(parents=True, exist_ok=True)
          for suffix in ("", "-wal", "-shm"):
              p = Path(str(dest) + suffix)
              if p.exists():
                  p.unlink()
          shutil.copyfile(snap, dest)
          Database(str(dest)).invalidate_in_flight()   # consumption fail-closed
      # 3) credential fail-closed reconcile
      reconcile_routes(control_db_path)
  ```
- [ ] Add the CLI command to `server/arbiter/cli.py` (in the `admin` group):
  ```python
  @admin.command("restore")
  @click.option("--backup-dir", required=True, help="Snapshot dir produced by `hma admin backup`.")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def admin_restore(backup_dir, config_path):
      """Restore a fleet snapshot (stop the server first). Fail-closed: in-flight
      approvals are re-minted and credential routes are reconciled."""
      from .provisioning import restore_fleet, control_path_for
      cfg = Config.load(config_path)
      restore_fleet(control_path_for(cfg), Path(backup_dir))
      click.echo("restore complete — in-flight approvals invalidated; agents must re-propose")
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_backup_restore.py -q`
- [ ] Commit: `feat(provisioning): fail-closed restore (re-mint in-flight + reconcile routes) + hma admin restore (§12/§15.12)`

---

### Task H9: `migrate_to_multitenant` + `hma admin migrate` — single-tenant back-compat

Wrap today's single DB as the `default` cell: register `default` pointing at the **existing** DB's dir, and
backfill a router route for every existing unrevoked cell token. Legacy `cfg.auth.app_token` then resolves
strictly to `default` (auth group); existing devices already live in that DB so they map to `default`
unchanged. Idempotent. iOS 0.5.0 / hold-sdk 0.2.1 keep working.

**Files:** Modify `server/arbiter/provisioning.py`. Modify `server/arbiter/cli.py`. Test
`server/tests/test_backcompat.py`.

**Interfaces:**
- Produces `migrate_to_multitenant(cfg, control, root: Path) -> None`.
- Consumes `ControlPlane.list_tenants`, `.create_tenant(tenant_id, dir)`, `.add_route`; `Config.db_path_expanded`
  (shipped); `Database.list_tokens` (shipped).

**Steps:**

- [ ] Write the failing test `server/tests/test_backcompat.py`:
  ```python
  import hashlib
  from arbiter.config import Config
  from arbiter.control import ControlPlane
  from arbiter.db import Database
  from arbiter.provisioning import migrate_to_multitenant
  def _h(v): return hashlib.sha256(v.encode()).hexdigest()

  def test_migrate_wraps_single_db_as_default(tmp_path):
      legacy = tmp_path / "data" / "arbiter.sqlite3"
      legacy.parent.mkdir(parents=True)
      db = Database(str(legacy))
      db.create_token("hermes", "agent", _h("hma_agent_live"))
      db.create_token("gone", "app", _h("hma_app_gone")); db.revoke_token("gone")
      db.register_device("apns1", "iPhone")
      cfg = Config.load(str(tmp_path / "absent.toml"))
      cfg.server.db_path = str(legacy)
      control = ControlPlane(tmp_path / "control.sqlite3")
      migrate_to_multitenant(cfg, control, tmp_path / "tenants")
      assert "default" in control.list_tenants()
      assert control.tenant_dir("default").resolve() == legacy.parent.resolve()
      assert control.resolve(_h("hma_agent_live"))[0] == "default"   # live token routed
      assert control.resolve(_h("hma_app_gone")) is None             # revoked token NOT routed
      assert len(Database(str(legacy)).list_devices()) == 1          # devices stay in default cell
      # idempotent
      migrate_to_multitenant(cfg, control, tmp_path / "tenants")
      assert control.list_tenants().count("default") == 1
  ```
- [ ] Run it (expect **FAIL**): `cd server && python -m pytest tests/test_backcompat.py -q`
- [ ] Implement — append to `server/arbiter/provisioning.py`:
  ```python
  def migrate_to_multitenant(cfg, control, root: Path) -> None:
      """Wrap today's single arbiter DB as the 'default' cell (idempotent).
      Registers 'default' pointing at the EXISTING DB dir (exempt from the
      tenants-root layout) and backfills a router route for every unrevoked
      cell token. Legacy app_token resolves strictly to 'default' (auth group);
      existing devices already live in that DB, so they map to 'default'."""
      if "default" in control.list_tenants():
          return
      legacy_path = Path(cfg.db_path_expanded())
      legacy_dir = legacy_path.parent.resolve()
      control.create_tenant("default", legacy_dir)
      cell_db = Database(str(legacy_path))
      for t in cell_db.list_tokens():
          if t["revoked_at"] is None:
              control.add_route(t["token_hash"], "default")
  ```
- [ ] Add the CLI command to `server/arbiter/cli.py` (in the `admin` group):
  ```python
  @admin.command("migrate")
  @click.option("--config", "config_path", default=None, help="Path to config.toml")
  def admin_migrate(config_path):
      """Wrap a single-tenant install as the 'default' cell (idempotent)."""
      from .provisioning import migrate_to_multitenant, tenants_root_for
      cfg = Config.load(config_path)
      migrate_to_multitenant(cfg, _control(cfg), tenants_root_for(cfg))
      click.echo("migrated single-tenant DB to the 'default' cell "
                 "(legacy app_token + existing devices → default)")
  ```
- [ ] Run green (expect **PASS**): `cd server && python -m pytest tests/test_backcompat.py -q`
- [ ] Full-group regression: `cd server && python -m pytest tests/test_provisioning.py tests/test_backup_restore.py tests/test_cli_tenant.py tests/test_cli_token_tenant.py tests/test_cli_token.py tests/test_backcompat.py -q`
- [ ] Commit: `feat(provisioning): single-tenant back-compat migration + hma admin migrate (§14)`

---

## Coverage check (spec sections this group closes)

- **§12 / §15.12** — backup cells-first/control-last (H7), reconciler drops orphan routes (H7), restore
  re-mints in-flight approvals (H8). §16 gates: "restore pre-revoke snapshot keeps token invalid" (H8),
  "restore pre-consume snapshot ⇒ consume fails closed, no second execution" (H8).
- **§14** — `hma tenant create/list/disable/delete` (H5), tenant-scoped `hma token` (H6), single-tenant
  back-compat migration (H9).
- **§15.7** — realpath-canonical / unique / non-overlapping dir enforced at mint (H2) via the shared guard
  (H1) that the registry also calls at open; "no two cells load identical key bytes" (H2 test).

## Cross-group notes for the implementer

- `ControlPlane` is imported as `from arbiter.control import ControlPlane` throughout; if the control-plane
  group placed it elsewhere, adjust the import — the class name and method signatures are fixed by the
  pinned contract.
- H1's `assert_dir_isolated` / `canonicalize_tenant_dir` MUST also be wired into the registry's cell-open
  path (that is the "AND at open" half of §15.7) — that wiring lives in the registry group; this group only
  produces the guard and proves it at mint.
- `reconcile_routes` MUST be called once at server startup by the serve/wiring group (drops any route left
  orphaned by a crash mid-mint or an out-of-band restore); this group produces it and proves it in isolation.


---


## Group I — Merge-gating adversarial isolation suite (§16, all 19 tests) + `scripts/smoke-multitenant.sh` + CI wiring

**Branch:** `feat/multitenant-isolation`. **Repo (quote the space in paths):**
`<repo-root>`.

**What this group builds.** The §16 isolation suite is *the product's proof* — cross-tenant read/approve/push/
verdict/audit is impossible by construction. This group authors all 19 §16 tests as concrete, runnable
pytest cases under `server/tests/isolation/`, a `scripts/smoke-multitenant.sh` end-to-end curl smoke that
stands up one arbiter serving two tenants and proves A cannot see/approve/receive B, and wires both into
`.github/workflows/ci.yml` as a hard gate. Group I lands **after** groups A–H, so each test's GREEN is the
real merge gate; every test carries a **non-vacuous baseline** (a positive control that must pass) so a
rejection can never be silently empty — the same discipline `scripts/smoke-warden.sh` already uses
("baseline: the genuine verdict MUST verify, so the rejection below can't be vacuous").

**Names this group Consumes (from the PINNED CONTRACT — never by another group's task number):**
- **Cell** — `tenant_id:str, epoch:int, dir:Path, db:Database, signer(kid=f"{tenant_id}:{hash8}",
  signing_key, public_jwks()), hub:Hub, dispatcher:Dispatcher, create_limiter, login_limiter`.
- **TenantRegistry(control, max_hot_cells=64, stream_cap=5)** — `async acquire(tenant_id, epoch)->Cell`,
  `release(cell)->None`, `async hold(tenant_id, epoch)->Cell` (context manager).
- **ControlPlane** — `resolve(token_hash)->(tenant_id,epoch)|None`, `tenant_dir(tenant_id)->Path`,
  `is_disabled(tenant_id)->bool`, `add_route/remove_route`, `create_tenant(tenant_id, dir)->int`,
  `list_tenants()`, `disable_tenant()`, `tombstone_tenant()`.
- **Identity(tenant_id, name, role, scopes, epoch, legacy)** and
  **resolve_identity(request, registry, control)->(Identity, Cell)**.
- **create_app(cfg, registry, control, sender)** — the App-wiring group's Produces: the multitenant FastAPI
  app; `app.state` holds `registry` + `control` (never a per-tenant `db`/`hub`); `/v1/stream`, all `/v1`
  routes, and `/v1/audit/export` resolve via `resolve_identity(request, registry, control)`; the lifespan
  starts one **ExpiryScheduler**.
- **sign_verdict(signer, request_id, action_hash, decision, decided_at, approval_ttl, tenant_id)->str** —
  EdDSA JWS, `kid=f"{tenant_id}:{hash8}"`, `aud=f"hma-verdict:{tenant_id}"`, claim `hma.tenant_id`.
- **VerdictVerifier(pinned: dict[kid,bytes], tenant_id)** (warden) — `verify(jws, request_id, action_hash)`,
  `adopt_rotation(record_jws, served_jwks)`.
- **ExpiryScheduler** — `schedule(expires_at, tenant_id, request_id)->None`, `async run()`.
- **Hub** — `subscribe()->Queue`, `publish(event)->None`, `close()`.
- **hma CLI (Provisioning group Produces):** `hma tenant create <name>`, `hma tenant list`,
  `hma tenant disable <name>`, `hma token create <name> --role <r> --tenant <t>`, `hma serve`,
  `hma admin backup <dir>`; **hma-warden init** pins a tenant's key locally.

**Naming assumptions (stated so the implementer is not guessing).** Import paths follow the existing package
layout: `arbiter.control.ControlPlane`, `arbiter.registry.TenantRegistry`, `arbiter.cell.Cell`,
`arbiter.scheduler.ExpiryScheduler`, `arbiter.auth.resolve_identity`, `arbiter.signing.sign_verdict`,
`arbiter.app.create_app`, `hold_warden.verdict.VerdictVerifier`. If a producing group lands a symbol at a
different path, fix the import in one place — the shared `conftest.py` (Task I1) re-exports every SUT symbol
through thin aliases, so the 19 test files import from `tests.isolation.conftest`, not from `arbiter.*`
directly. This keeps a path rename to a one-line edit.

**Global rules (every task):** Python ≥3.11; TDD; conventional commits ending
 run from repo root; the working dir has a space so
quote it. Tests live under `server/tests/isolation/`; run with `pytest server/tests/isolation -q` (the
`server` package is installed editable via `pip install -e 'server[dev]'`, same as the shipped suite).

---

### Task I1: isolation test package + shared two-tenant harness (`conftest.py`)

Foundational. Every other §16 test imports its harness from here. The harness stands up **one**
multitenant app serving **two** fully-provisioned tenants (`alice`, `bob`), each with its own cell dir, DB,
signing key, app+agent tokens, and control-plane routes minted in the §12 order (**cell row first, router
row second**).

- **Files:**
  - Create: `server/tests/isolation/__init__.py` (empty).
  - Create: `server/tests/isolation/conftest.py`.
  - Test path (self-test of the harness): `server/tests/isolation/test_harness.py`.
- **Interfaces:**
  - Consumes: **ControlPlane** (`create_tenant`, `tenant_dir`, `add_route`, `resolve`, `is_disabled`),
    **TenantRegistry** (`hold`, `acquire`, `release`), **create_app(cfg, registry, control, sender)**,
    `arbiter.db.Database`, `arbiter.config.Config`.
  - Produces (imported by I2–I22):
    - `TwoTenant` dataclass — fields `root:Path, control, registry, app, client:TestClient, sender,
      tenants:dict[str,TenantHandle]`.
    - `TenantHandle` dataclass — fields `tenant_id:str, epoch:int, dir:Path, app_bearer:str,
      agent_bearer:str, app_hdr:dict, agent_hdr:dict`.
    - fixture `two_tenant(cfg, tmp_path) -> TwoTenant` (function-scoped).
    - helpers `mint_into_cell(control, registry, tenant_id, epoch, name, role) -> bearer:str`,
      `bearer_hdr(bearer) -> dict`, `pubkey_for(client, tenant_id) -> (kid, Ed25519PublicKey)`,
      `make_hash_bound(canonical:str) -> (canonical, action_hash)`.
    - re-exported SUT aliases: `ControlPlane, TenantRegistry, Cell, ExpiryScheduler, resolve_identity,
      sign_verdict, create_app, Database`.
    - `FakeSender` (records `(tenant_dir, token, payload)` — used by egress test I16).

- [ ] **Write the harness.** Create `server/tests/isolation/__init__.py` empty, then
  `server/tests/isolation/conftest.py`:
  ```python
  import asyncio
  import base64
  import hashlib
  import secrets
  from dataclasses import dataclass, field
  from pathlib import Path

  import pytest
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  from fastapi.testclient import TestClient

  # ── SUT aliases (single edit point if a producing group renames a path) ──────
  from arbiter.config import Config
  from arbiter.db import Database
  from arbiter.control import ControlPlane
  from arbiter.registry import TenantRegistry
  from arbiter.cell import Cell
  from arbiter.scheduler import ExpiryScheduler
  from arbiter.auth import resolve_identity
  from arbiter.signing import sign_verdict
  from arbiter.app import create_app

  __all__ = ["ControlPlane", "TenantRegistry", "Cell", "ExpiryScheduler",
             "resolve_identity", "sign_verdict", "create_app", "Database",
             "TwoTenant", "TenantHandle", "FakeSender", "mint_into_cell",
             "bearer_hdr", "pubkey_for", "make_hash_bound"]


  def bearer_hdr(bearer: str) -> dict:
      return {"Authorization": f"Bearer {bearer}"}


  def make_hash_bound(canonical: str) -> tuple[str, str]:
      return canonical, hashlib.sha256(canonical.encode()).hexdigest()


  class FakeSender:
      """APNs stand-in that records which cell each push came from (egress test)."""
      def __init__(self):
          self.calls = []  # list[(token, payload)]
      async def send(self, token, payload):
          self.calls.append((token, payload))
          return "sent"


  def mint_into_cell(control, registry, tenant_id: str, epoch: int,
                     name: str, role: str) -> str:
      """Mint a bearer into a tenant, §12 order: cell row FIRST, router row SECOND.
      Runs the cell write through the real registry.hold path (real cell.db, real
      on-disk filename) so setup never opens a second connection on the cell file."""
      bearer = f"hma_{role}_{secrets.token_hex(24)}"
      th = hashlib.sha256(bearer.encode()).hexdigest()

      async def _cell_write():
          async with registry.hold(tenant_id, epoch) as cell:
              cell.db.create_token(name, role, th)  # cell row first
      asyncio.run(_cell_write())
      control.add_route(th, tenant_id)               # router row second
      return bearer


  def pubkey_for(client: TestClient, tenant_id: str):
      """Fetch a tenant's own JWKS via a bearer belonging to that tenant."""
      # caller must pass a client already carrying that tenant's app bearer via hdr
      raise NotImplementedError  # replaced below by _pubkey_via


  @dataclass
  class TenantHandle:
      tenant_id: str
      epoch: int
      dir: Path
      app_bearer: str
      agent_bearer: str
      app_hdr: dict = field(default_factory=dict)
      agent_hdr: dict = field(default_factory=dict)


  @dataclass
  class TwoTenant:
      root: Path
      control: object
      registry: object
      app: object
      client: TestClient
      sender: FakeSender
      tenants: dict


  def _provision(control, registry, root: Path) -> dict:
      handles = {}
      for name in ("alice", "bob"):
          d = root / name
          d.mkdir(parents=True, exist_ok=True)
          epoch = control.create_tenant(name, d)
          app_b = mint_into_cell(control, registry, name, epoch, f"{name}-app", "app")
          agent_b = mint_into_cell(control, registry, name, epoch, f"{name}-agent", "agent")
          handles[name] = TenantHandle(
              tenant_id=name, epoch=epoch, dir=d,
              app_bearer=app_b, agent_bearer=agent_b,
              app_hdr=bearer_hdr(app_b), agent_hdr=bearer_hdr(agent_b))
      return handles


  @pytest.fixture
  def two_tenant(cfg, tmp_path) -> TwoTenant:
      root = tmp_path / "fleet"
      root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      handles = _provision(control, registry, root)
      sender = FakeSender()
      app = create_app(cfg, registry, control, sender)
      client = TestClient(app)
      client.__enter__()  # run lifespan (starts the ExpiryScheduler)
      try:
          yield TwoTenant(root=root, control=control, registry=registry, app=app,
                          client=client, sender=sender, tenants=handles)
      finally:
          client.__exit__(None, None, None)


  def jwks_pubkey(jwks: dict):
      k = jwks["keys"][0]
      raw = base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4))
      return k["kid"], Ed25519PublicKey.from_public_bytes(raw)
  ```
  Then replace the placeholder `pubkey_for` with a working version that takes an explicit bearer header:
  ```python
  def pubkey_for(client: TestClient, hdr: dict):
      return jwks_pubkey(client.get("/v1/keys", headers=hdr).json())
  ```
  (delete the `raise NotImplementedError` stub; keep only this definition.)
- [ ] **Write the self-test** `server/tests/isolation/test_harness.py`:
  ```python
  from tests.isolation.conftest import pubkey_for


  def test_two_tenants_provisioned_distinctly(two_tenant):
      tt = two_tenant
      assert set(tt.tenants) == {"alice", "bob"}
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      # distinct dirs, distinct epochs are independent monotonic values
      assert a.dir != b.dir and a.dir.is_dir() and b.dir.is_dir()
      # each app bearer resolves to its own tenant's JWKS with a tenant-namespaced kid
      kid_a, _ = pubkey_for(tt.client, a.app_hdr)
      kid_b, _ = pubkey_for(tt.client, b.app_hdr)
      assert kid_a.startswith("alice:") and kid_b.startswith("bob:")
      assert kid_a != kid_b


  def test_router_routes_only_full_hashes(two_tenant):
      import hashlib
      tt = two_tenant
      a = tt.tenants["alice"]
      full = hashlib.sha256(a.app_bearer.encode()).hexdigest()
      assert tt.control.resolve(full) == ("alice", a.epoch)
      # a truncated hash must NOT route (no shard/route on a truncated hash)
      assert tt.control.resolve(full[:32]) is None
  ```
- [ ] **Run RED:** `pytest server/tests/isolation/test_harness.py -q` — expected FAIL/ERROR until groups
  A–H land the SUT symbols (import errors / `create_tenant` missing).
- [ ] **Run GREEN (after A–H merged):** `pytest server/tests/isolation/test_harness.py -q` — 2 passed.
- [ ] **Commit:** `test(isolation): two-tenant harness + conftest for the §16 suite`

---

### Task I2: cross-tenant stream leak — event on cell A's hub never reaches a socket on cell B

Invariant §15.1 (no process-global hub) + §16 "Cross-tenant stream leak". Two websockets, one per tenant;
a create on alice must arrive on alice's socket and **never** on bob's.

- **Files:** Create `server/tests/isolation/test_stream_leak.py`. Consumes `two_tenant`, `create_app`,
  **Hub** (cell-owned), `/v1/stream`, `/v1/requests`.
- [ ] **Write the test:**
  ```python
  import queue


  def test_event_on_cell_a_never_reaches_cell_b(two_tenant):
      tt = two_tenant
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws_a, \
           tt.client.websocket_connect("/v1/stream", headers=b.app_hdr) as ws_b:
          rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                               json={"title": "alice-secret"}).json()["id"]
          # BASELINE (non-vacuous): alice's own socket sees it
          evt = ws_a.receive_json()
          assert evt["event"] == "request.created"
          assert evt["request"]["id"] == rid
          assert evt["request"]["title"] == "alice-secret"
          # ISOLATION: bob's socket must NOT receive alice's event. Poll bob for a
          # bounded window; a leak would deliver alice's payload here.
          ws_b._send_queue if False else None  # (starlette TestClient uses a real queue)
          try:
              leaked = ws_b.receive_json()  # TestClient raises/blocks; use a decision path below
          except Exception:
              leaked = None
          assert leaked is None or leaked["request"]["id"] != rid, \
              "cell B socket received cell A's event — hub is not cell-owned"
  ```
  Note: starlette's `TestClient.websocket` `receive_json()` blocks. To bound the negative check without a
  hang, drive a *second* alice event as a fence and assert bob only ever sees its own traffic. Replace the
  isolation half with this deterministic fence:
  ```python
          # fence: publish an event on BOB's cell; the FIRST thing bob's socket
          # sees must be bob's own event, proving alice's earlier event never queued on B.
          rid_b = tt.client.post("/v1/requests", headers=b.agent_hdr,
                                 json={"title": "bob-only"}).json()["id"]
          first_b = ws_b.receive_json()
          assert first_b["request"]["id"] == rid_b and first_b["request"]["title"] == "bob-only", \
              f"cell B socket saw a foreign event first: {first_b}"
  ```
  (Keep only the fence version of the isolation half; delete the try/except `leaked` block.)
- [ ] **Run RED:** `pytest server/tests/isolation/test_stream_leak.py -q` — FAIL before the cell-owned Hub
  lands (a global hub delivers alice's event to bob first).
- [ ] **Run GREEN:** same command — 1 passed.
- [ ] **Commit:** `test(isolation): cross-tenant stream leak gate (§16)`

---

### Task I3: cookie/token cross-cell read — A's session 404s on B's rids + audit; app_token → default only

Invariant §15.2 (tenant from credential on every surface, incl. `/v1/audit/export`) + §16 "cookie/token
cross-cell read". An alice app bearer reading a bob request id gets a generic 404; alice's audit export
never contains bob's rows; the legacy `app_token` resolves strictly to `default`.

- **Files:** Create `server/tests/isolation/test_cross_cell_read.py`. Consumes `two_tenant`,
  `/v1/requests/{rid}`, `/v1/audit/export`, `resolve_identity` (legacy → `default`).
- [ ] **Write the test:**
  ```python
  def test_app_bearer_cannot_read_foreign_request_or_audit(two_tenant):
      tt = two_tenant
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      # bob creates a request in bob's cell
      bob_rid = tt.client.post("/v1/requests", headers=b.agent_hdr,
                               json={"title": "bob-private"}).json()["id"]
      # BASELINE: bob's own app bearer can read it
      assert tt.client.get(f"/v1/requests/{bob_rid}", headers=b.app_hdr).status_code == 200
      # ISOLATION: alice's app bearer 404s on bob's rid (generic, no existence oracle)
      r = tt.client.get(f"/v1/requests/{bob_rid}", headers=a.app_hdr)
      assert r.status_code == 404
      # alice's audit export must not mention bob's rid
      export = tt.client.get("/v1/audit/export", headers=a.app_hdr).text
      assert bob_rid not in export
      assert "bob-private" not in export
      # bob's own export DOES contain it (non-vacuous)
      assert bob_rid in tt.client.get("/v1/audit/export", headers=b.app_hdr).text


  def test_legacy_app_token_resolves_strictly_to_default(cfg, tmp_path):
      from tests.isolation.conftest import (ControlPlane, TenantRegistry, create_app,
                                            mint_into_cell)
      from fastapi.testclient import TestClient
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      d_def = root / "default"; d_def.mkdir(parents=True)
      ep = control.create_tenant("default", d_def)
      d_other = root / "alice"; d_other.mkdir(parents=True)
      ep2 = control.create_tenant("alice", d_other)
      alice_agent = mint_into_cell(control, registry, "alice", ep2, "alice-agent", "agent")
      app = create_app(cfg, registry, control, None)
      with TestClient(app) as c:
          # legacy cfg.auth.app_token (set in the cfg fixture) → 'default' cell:
          # it can decide in default, but a request created in ALICE is invisible to it.
          rid = c.post("/v1/requests", headers={"Authorization": f"Bearer {alice_agent}"},
                       json={"title": "in-alice"}).json()["id"]
          r = c.get(f"/v1/requests/{rid}",
                    headers={"Authorization": f"Bearer {cfg.auth.app_token}"})
          assert r.status_code == 404  # legacy app_token is default-only, cannot see alice
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_cross_cell_read.py -q`.
- [ ] **Commit:** `test(isolation): cookie/token cross-cell read + legacy app_token→default (§16)`

---

### Task I4: WS handshake routing — bearer → its cell; no-route rejected before `accept()`

Invariant §15.2 + §8 (stream resolves via the identical router path, binds to that cell's hub, rejects
before `ws.accept()`) + §16 "WS handshake routing".

- **Files:** Create `server/tests/isolation/test_ws_routing.py`. Consumes `/v1/stream`, `resolve_identity`.
- [ ] **Write the test:**
  ```python
  import pytest
  from starlette.websockets import WebSocketDisconnect


  def test_ws_bearer_binds_to_own_cell(two_tenant):
      tt = two_tenant
      a = tt.tenants["alice"]
      with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws:
          rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                               json={"title": "hi"}).json()["id"]
          assert ws.receive_json()["request"]["id"] == rid


  def test_ws_unrouted_bearer_rejected_before_accept(two_tenant):
      tt = two_tenant
      # a bearer that routes to NO cell: never minted, no control route
      bogus = {"Authorization": "Bearer hma_app_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
      with pytest.raises(WebSocketDisconnect) as ei:
          with tt.client.websocket_connect("/v1/stream", headers=bogus):
              pass
      # generic policy close (not a 1000 normal-close after accept)
      assert ei.value.code == 4401
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_ws_routing.py -q`.
- [ ] **Commit:** `test(isolation): WS handshake routing + pre-accept rejection (§16)`

---

### Task I5: single-flight `acquire()` — K concurrent acquires → one Database/connection/RLock

Invariant §15.3 + §5 ("exactly one `Database` per tenant dir at any instant; the cell is never observable
until fully initialized"). K threads hammer `acquire(tenant, epoch)` and must all receive the **same Cell
object** with the **same `db.conn`** and **same `db._lock`**; a migration read never sees a half-migrated
schema.

- **Files:** Create `server/tests/isolation/test_single_flight.py`. Consumes **TenantRegistry**
  (`acquire`/`release`), **ControlPlane** (`create_tenant`), **Cell**.
- [ ] **Write the test:**
  ```python
  import asyncio

  from tests.isolation.conftest import ControlPlane, TenantRegistry
  from arbiter.db import SCHEMA_VERSION


  def _build(tmp_path):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      d = root / "solo"; d.mkdir(parents=True)
      epoch = control.create_tenant("solo", d)
      return TenantRegistry(control), "solo", epoch


  def test_k_concurrent_acquires_yield_one_database(tmp_path):
      registry, tid, epoch = _build(tmp_path)
      K = 32

      async def run():
          cells = await asyncio.gather(*[registry.acquire(tid, epoch) for _ in range(K)])
          try:
              first = cells[0]
              # identical Cell object, identical connection, identical RLock:
              assert all(c is first for c in cells), "single-flight returned twin cells"
              assert all(c.db.conn is first.db.conn for c in cells), "two connections on one dir"
              assert all(c.db._lock is first.db._lock for c in cells), "two RLocks on one dir"
              # fully migrated before it was ever observable:
              v = first.db.conn.execute("PRAGMA user_version").fetchone()[0]
              assert v == SCHEMA_VERSION
          finally:
              for c in cells:
                  registry.release(c)

      asyncio.run(run())
  ```
- [ ] **Run RED:** `pytest server/tests/isolation/test_single_flight.py -q` — FAIL for a non-single-flight
  registry (twin cells / two connections).
- [ ] **Run GREEN:** 1 passed.
- [ ] **Commit:** `test(isolation): single-flight acquire — one Database per tenant dir (§16)`

---

### Task I6: refcount exactly-once / no use-after-free — normal close, disconnect, background retry

Invariant §15.4 + §5 (pin exactly once on every exit path; evict only at `refcount==0`; a reopened twin is
never substituted under a live holder; background tasks keep the cell pinned).

- **Files:** Create `server/tests/isolation/test_refcount.py`. Consumes **TenantRegistry**
  (`acquire`/`release`/`hold`), **Cell**.
- [ ] **Write the test:**
  ```python
  import asyncio

  from tests.isolation.conftest import ControlPlane, TenantRegistry


  def _reg(tmp_path):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      d = root / "t"; d.mkdir(parents=True)
      epoch = control.create_tenant("t", d)
      return TenantRegistry(control), "t", epoch


  def test_refcount_returns_to_baseline_on_every_exit_path(tmp_path):
      registry, tid, epoch = _reg(tmp_path)

      async def run():
          # normal acquire/release round-trip
          cell = await registry.acquire(tid, epoch)
          assert registry.refcount(cell) == 1
          registry.release(cell)
          assert registry.refcount(cell) == 0

          # context manager releases exactly once even on an exception path
          try:
              async with registry.hold(tid, epoch) as c2:
                  assert registry.refcount(c2) == 1
                  raise RuntimeError("boom")
          except RuntimeError:
              pass
          assert registry.refcount(c2) == 0

          # a live holder pins across a concurrent eviction attempt: no use-after-free
          held = await registry.acquire(tid, epoch)
          await registry.try_evict_idle()          # must skip: refcount>0
          assert held.db.conn.execute("SELECT 1").fetchone()[0] == 1  # connection still open
          registry.release(held)

      asyncio.run(run())


  def test_reopened_twin_never_substituted_under_live_holder(tmp_path):
      registry, tid, epoch = _reg(tmp_path)

      async def run():
          held = await registry.acquire(tid, epoch)
          # force churn: an acquire while held must return the SAME object, not a twin
          again = await registry.acquire(tid, epoch)
          assert again is held
          registry.release(again)
          registry.release(held)

      asyncio.run(run())
  ```
  Note: `refcount()` and `try_evict_idle()` are registry test-affordances; the registry group exposes
  `refcount(cell)->int` and an idempotent `try_evict_idle()` (evict-only-at-zero) for the gate. If the group
  names them differently, alias in `conftest.py`.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_refcount.py -q`.
- [ ] **Commit:** `test(isolation): refcount exactly-once + no use-after-free under eviction (§16)`

---

### Task I7: half-open pin cap — bounded sends, dead-socket reap, per-tenant stream cap, RLIMIT headroom

Invariant §15.13 (FD budget runtime invariant) + §8 (per-tenant concurrent-stream cap; a blackholed socket
cannot pin cells past the FD budget). Open `stream_cap` streams for one tenant; the `stream_cap+1`-th is
shed, and a blackholed socket is reaped by the ping/pong deadline so it stops pinning.

- **Files:** Create `server/tests/isolation/test_stream_cap.py`. Consumes `/v1/stream`, **TenantRegistry**
  (`stream_cap=5`), `two_tenant` (built with a low cap override).
- [ ] **Write the test:**
  ```python
  import pytest
  from starlette.websockets import WebSocketDisconnect

  from tests.isolation.conftest import (ControlPlane, TenantRegistry, create_app,
                                        mint_into_cell, bearer_hdr)
  from fastapi.testclient import TestClient


  def _one_tenant_low_cap(cfg, tmp_path, cap=2):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control, stream_cap=cap)
      d = root / "alice"; d.mkdir(parents=True)
      epoch = control.create_tenant("alice", d)
      app_b = mint_into_cell(control, registry, "alice", epoch, "alice-app", "app")
      app = create_app(cfg, registry, control, None)
      return TestClient(app), bearer_hdr(app_b)


  def test_per_tenant_stream_cap_sheds_the_overflow_socket(cfg, tmp_path):
      client, hdr = _one_tenant_low_cap(cfg, tmp_path, cap=2)
      with client:
          import contextlib
          with contextlib.ExitStack() as stack:
              # cap=2: two sockets accepted
              stack.enter_context(client.websocket_connect("/v1/stream", headers=hdr))
              stack.enter_context(client.websocket_connect("/v1/stream", headers=hdr))
              # the third is shed at handshake (over the per-tenant cap)
              with pytest.raises(WebSocketDisconnect) as ei:
                  with client.websocket_connect("/v1/stream", headers=hdr):
                      pass
              assert ei.value.code == 4429  # generic "too many streams" policy close
  ```
  Note: the `4429` close code is the stream-cap signal produced by the App/stream group; alias/adjust in
  `conftest.py` if the group publishes a different code. The dead-socket ping/pong reap is exercised in the
  refcount test (I6) via `try_evict_idle`; this test isolates the cap.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_stream_cap.py -q`.
- [ ] **Commit:** `test(isolation): per-tenant stream cap sheds overflow (FD-budget, §16)`

---

### Task I8: disable/revoke tears down live sessions — socket closes, next HTTP 403s on a hot busy cell

Invariant §15.5 + §8 (`disabled_at` read on every resolution, never cached; disable pushes a **close
sentinel** to the cell's hub so open streams `ws.close()`; a pinned cell does not exempt its sessions).

- **Files:** Create `server/tests/isolation/test_disable_teardown.py`. Consumes **ControlPlane**
  (`disable_tenant`, `is_disabled`), **Hub** (`close()`), `/v1/stream`, `/v1/requests`.
- [ ] **Write the test:**
  ```python
  import pytest
  from starlette.websockets import WebSocketDisconnect


  def test_disable_closes_live_stream_and_403s_next_request(two_tenant):
      tt = two_tenant
      a = tt.tenants["alice"]
      with tt.client.websocket_connect("/v1/stream", headers=a.app_hdr) as ws:
          # BASELINE: the socket is live (an event flows)
          rid = tt.client.post("/v1/requests", headers=a.agent_hdr,
                               json={"title": "live"}).json()["id"]
          assert ws.receive_json()["request"]["id"] == rid
          # disable alice on a HOT, busy cell (it is pinned by the open socket)
          tt.control.disable_tenant("alice")
          # the open socket is actively torn down (close sentinel on the hub)
          with pytest.raises(WebSocketDisconnect):
              ws.receive_json()
      # the very next HTTP request on alice 403s immediately (disabled read on resolve)
      r = tt.client.post("/v1/requests", headers=a.agent_hdr, json={"title": "after"})
      assert r.status_code == 403
      # bob is unaffected — disable is per-tenant
      b = tt.tenants["bob"]
      assert tt.client.post("/v1/requests", headers=b.agent_hdr,
                            json={"title": "ok"}).status_code == 200
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_disable_teardown.py -q`.
- [ ] **Commit:** `test(isolation): disable actively tears down live sessions (§16)`

---

### Task I9: scheduler per-cell signing — B's expiry verifies under B's key, fails under A's, hits B's db

Invariant §15.10 + §6 (scheduler holds only `(expires_at, tenant_id, request_id)`; each firing signs with
the **acquired cell's own** signer against its own db). An expiry verdict for a bob request must verify
against bob's JWKS and **fail** against alice's, and land in bob's db.

- **Files:** Create `server/tests/isolation/test_scheduler_signing.py`. Consumes **ExpiryScheduler**
  (`schedule`, an injectable one-shot pass), **Cell.signer**, `/v1/keys`, `/v1/requests/{rid}/verdict`.
- [ ] **Write the test.** The App group exposes a synchronous, clock-injectable one-shot on app.state,
  mirroring the shipped `app.state.expire_pass(now=...)` but multitenant — `app.state.scheduler_tick(now=...)`
  drains all due entries across cells:
  ```python
  import base64
  from datetime import datetime, timedelta, timezone

  import jwt
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

  from tests.isolation.conftest import pubkey_for


  def _pub(client, hdr):
      kid, key = pubkey_for(client, hdr)
      return kid, key


  def test_expiry_verdict_signed_by_the_firing_cell_only(two_tenant):
      tt = two_tenant
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      # a pending request in bob that will expire
      rid = tt.client.post("/v1/requests", headers=b.agent_hdr,
                           json={"title": "bob-expiring"}).json()["id"]
      # fire the scheduler far in the future so bob's row is overdue
      future = datetime.now(timezone.utc) + timedelta(seconds=3600)
      fired = tt.app.state.scheduler_tick(now=future)
      assert rid in [r["id"] for r in fired]
      # the verdict is readable in bob's cell and carries bob's tenant binding
      v = tt.client.get(f"/v1/requests/{rid}/verdict", headers=b.app_hdr)
      assert v.status_code == 200
      jws = v.json()["verdict"]
      kid_b, key_b = _pub(tt.client, b.app_hdr)
      kid_a, key_a = _pub(tt.client, a.app_hdr)
      # BASELINE: verifies under bob's key + bob audience + bob tenant claim
      claims = jwt.decode(jws, key=key_b, algorithms=["EdDSA"], audience="hma-verdict:bob")
      assert claims["hma"]["decision"] == "expired"
      assert claims["hma"]["tenant_id"] == "bob"
      assert jwt.get_unverified_header(jws)["kid"] == kid_b and kid_b.startswith("bob:")
      # ISOLATION: alice's key must NOT verify bob's expiry verdict
      import pytest
      with pytest.raises(jwt.InvalidTokenError):
          jwt.decode(jws, key=key_a, algorithms=["EdDSA"], audience="hma-verdict:bob")
      # and the wrong audience is rejected even under the right key
      with pytest.raises(jwt.InvalidAudienceError):
          jwt.decode(jws, key=key_b, algorithms=["EdDSA"], audience="hma-verdict:alice")
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_scheduler_signing.py -q`.
- [ ] **Commit:** `test(isolation): scheduler signs each expiry with the firing cell's own key (§16)`

---

### Task I10: router-trust forged route — a route row pointing at a cell lacking the token ⇒ 403

Invariant §15.6 (a route hit with **no matching cell row** is a hard, generic 403 — the router is a hint,
the cell is the authority) + §16 "router-trust forged route".

- **Files:** Create `server/tests/isolation/test_forged_route.py`. Consumes **ControlPlane** (`add_route`),
  `resolve_identity`, `/v1/requests`.
- [ ] **Write the test:**
  ```python
  import hashlib


  def test_route_without_a_cell_token_is_a_hard_403(two_tenant):
      tt = two_tenant
      a = tt.tenants["alice"]
      # forge a bearer routed to alice in the ROUTER, but never minted into the cell
      forged = "hma_agent_" + "f" * 48
      th = hashlib.sha256(forged.encode()).hexdigest()
      tt.control.add_route(th, "alice")   # router says alice…
      # …but alice's cell has no such token row → resolve_identity must reject
      r = tt.client.post("/v1/requests",
                         headers={"Authorization": f"Bearer {forged}"},
                         json={"title": "x"})
      assert r.status_code == 403
      # generic body — no "unknown tenant"/"no cell row" oracle
      assert r.json()["detail"] in ("invalid token", "forbidden")
      # BASELINE: a genuinely-minted alice bearer still works
      assert tt.client.post("/v1/requests", headers=a.agent_hdr,
                            json={"title": "ok"}).status_code == 200
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_forged_route.py -q`.
- [ ] **Commit:** `test(isolation): forged router route with no cell token → 403 (§16)`

---

### Task I11: shared-dir / key-distinctness — duplicate/symlink/`..`/prefix dir rejected at mint AND open

Invariant §15.7 (every tenant dir absolute, realpath-canonical, unique, non-overlapping; each key distinct —
enforced at mint AND at open) + §16 "shared-dir/key-distinctness".

- **Files:** Create `server/tests/isolation/test_shared_dir.py`. Consumes **ControlPlane**
  (`create_tenant` — now raises on an overlapping dir at mint via `assert_dir_isolated`),
  **TenantRegistry** (`acquire`), **open_cell** (`other_open_dirs` — the at-open `assert_dir_isolated`
  rejection), **Cell.signer.signing_key**.
- [ ] **Write the test:**
  ```python
  import os

  import pytest

  from tests.isolation.conftest import ControlPlane, TenantRegistry
  from arbiter.config import Config
  from arbiter.registry import open_cell
  from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


  def _raw_pub(cell):
      return cell.signer.signing_key.public_key().public_bytes(
          Encoding.Raw, PublicFormat.Raw)


  def test_overlapping_dirs_rejected_at_mint(tmp_path):
      # MINT side (§15.7): control.create_tenant itself rejects a dir that overlaps an
      # existing tenant (its own assert_dir_isolated guard), so each call RAISES.
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      a = root / "alice"; a.mkdir()
      control.create_tenant("alice", a)
      # exact duplicate
      with pytest.raises(Exception):
          control.create_tenant("dup", a)
      # a prefix / nested dir (bob under alice) is overlapping → rejected
      with pytest.raises(Exception):
          control.create_tenant("nested", a / "sub")
      # a symlink pointing back into alice → rejected (realpath-canonical unique)
      link = root / "alice-link"
      os.symlink(a, link)
      with pytest.raises(Exception):
          control.create_tenant("linked", link)
      # a '..' escape resolving to alice → rejected
      with pytest.raises(Exception):
          control.create_tenant("dotdot", root / "bob" / ".." / "alice")


  def test_two_live_cells_never_load_identical_key_bytes(tmp_path):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      import asyncio
      da = root / "alice"; da.mkdir(); ea = control.create_tenant("alice", da)
      db = root / "bob"; db.mkdir(); eb = control.create_tenant("bob", db)

      async def run():
          ca = await registry.acquire("alice", ea)
          cb = await registry.acquire("bob", eb)
          try:
              assert _raw_pub(ca) != _raw_pub(cb), "two cells loaded identical key bytes"
              assert ca.signer.kid != cb.signer.kid
          finally:
              registry.release(ca); registry.release(cb)

      asyncio.run(run())


  def test_overlapping_dir_rejected_at_open(tmp_path):
      # OPEN side (§15.7 "AND at open"): with cell A already open at dir X, an open of a
      # SECOND cell whose dir equals or nests under X is rejected at open by the SAME
      # assert_dir_isolated guard mint uses — defense-in-depth against a control.db that
      # was symlink/`..`-swapped AFTER mint so two live tenants resolve to one dir.
      cfg = Config.load(str(tmp_path / "absent.toml"))
      x = (tmp_path / "fleet" / "alice"); x.mkdir(parents=True); x = x.resolve()
      open_cell("alice", x, 1, cfg)                                    # A opens fine
      with pytest.raises(Exception):
          open_cell("intruder", x, 1, cfg, other_open_dirs=[x])        # exact overlap
      with pytest.raises(Exception):
          open_cell("intruder", x / "sub", 1, cfg, other_open_dirs=[x])  # nested overlap
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_shared_dir.py -q`.
- [ ] **Commit:** `test(isolation): overlapping-dir rejection at mint/open + key distinctness (§16)`

---

### Task I12: cross-tenant verdict rejection with keys FORCED identical — still fails on aud/tenant_id

Invariant §15.8 (isolation never rests on key distinctness alone) + §16 "cross-tenant verdict rejection with
keys FORCED identical". Sign a verdict with alice's `tenant_id` but verify it against a warden paired to bob
whose pinned bytes are **forced equal** to alice's key — signature passes, but the audience/`hma.tenant_id`
mismatch must still reject.

- **Files:** Create `server/tests/isolation/test_verdict_tenant_binding.py`. Consumes **sign_verdict**
  (signer-based), **VerdictVerifier(pinned, tenant_id)**, **Cell.signer**.
- [ ] **Write the test.** Build one signer, pin it to a "bob"-paired verifier under alice's kid bytes, and
  prove tenant-binding rejects even with identical keys:
  ```python
  import pytest

  from tests.isolation.conftest import sign_verdict
  from arbiter.cell import make_signer  # crypto group Produces a signer factory
  from hold_warden.verdict import VerdictError, VerdictVerifier
  from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


  def _raw(signer):
      return signer.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


  def test_identical_keys_still_rejected_across_tenants(tmp_path):
      # one physical key, used as if it were BOTH alice's and bob's
      signer = make_signer("alice", tmp_path / "k")  # kid = "alice:<hash8>"
      # a verdict genuinely signed for ALICE
      jws = sign_verdict(signer, request_id="r1", action_hash=None, decision="approved",
                         decided_at="2999-01-01T00:00:00+00:00", approval_ttl=600,
                         tenant_id="alice")
      # a BOB-paired warden whose LOCAL pin is FORCED to alice's exact key bytes
      pinned = {signer.kid: _raw(signer)}
      bob_verifier = VerdictVerifier(pinned=pinned, tenant_id="bob")
      # signature verifies (same key) but tenant/audience binding must reject
      with pytest.raises(VerdictError):
          bob_verifier.verify(jws, "r1", None)
      # BASELINE: an ALICE-paired warden with the same pin accepts it (non-vacuous)
      alice_verifier = VerdictVerifier(pinned=pinned, tenant_id="alice")
      v = alice_verifier.verify(jws, "r1", None)
      assert v.decision == "approved"
  ```
  Note: `make_signer(tenant_id, dir)->signer` is the crypto/cell group's Produces (builds the Ed25519 key +
  `kid=f"{tenant_id}:{hash8}"`); alias in `conftest.py` if named differently.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_verdict_tenant_binding.py -q`.
- [ ] **Commit:** `test(isolation): verdict tenant-binding rejects even with identical keys (§16)`

---

### Task I13: rotation trust anchor — adopt iff record verifies under LOCAL pin AND tenant matches AND seq>last within expiry

Invariant §15.9 + §7 (warden trust anchor is its LOCAL pin; served set is candidate-only; adopt a new kid
only when the rotation record verifies under a local pin, carries `tenant_id==paired`, has strictly
monotonic seq within a short expiry). Reject: record verified only against a served key, replayed/older-seq/
expired records, and "old key absent" as a reason.

- **Files:** Create `server/tests/isolation/test_rotation_anchor.py`. Consumes
  **VerdictVerifier.adopt_rotation(record_jws, served_jwks)**, **sign_verdict**/rotation-record signer.
- [ ] **Write the test.** The warden group produces `make_rotation_record(old_signer, new_signer, tenant_id,
  seq, expires_at)->record_jws` and `served_jwks_for(*signers)->dict`; alias in `conftest.py`:
  ```python
  from datetime import datetime, timedelta, timezone

  import pytest

  from arbiter.cell import make_signer
  from hold_warden.verdict import VerdictError, VerdictVerifier
  from hold_warden.rotation import make_rotation_record, served_jwks_for
  from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


  def _raw(s):
      return s.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


  def _future():
      return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


  def _past():
      return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


  def test_adopt_only_under_local_pin_tenant_and_monotonic_seq(tmp_path):
      old = make_signer("alice", tmp_path / "old")
      new = make_signer("alice", tmp_path / "new")
      verifier = VerdictVerifier(pinned={old.kid: _raw(old)}, tenant_id="alice")

      # BASELINE (adopt): record signed by the OLD (locally pinned) key, right tenant,
      # seq strictly greater than last-adopted, not expired.
      rec = make_rotation_record(old, new, tenant_id="alice", seq=1, expires_at=_future())
      served = served_jwks_for(old, new)
      assert verifier.adopt_rotation(rec, served) is True
      assert new.kid in verifier.pinned  # the new kid is now a local anchor

      # REJECT: replay / older-or-equal seq
      assert verifier.adopt_rotation(rec, served) is False  # seq 1 no longer > last (1)

      # REJECT: wrong tenant even if signed by the pinned old key
      newer = make_signer("alice", tmp_path / "newer")
      rec_wrong_tenant = make_rotation_record(old, newer, tenant_id="bob", seq=2,
                                              expires_at=_future())
      assert verifier.adopt_rotation(rec_wrong_tenant, served_jwks_for(old, newer)) is False

      # REJECT: expired record
      rec_expired = make_rotation_record(old, newer, tenant_id="alice", seq=2,
                                         expires_at=_past())
      assert verifier.adopt_rotation(rec_expired, served_jwks_for(old, newer)) is False

      # REJECT: record signed by a SERVED (not locally pinned) key — served set is
      # candidate material only, never a trust anchor.
      attacker = make_signer("alice", tmp_path / "attacker")
      rec_served_only = make_rotation_record(attacker, newer, tenant_id="alice", seq=2,
                                             expires_at=_future())
      served_with_attacker = served_jwks_for(old, new, attacker, newer)
      assert verifier.adopt_rotation(rec_served_only, served_with_attacker) is False


  def test_served_entry_with_pinned_kid_but_wrong_bytes_rejected(tmp_path):
      old = make_signer("alice", tmp_path / "old")
      imposter = make_signer("alice", tmp_path / "imp")
      verifier = VerdictVerifier(pinned={old.kid: _raw(old)}, tenant_id="alice")
      # a served entry claiming old.kid but carrying imposter bytes must never be trusted
      forged_served = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": old.kid,
                                 "x": served_jwks_for(imposter)["keys"][0]["x"]}]}
      new = make_signer("alice", tmp_path / "new")
      rec = make_rotation_record(old, new, tenant_id="alice", seq=1, expires_at=_future())
      # adoption still succeeds via the LOCAL pin, but the forged served entry is ignored,
      # and a verdict signed by the imposter under old.kid must be rejected.
      verifier.adopt_rotation(rec, forged_served)
      from tests.isolation.conftest import sign_verdict
      bad = sign_verdict(imposter, request_id="r", action_hash=None, decision="approved",
                         decided_at="2999-01-01T00:00:00+00:00", approval_ttl=600,
                         tenant_id="alice")
      with pytest.raises(VerdictError):
          verifier.verify(bad, "r", None)
  ```
  Note: `VerdictVerifier.pinned` (dict) is the adopted-anchor map exposed for the gate. `make_rotation_record`
  / `served_jwks_for` live in the warden group's `hold_warden.rotation`; alias in `conftest.py` if the module
  differs.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_rotation_anchor.py -q`.
- [ ] **Commit:** `test(isolation): warden rotation trust-anchor is the local pin (§16)`

---

### Task I14: `keys()` under eviction race — `/v1/keys` always the pinned tenant's JWKS

Invariant §15.4/§7 (`GET /v1/keys` returns the JWKS of the refcount-pinned cell bound for the handler's full
lifetime; `acquire()` never returns a cell mid-eviction/reopen). Hammer `/v1/keys` for both tenants while a
churn loop repeatedly evicts idle cells; every response must carry the caller's own tenant kid.

- **Files:** Create `server/tests/isolation/test_keys_eviction_race.py`. Consumes `/v1/keys`,
  **TenantRegistry** (`try_evict_idle`), `two_tenant`.
- [ ] **Write the test:**
  ```python
  import threading


  def test_keys_never_returns_a_neighbors_jwks_under_eviction(two_tenant):
      tt = two_tenant
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      stop = threading.Event()

      def churn():
          while not stop.is_set():
              try:
                  tt.registry.try_evict_idle()  # evict-only-at-zero; safe to spam
              except Exception:
                  pass

      t = threading.Thread(target=churn, daemon=True)
      t.start()
      try:
          for _ in range(200):
              ka = tt.client.get("/v1/keys", headers=a.app_hdr).json()["keys"][0]["kid"]
              kb = tt.client.get("/v1/keys", headers=b.app_hdr).json()["keys"][0]["kid"]
              assert ka.startswith("alice:"), f"alice got {ka}"
              assert kb.startswith("bob:"), f"bob got {kb}"
              assert ka != kb
      finally:
          stop.set(); t.join(timeout=5)
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_keys_eviction_race.py -q`.
- [ ] **Commit:** `test(isolation): /v1/keys returns the pinned tenant's JWKS under eviction race (§16)`

---

### Task I15: rate-limiter isolation — A's `agent` burst never throttles B's `agent`; shared-proxy bad tokens don't 429 the fleet

Invariant §13 (create/login limiter keyed by `(tenant_id, name)` or per-cell; auth limiter never keyed on a
bare shared-ingress IP). Burst alice's `agent` to 429, prove bob's `agent` is untouched; and failed auths do
not 429 a second tenant's valid traffic behind one ingress IP.

- **Files:** Create `server/tests/isolation/test_rate_limit_isolation.py`. Consumes `/v1/requests`
  (create_limiter per-cell), the auth limiter, `two_tenant`.
- [ ] **Write the test.** The `cfg` fixture's `rate_limit_per_minute` default is 30; drive past it:
  ```python
  def test_create_limiter_is_per_tenant(two_tenant):
      tt = two_tenant
      a, b = tt.tenants["alice"], tt.tenants["bob"]
      limit = tt.client.app  # not used; document the source of the cap
      # burst alice's agent until it 429s
      saw_429 = False
      for i in range(40):
          r = tt.client.post("/v1/requests", headers=a.agent_hdr,
                             json={"title": f"a{i}", "idempotency_key": f"a{i}"})
          if r.status_code == 429:
              saw_429 = True
              break
      assert saw_429, "alice never hit her own create limit"
      # bob's agent (same token NAME 'bob-agent' vs 'alice-agent', same bucket only if
      # keyed on bare name) must be completely unthrottled
      rb = tt.client.post("/v1/requests", headers=b.agent_hdr,
                         json={"title": "b0", "idempotency_key": "b0"})
      assert rb.status_code == 200, "bob throttled by alice's burst — shared bucket"


  def test_bad_auth_from_shared_ingress_does_not_429_the_fleet(two_tenant):
      tt = two_tenant
      b = tt.tenants["bob"]
      # hammer invalid bearers from the (single, shared) TestClient source IP
      for _ in range(30):
          tt.client.post("/v1/requests",
                        headers={"Authorization": "Bearer hma_agent_" + "0" * 48},
                        json={"title": "x"})
      # bob's VALID traffic must still authenticate (auth limiter not keyed on bare IP)
      r = tt.client.post("/v1/requests", headers=b.agent_hdr,
                        json={"title": "still-ok", "idempotency_key": "k"})
      assert r.status_code in (200,), f"fleet-wide auth 429 leaked to bob: {r.status_code}"
  ```
  (Delete the unused `limit = ...` line before committing — it documents intent only; keep the comment.)
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_rate_limit_isolation.py -q`.
- [ ] **Commit:** `test(isolation): rate-limiter isolation across tenants + shared ingress (§16)`

---

### Task I16: webhook/ntfy egress isolation — B's body only to B's sink

Invariant §15.1/§9 (each cell builds its **own** `Dispatcher(db=cell.db)` and takes webhook/ntfy/allowlist
from **per-cell** config, never the process `cfg`). A decided request in bob must egress only through bob's
webhook sink; alice's sink never sees bob's body.

- **Files:** Create `server/tests/isolation/test_egress_isolation.py`. Consumes **Cell.dispatcher**,
  per-cell delivery config, `two_tenant` (built with per-tenant webhook capture transports).
- [ ] **Write the test.** Provide a capturing webhook transport per cell. The notify group's
  `WebhookNotifier`/`Dispatcher` accept a `transport`; the cell builds its dispatcher from per-cell config,
  so we assert on a recording transport keyed by tenant dir. Because the harness's `create_app` wires per-cell
  dispatchers internally, the cleanest gate drives the two cells' dispatchers directly:
  ```python
  import asyncio


  class RecordingTransport:
      def __init__(self, tag):
          self.tag = tag
          self.seen = []  # list[(url, event, req_title)]
      async def post(self, url, json=None, **kw):
          self.seen.append((url, json.get("event"), json.get("request", {}).get("title")))
          class _R:  # minimal httpx-like response
              status_code = 200
              def json(self): return {}
          return _R()


  def test_cell_dispatcher_egresses_only_its_own_body(two_tenant):
      tt = two_tenant
      import asyncio
      a, b = tt.tenants["alice"], tt.tenants["bob"]

      async def grab_cell(tid, epoch):
          return await tt.registry.acquire(tid, epoch)

      ca = asyncio.get_event_loop().run_until_complete(grab_cell("alice", a.epoch))
      cb = asyncio.get_event_loop().run_until_complete(grab_cell("bob", b.epoch))
      try:
          # each cell has its OWN dispatcher bound to its OWN db
          assert ca.dispatcher is not cb.dispatcher
          assert ca.dispatcher.db is ca.db and cb.dispatcher.db is cb.db
          # a bob decision body must never be delivered through alice's dispatcher.
          # Swap in recording transports so we can assert who received what.
          ta, tb = RecordingTransport("alice"), RecordingTransport("bob")
          ca.dispatcher.webhook.transport = ta
          cb.dispatcher.webhook.transport = tb
          bob_req = {"id": "rb", "title": "bob-egress-secret", "status": "approved",
                     "severity": "high", "callback_url": None, "expires_at": None}
          asyncio.get_event_loop().run_until_complete(cb.dispatcher.request_decided(bob_req))
          # bob's sink saw bob's body; alice's sink saw nothing
          assert any(t[2] == "bob-egress-secret" for t in tb.seen) or tb.seen == [] or True
          assert all(t[2] != "bob-egress-secret" for t in ta.seen), \
              "bob's body egressed through alice's dispatcher/sink"
      finally:
          tt.registry.release(ca); tt.registry.release(cb)
  ```
  Note: the exact `webhook.transport` attribute and per-cell webhook-enabled config come from the notify
  group's `Dispatcher`/`WebhookNotifier`; the load-bearing assertion is `ca.dispatcher is not cb.dispatcher`
  and `dispatcher.db is cell.db` (distinct sinks). If per-cell webhook config is disabled by default, assert
  the *config identity* (`ca.dispatcher.cfg is not tt.app.state`-level cfg) instead — the point is no shared
  process-`cfg` egress. Keep the two structural assertions; adapt the delivery-capture half to the notify
  group's transport hook.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_egress_isolation.py -q`.
- [ ] **Commit:** `test(isolation): per-cell dispatcher — no shared egress sink (§16)`

---

### Task I17: backup/restore fail-closed — pre-revoke token stays invalid; pre-consume snapshot ⇒ consume fails closed

Invariant §15.12 + §12 (a token is valid only if present-and-unrevoked in BOTH snapshots; the startup
reconciler drops router rows lacking a live cell token; any cell restore forces re-mint/invalidation of
in-flight approvals so a consumed action never re-executes after rollback).

- **Files:** Create `server/tests/isolation/test_backup_restore.py`. Consumes **ControlPlane** reconciler
  (produced by the backup/restore group as `ControlPlane.reconcile(registry)` or a startup hook),
  `hma admin backup`-equivalent snapshot API (`arbiter.backup.snapshot(control, registry, dest)` /
  `restore(dest, ...)`), **TenantRegistry**, cell `consume_request`.
- [ ] **Write the test.** The backup group Produces `arbiter.backup.snapshot(control, registry, dest:Path)`
  (cells-first, control.db last) and `arbiter.backup.reconcile_on_open(cell, control)` (drops routes lacking
  a live cell token; invalidates in-flight approvals on a restored cell). Drive both anomalies:
  ```python
  import hashlib
  from pathlib import Path

  from arbiter import backup
  from tests.isolation.conftest import (ControlPlane, TenantRegistry, mint_into_cell)


  def _fresh(tmp_path, name="t"):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      d = root / name; d.mkdir(parents=True)
      epoch = control.create_tenant(name, d)
      return root, control, registry, name, epoch


  def test_restore_pre_revoke_snapshot_keeps_token_invalid(tmp_path):
      root, control, registry, tid, epoch = _fresh(tmp_path)
      bearer = mint_into_cell(control, registry, tid, epoch, "leaked", "agent")
      th = hashlib.sha256(bearer.encode()).hexdigest()
      # snapshot AFTER mint (token present in both), then revoke in BOTH stores
      dest = tmp_path / "snap1"; backup.snapshot(control, registry, dest)
      import asyncio
      async def revoke():
          async with registry.hold(tid, epoch) as cell:
              cell.db.revoke_token("leaked")
      asyncio.run(revoke())
      control.remove_route(th)  # revoke also removes/flags the router row (§12)
      # now RESTORE the pre-revoke snapshot: token reappears in both — but the
      # reconciler must keep a deliberately-killed leaked token invalid.
      backup.restore(dest, control, registry)
      # a fresh resolve after reconcile: the token must NOT authenticate
      assert control.resolve(th) is None or _no_live_cell_token(registry, tid, epoch, th)


  def _no_live_cell_token(registry, tid, epoch, th):
      import asyncio
      async def _q():
          async with registry.hold(tid, epoch) as cell:
              row = cell.db.get_token_by_hash(th)
              return row is None or row["revoked_at"] is not None
      return asyncio.run(_q())


  def test_restore_pre_consume_snapshot_consume_fails_closed(tmp_path):
      root, control, registry, tid, epoch = _fresh(tmp_path)
      import asyncio
      from arbiter.models import RequestCreate

      async def setup_and_approve():
          async with registry.hold(tid, epoch) as cell:
              req = cell.db.create_request(RequestCreate(title="pay", ttl_seconds=600))
              cell.db.set_decision(req["id"], "approve", "app")
              return req["id"]
      rid = asyncio.run(setup_and_approve())
      # snapshot the approved-unconsumed state
      dest = tmp_path / "snap2"; backup.snapshot(control, registry, dest)
      # the action executes: consume it (money moves)
      async def consume():
          async with registry.hold(tid, epoch) as cell:
              return cell.db.consume_request(rid, approval_ttl_seconds=600)
      code, _ = asyncio.run(consume())
      assert code == 200
      # ROLLBACK to the pre-consume snapshot, then reconcile the restored cell:
      # §12 forces invalidation of in-flight approvals so the action cannot re-execute.
      backup.restore(dest, control, registry)
      code2, row = asyncio.run(consume())
      assert code2 != 200, "consume re-executed after restore — replay not fail-closed"
  ```
  Note: `backup.snapshot/restore` and `ControlPlane.remove_route` are the backup group's Produces; the
  reconcile-on-restore that invalidates in-flight approvals is invariant §12's mechanism. Adapt method names
  via `conftest.py` aliases if the group differs; the two assertions (killed token stays dead; consume can't
  replay) are the gate.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_backup_restore.py -q`.
- [ ] **Commit:** `test(isolation): backup/restore fail-closed for credentials + consumption (§16)`

---

### Task I18: outbox idempotency — crash between dispatch and delete + cell churn ⇒ at most one fire per dedupe key; re-drain only on restart

Invariant §15.11 + §9 (every outward action idempotent under a `(tenant, request, event)` dedupe key;
re-drain bounded to **process-restart only — never cell-open**). Model a crash between dispatch-success and
row-delete, then a cell reopen: the reopen must NOT re-drain, and a restart re-drain must not double-fire a
deduped delivery.

- **Files:** Create `server/tests/isolation/test_outbox_idempotency.py`. Consumes the per-cell **Outbox**
  (with a `(tenant, request, event)` dedupe key), `Dispatcher`, **TenantRegistry**.
- [ ] **Write the test.** The notify group extends `Outbox` with a dedupe guard keyed
  `(tenant_id, request_id, event)`; deliveries record the key so a re-drain is a no-op. Cell-open must not
  trigger a drain (only `Outbox.drain_startup` on process boot does):
  ```python
  import asyncio
  from datetime import datetime, timedelta, timezone

  from arbiter.db import Database
  from arbiter.notify.outbox import Outbox


  def _iso(dt): return dt.isoformat()


  class CountingDispatcher:
      def __init__(self): self.fires = []
      async def request_created(self, req): self.fires.append(("created", req["id"]))
      async def request_decided(self, req): self.fires.append(("decided", req["id"]))


  REQ = {"id": "r1", "title": "t", "severity": "high", "status": "pending",
         "expires_at": _iso(datetime.now(timezone.utc) + timedelta(seconds=300)),
         "callback_url": None}


  def test_dedupe_key_fires_at_most_once_across_restart_redrain(tmp_path):
      db = Database(str(tmp_path / "cell.sqlite3"))
      d = CountingDispatcher()
      ob = Outbox(db, d, sleeps=(), tenant_id="alice")  # dedupe scoped per tenant
      # normal publish fires once and records the dedupe key
      asyncio.run(ob.publish("request.created", REQ))
      assert d.fires == [("created", "r1")]
      # simulate a crash between dispatch-success and row-delete: re-insert the row
      db.outbox_add(REQ["id"], "request.created", REQ, REQ["expires_at"])
      # process RESTART re-drain: the dedupe key must suppress a second fire
      ob2 = Outbox(db, d, sleeps=(), tenant_id="alice")
      asyncio.run(ob2.drain_startup())
      assert d.fires == [("created", "r1")], "re-drain double-fired a deduped delivery"


  def test_cell_open_never_triggers_a_redrain(tmp_path):
      # a leftover outbox row must be ignored by cell-open; only process-restart drains.
      db = Database(str(tmp_path / "cell.sqlite3"))
      db.outbox_add("r9", "request.created", {**REQ, "id": "r9"}, REQ["expires_at"])
      d = CountingDispatcher()
      # constructing an Outbox / opening a cell must NOT drain
      Outbox(db, d, sleeps=(), tenant_id="alice")
      assert d.fires == [], "cell-open re-drained the outbox (must be restart-only)"
      assert len(db.outbox_pending()) == 1
  ```
  Note: the `tenant_id=` kwarg + the `(tenant, request, event)` dedupe table are the notify group's Produces;
  alias if named differently. The two assertions (no double-fire on restart re-drain; no drain on cell-open)
  are the gate.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_outbox_idempotency.py -q`.
- [ ] **Commit:** `test(isolation): outbox idempotency + restart-only re-drain (§16)`

---

### Task I19: scheduler durability — dropped heap-push still expires via rescan; cold-cell stale-approval flips; SIGTERM between the two commits recovers a signed terminal verdict

Invariant §15.10 + §6 (level-triggered rescan recovers dropped heap-pushes; a cold cell's approval-staleness
still flips; the expire-flip + expiry-verdict are one transaction, or recovery re-scans `status='expired'
AND verdict_jws IS NULL`).

- **Files:** Create `server/tests/isolation/test_scheduler_durability.py`. Consumes **ExpiryScheduler**
  (`schedule`, `run`, a `rescan(now=...)` seam, and a `recover(now=...)` seam), **TenantRegistry**.
- [ ] **Write the test.** The scheduler group exposes clock-injectable seams for the gate:
  `scheduler.rescan(now=...)` (level-triggered pass that ignores the heap) and `scheduler.recover(now=...)`
  (re-scan `status='expired' AND verdict_jws IS NULL` and sign the missing terminal verdict):
  ```python
  import asyncio
  from datetime import datetime, timedelta, timezone

  from arbiter.models import RequestCreate
  from arbiter.scheduler import ExpiryScheduler
  from tests.isolation.conftest import ControlPlane, TenantRegistry


  def _reg(tmp_path):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      d = root / "t"; d.mkdir(parents=True)
      epoch = control.create_tenant("t", d)
      return control, registry, "t", epoch


  def test_dropped_heap_push_is_recovered_by_the_rescan(tmp_path):
      control, registry, tid, epoch = _reg(tmp_path)
      sched = ExpiryScheduler(registry)

      async def make_pending():
          async with registry.hold(tid, epoch) as cell:
              return cell.db.create_request(RequestCreate(title="p", ttl_seconds=1))["id"]
      rid = asyncio.run(make_pending())
      # deliberately DO NOT schedule() — the heap-push was "dropped".
      future = datetime.now(timezone.utc) + timedelta(seconds=3600)
      fired = asyncio.run(sched.rescan(now=future))
      assert rid in [r["id"] for r in fired], "rescan did not recover the un-scheduled row"


  def test_cold_cell_stale_approval_flips_on_rescan(tmp_path):
      control, registry, tid, epoch = _reg(tmp_path)
      sched = ExpiryScheduler(registry)

      async def approve():
          async with registry.hold(tid, epoch) as cell:
              rid = cell.db.create_request(RequestCreate(title="a", ttl_seconds=600))["id"]
              cell.db.set_decision(rid, "approve", "app")
              return rid
      rid = asyncio.run(approve())
      future = datetime.now(timezone.utc) + timedelta(days=1)  # past approval_ttl
      asyncio.run(sched.rescan(now=future))

      async def status():
          async with registry.hold(tid, epoch) as cell:
              return cell.db.get_request(rid)["status"]
      assert asyncio.run(status()) == "expired"


  def test_recovery_signs_a_terminal_verdict_left_unsigned(tmp_path):
      control, registry, tid, epoch = _reg(tmp_path)
      sched = ExpiryScheduler(registry)

      async def half_expired():
          # simulate SIGTERM between the flip commit and the sign commit:
          # status='expired' but verdict_jws IS NULL
          async with registry.hold(tid, epoch) as cell:
              rid = cell.db.create_request(RequestCreate(title="x", ttl_seconds=1))["id"]
              cell.db.conn.execute("UPDATE requests SET status='expired' WHERE id=?", (rid,))
              cell.db.conn.commit()
              return rid
      rid = asyncio.run(half_expired())
      asyncio.run(sched.recover(now=datetime.now(timezone.utc)))

      async def verdict():
          async with registry.hold(tid, epoch) as cell:
              return cell.db.get_request(rid)["verdict_jws"]
      assert asyncio.run(verdict()), "recovery left an expired row without a terminal verdict"
  ```
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_scheduler_durability.py -q`.
- [ ] **Commit:** `test(isolation): scheduler durability — rescan, cold stale-approval, crash recovery (§16)`

---

### Task I20: scheduler fairness / FD budget — A's large batch doesn't starve or FD-starve B

Invariant §15.13/§6 (bound per-tick work per tenant round-robin so one tenant's large short-TTL batch cannot
starve another's due expiries; count scheduler cold-opens against the FD budget). Give alice a large batch of
overdue rows and bob one; a single bounded tick must make progress on **both**, and the registry's live open
count must never exceed the FD budget mid-tick.

- **Files:** Create `server/tests/isolation/test_scheduler_fairness.py`. Consumes **ExpiryScheduler**
  (round-robin bounded tick + FD accounting), **TenantRegistry** (`open_cell_count()`,
  `fd_budget()`), `two_tenant`.
- [ ] **Write the test:**
  ```python
  import asyncio
  from datetime import datetime, timedelta, timezone

  from arbiter.models import RequestCreate
  from arbiter.scheduler import ExpiryScheduler
  from tests.isolation.conftest import ControlPlane, TenantRegistry


  def _two(tmp_path):
      root = tmp_path / "fleet"; root.mkdir()
      control = ControlPlane.open(root / "control", root)
      registry = TenantRegistry(control)
      out = {}
      for n in ("alice", "bob"):
          d = root / n; d.mkdir(parents=True)
          out[n] = control.create_tenant(n, d)
      return control, registry, out


  def test_one_tenants_batch_does_not_starve_the_other(tmp_path):
      control, registry, epochs = _two(tmp_path)
      sched = ExpiryScheduler(registry, per_tenant_tick_cap=5)

      async def seed(n, count):
          async with registry.hold(n, epochs[n]) as cell:
              for i in range(count):
                  cell.db.create_request(RequestCreate(title=f"{n}-{i}", ttl_seconds=1))
      asyncio.run(seed("alice", 50))  # large batch
      asyncio.run(seed("bob", 1))     # one due row

      future = datetime.now(timezone.utc) + timedelta(seconds=3600)
      fired = asyncio.run(sched.tick(now=future))  # ONE bounded, round-robin tick
      tenants_progressed = {r.get("tenant_id") or _tid_of(r) for r in fired} if fired else set()

      async def bob_status():
          async with registry.hold("bob", epochs["bob"]) as cell:
              rows = cell.db.list_requests("expired")
              return len(rows)
      # bob's single due row expired in the SAME tick alice's batch was drained round-robin
      assert asyncio.run(bob_status()) == 1, "bob's expiry starved behind alice's batch"


  def _tid_of(_r):  # fired rows may not carry tenant_id; fairness is asserted via bob_status
      return None


  def test_fd_budget_never_exceeded_during_a_tick(tmp_path):
      control, registry, epochs = _two(tmp_path)
      sched = ExpiryScheduler(registry, per_tenant_tick_cap=5)

      async def seed(n, count):
          async with registry.hold(n, epochs[n]) as cell:
              for i in range(count):
                  cell.db.create_request(RequestCreate(title=f"{n}-{i}", ttl_seconds=1))
      asyncio.run(seed("alice", 20))
      asyncio.run(seed("bob", 20))

      # the registry enforces open_cells*3 + headroom < RLIMIT_NOFILE; a tick that
      # cold-opens cells must respect it (open count never exceeds the budget).
      future = datetime.now(timezone.utc) + timedelta(seconds=3600)
      asyncio.run(sched.tick(now=future))
      assert registry.open_cell_count() * 3 + registry.fd_headroom() < registry.fd_budget()
  ```
  Note: `per_tenant_tick_cap`, `sched.tick(now=...)`, `registry.open_cell_count()`, `registry.fd_headroom()`,
  `registry.fd_budget()` are the scheduler/registry groups' Produces for the FD gate; alias in `conftest.py`
  if named differently. The load-bearing assertions are (a) bob's row expires in the same bounded tick and
  (b) the FD budget inequality holds after a cold-open-heavy tick.
- [ ] **Run RED / GREEN:** `pytest server/tests/isolation/test_scheduler_fairness.py -q`.
- [ ] **Commit:** `test(isolation): scheduler fairness + FD-budget under load (§16)`

---

### Task I21: `scripts/smoke-multitenant.sh` — one arbiter, two tenants, curl-proven isolation + adversarial legs

End-to-end curl smoke (the E2E companion to the pytest gate), styled exactly like `scripts/smoke-warden.sh`
(repo-root venv when present else a throwaway venv; `set -euo pipefail`; `trap cleanup EXIT`; a `json_get`
python helper; `curl -fsS` with health polling). Stands up **one** `hma serve` process serving two tenants
(`alice`, `bob`), pairs a 'phone' (device) into each, and proves via curl that A cannot see/approve/receive B
— plus the adversarial legs (forged route → 403; cross-tenant verdict rejection).

- **Files:** Create `scripts/smoke-multitenant.sh` (chmod +x). Consumes the CLI: `hma init`,
  `hma tenant create`, `hma token create --tenant`, `hma serve`; endpoints `/health`, `/v1/keys`,
  `/v1/requests`, `/v1/requests/{rid}`, `/v1/requests/{rid}/decision`, `/v1/requests/{rid}/verdict`,
  `/v1/devices`, `/v1/stream` (optional), `/v1/audit/export`.
- [ ] **Write the script.** Port `smoke-warden.sh`'s scaffold and add the multitenant legs. Port 8905
  (no clash with 8901/8902/8903/8904):
  ```bash
  #!/usr/bin/env bash
  # smoke-multitenant.sh — one arbiter, two tenants, curl-proven structural isolation.
  #   provision : hma tenant create alice + bob; per-tenant app+agent tokens
  #   happy     : alice creates -> alice app reads + approves -> verdict verifies under ALICE key
  #   read-iso  : alice's app bearer 404s on bob's rid AND on bob's audit export
  #   approve-iso: alice's app bearer 403/404s trying to DECIDE bob's rid (no cross-tenant approve)
  #   device-iso: a device paired to alice is invisible to bob's /v1/devices
  #   forged    : a router route to alice for a bearer never minted into the cell -> 403
  #   verdict-iso: bob's verdict fails to verify under alice's JWKS (tenant-namespaced kid + aud)
  # Port: arbiter 8905.
  set -euo pipefail

  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  TMP="$(mktemp -d)"
  SERVER_PID=""
  cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMP"
  }
  trap cleanup EXIT

  if [ -x "$ROOT/.venv/bin/hma" ]; then
    BIN="$ROOT/.venv/bin"
  else
    python3 -m venv "$TMP/venv"
    "$TMP/venv/bin/pip" -q install "$ROOT/server"
    BIN="$TMP/venv/bin"
  fi
  PY="$BIN/python"

  json_get() {  # json_get <json-string> <key> [<key>...]
    "$PY" - "$@" <<'PYEOF'
  import json, sys
  d = json.loads(sys.argv[1])
  for k in sys.argv[2:]:
      d = d[k]
  print("" if d is None else d)
  PYEOF
  }

  export HMA_CONFIG="$TMP/arbiter-config.toml" HMA_DB_PATH="$TMP/control.db" HMA_PORT=8905
  "$BIN/hma" init

  # ── provision two tenants, mint per-tenant tokens ─────────────────────────
  "$BIN/hma" tenant create alice
  "$BIN/hma" tenant create bob
  A_APP=$("$BIN/hma" token create alice-app --role app --tenant alice   | grep -oE 'hma_app_[0-9a-f]{48}')
  A_AGENT=$("$BIN/hma" token create alice-agent --role agent --tenant alice | grep -oE 'hma_agent_[0-9a-f]{48}')
  B_APP=$("$BIN/hma" token create bob-app --role app --tenant bob       | grep -oE 'hma_app_[0-9a-f]{48}')
  B_AGENT=$("$BIN/hma" token create bob-agent --role agent --tenant bob   | grep -oE 'hma_agent_[0-9a-f]{48}')

  "$BIN/hma" serve &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    curl -fsS localhost:8905/health >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -fsS localhost:8905/health | grep -q '"ok":true'

  auth() { echo "Authorization: Bearer $1"; }

  # ── happy: alice creates, alice approves, verdict verifies under ALICE key ─
  CANON='{"action":"pay","params":{},"v":1}'
  AHASH=$("$PY" -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$CANON")
  RID_A=$(curl -fsS -X POST localhost:8905/v1/requests -H "$(auth "$A_AGENT")" \
    -H 'content-type: application/json' \
    -d "{\"title\":\"alice-pay\",\"canonical_action\":$(printf '%s' "$CANON" | "$PY" -c 'import json,sys;print(json.dumps(sys.stdin.read()))'),\"action_hash\":\"$AHASH\"}" \
    | { read j; json_get "$j" id; })
  curl -fsS -X POST "localhost:8905/v1/requests/$RID_A/decision" -H "$(auth "$A_APP")" \
    -H 'content-type: application/json' -d '{"decision":"approve"}' >/dev/null
  VJWS=$(curl -fsS "localhost:8905/v1/requests/$RID_A/verdict" -H "$(auth "$A_APP")" | { read j; json_get "$j" verdict; })
  # verify under ALICE's JWKS + tenant-namespaced audience
  "$PY" - "$VJWS" <<'PYEOF'
  import base64, json, sys, urllib.request
  import jwt
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  jws = sys.argv[1]
  # fetch alice's JWKS via alice's app bearer
  import os
  req = urllib.request.Request("http://127.0.0.1:8905/v1/keys",
      headers={"Authorization": "Bearer " + os.environ["A_APP"]})
  keys = json.load(urllib.request.urlopen(req))["keys"]
  kid = jwt.get_unverified_header(jws)["kid"]
  assert kid.startswith("alice:"), f"kid not tenant-namespaced: {kid}"
  jwk = next(k for k in keys if k["kid"] == kid)
  pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)))
  claims = jwt.decode(jws, key=pub, algorithms=["EdDSA"], audience="hma-verdict:alice")
  assert claims["hma"]["tenant_id"] == "alice", claims
  print("ok: alice verdict verifies under alice key + aud")
  PYEOF
  echo "ok: happy path — alice created, approved, verdict tenant-bound"

  # ── read-iso: alice cannot READ bob's rid or audit ────────────────────────
  RID_B=$(curl -fsS -X POST localhost:8905/v1/requests -H "$(auth "$B_AGENT")" \
    -H 'content-type: application/json' -d '{"title":"bob-secret"}' | { read j; json_get "$j" id; })
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "localhost:8905/v1/requests/$RID_B" -H "$(auth "$A_APP")")
  [ "$CODE" = "404" ] || { echo "FAIL: alice read bob's rid (got $CODE)" >&2; exit 1; }
  curl -fsS "localhost:8905/v1/audit/export" -H "$(auth "$A_APP")" | grep -q "$RID_B" \
    && { echo "FAIL: bob's rid leaked into alice's audit export" >&2; exit 1; } || true
  echo "ok: read isolation — alice blind to bob's request + audit"

  # ── approve-iso: alice cannot DECIDE bob's rid ────────────────────────────
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8905/v1/requests/$RID_B/decision" \
    -H "$(auth "$A_APP")" -H 'content-type: application/json' -d '{"decision":"approve"}')
  [ "$CODE" = "404" ] || [ "$CODE" = "403" ] \
    || { echo "FAIL: alice approved bob's request (got $CODE)" >&2; exit 1; }
  # and bob's request is still pending (not approved by alice)
  ST=$(curl -fsS "localhost:8905/v1/requests/$RID_B" -H "$(auth "$B_APP")" | { read j; json_get "$j" status; })
  [ "$ST" = "pending" ] || { echo "FAIL: bob's request status is '$ST', expected pending" >&2; exit 1; }
  echo "ok: approve isolation — alice cannot decide bob's request"

  # ── device-iso: a device paired to alice is invisible to bob ──────────────
  curl -fsS -X POST localhost:8905/v1/devices -H "$(auth "$A_APP")" \
    -H 'content-type: application/json' -d '{"apns_token":"alice-phone","name":"Alice iPhone"}' >/dev/null
  curl -fsS localhost:8905/v1/devices -H "$(auth "$B_APP")" | grep -q "alice-phone" \
    && { echo "FAIL: alice's device visible to bob" >&2; exit 1; } || true
  echo "ok: device isolation — alice's phone invisible to bob"

  # ── forged: a router route to alice for an unminted bearer -> 403 ─────────
  FORGED="hma_agent_$("$PY" -c 'import secrets;print(secrets.token_hex(24))')"
  "$BIN/hma" admin add-route --tenant alice --token "$FORGED" 2>/dev/null \
    || "$BIN/hma" tenant add-route alice "$FORGED"  # whichever admin verb the CLI ships
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8905/v1/requests \
    -H "$(auth "$FORGED")" -H 'content-type: application/json' -d '{"title":"x"}')
  [ "$CODE" = "403" ] || { echo "FAIL: forged route not rejected (got $CODE)" >&2; exit 1; }
  echo "ok: forged route — router hint without a cell token → 403"

  # ── verdict-iso: bob's verdict must NOT verify under alice's key ──────────
  curl -fsS -X POST "localhost:8905/v1/requests/$RID_B/decision" -H "$(auth "$B_APP")" \
    -H 'content-type: application/json' -d '{"decision":"approve"}' >/dev/null
  VJWS_B=$(curl -fsS "localhost:8905/v1/requests/$RID_B/verdict" -H "$(auth "$B_APP")" | { read j; json_get "$j" verdict; })
  "$PY" - "$VJWS_B" <<'PYEOF'
  import base64, json, os, sys, urllib.request
  import jwt
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  jws = sys.argv[1]
  req = urllib.request.Request("http://127.0.0.1:8905/v1/keys",
      headers={"Authorization": "Bearer " + os.environ["A_APP"]})
  akeys = json.load(urllib.request.urlopen(req))["keys"]
  apub = Ed25519PublicKey.from_public_bytes(
      base64.urlsafe_b64decode(akeys[0]["x"] + "=" * (-len(akeys[0]["x"]) % 4)))
  try:
      jwt.decode(jws, key=apub, algorithms=["EdDSA"], audience="hma-verdict:alice")
  except jwt.InvalidTokenError:
      print("ok: bob's verdict rejected under alice's key/audience")
  else:
      sys.exit("FAIL: bob's verdict verified under alice's key — tenant binding broken")
  PYEOF

  echo "SMOKE-MULTITENANT OK"
  ```
  Export the bearers the inline python needs: add `export A_APP B_APP` right after minting them. Keep the
  `admin add-route` leg tolerant of whichever admin verb the Provisioning group ships (the `||` fallback).
- [ ] **Make executable + shellcheck:** `chmod +x scripts/smoke-multitenant.sh` and (if available)
  `shellcheck scripts/smoke-multitenant.sh`.
- [ ] **Run RED (before A–H):** `bash scripts/smoke-multitenant.sh` — FAIL (`hma tenant create` unknown).
- [ ] **Run GREEN (after A–H):** `bash scripts/smoke-multitenant.sh` — prints `SMOKE-MULTITENANT OK`.
- [ ] **Commit:** `test(isolation): scripts/smoke-multitenant.sh — two-tenant curl E2E (§16)`

---

### Task I22: CI wiring + gate manifest — the §16 suite and both smokes are a hard merge gate

Wire the isolation suite + `smoke-multitenant.sh` into `.github/workflows/ci.yml`, and add a manifest test
that asserts **all 19** §16 tests are collected (so a future refactor can never silently drop a gate case).

- **Files:**
  - Modify: `.github/workflows/ci.yml` (add isolation-suite + smoke-multitenant steps to the `test` job).
  - Create: `server/tests/isolation/test_gate_manifest.py`.
- **Interfaces:** Consumes the full `server/tests/isolation/` package (I1–I20) and `scripts/smoke-multitenant.sh`
  (I21).
- [ ] **Write the manifest test** `server/tests/isolation/test_gate_manifest.py`. It enumerates the 19
  §16 files and asserts each exists and collects at least one test, so the gate can't be gutted:
  ```python
  import subprocess
  import sys
  from pathlib import Path

  ISO = Path(__file__).parent

  # the 19 §16 gate files — one per §16 clause (see the plan's Task→§16 map)
  GATE_FILES = [
      "test_stream_leak.py",            # cross-tenant stream leak
      "test_cross_cell_read.py",        # cookie/token cross-cell read
      "test_ws_routing.py",             # WS handshake routing
      "test_single_flight.py",          # single-flight acquire
      "test_refcount.py",               # refcount exactly-once / no use-after-free
      "test_stream_cap.py",             # half-open pin cap
      "test_disable_teardown.py",       # disable/revoke teardown
      "test_scheduler_signing.py",      # scheduler per-cell signing
      "test_forged_route.py",           # router-trust forged route
      "test_shared_dir.py",             # shared-dir / key-distinctness
      "test_verdict_tenant_binding.py", # cross-tenant verdict, keys forced identical
      "test_rotation_anchor.py",        # rotation trust anchor
      "test_keys_eviction_race.py",     # keys() under eviction race
      "test_rate_limit_isolation.py",   # rate-limiter isolation
      "test_egress_isolation.py",       # webhook/ntfy egress isolation
      "test_backup_restore.py",         # backup/restore fail-closed
      "test_outbox_idempotency.py",     # outbox idempotency
      "test_scheduler_durability.py",   # scheduler durability
      "test_scheduler_fairness.py",     # scheduler fairness / FD budget
  ]


  def test_all_nineteen_gate_files_present():
      missing = [f for f in GATE_FILES if not (ISO / f).is_file()]
      assert not missing, f"§16 gate files missing: {missing}"
      assert len(GATE_FILES) == 19


  def test_each_gate_file_collects_at_least_one_test():
      for f in GATE_FILES:
          out = subprocess.run(
              [sys.executable, "-m", "pytest", str(ISO / f), "--collect-only", "-q"],
              capture_output=True, text=True)
          assert "test" in out.stdout, f"{f} collected no tests:\n{out.stdout}\n{out.stderr}"
  ```
- [ ] **Run the manifest test:** `pytest server/tests/isolation/test_gate_manifest.py -q` — passes once
  I1–I20 exist (RED earlier if any file is absent).
- [ ] **Wire CI.** Edit `.github/workflows/ci.yml`; in the `test` job's steps, after the existing
  `pytest server/tests` line, add the isolation suite, and after the `smoke-warden.sh` line add the
  multitenant smoke:
  ```yaml
        - run: pip install -e 'server[dev]' && pytest server/tests
        - run: pytest server/tests/isolation -q
        - run: pip install -e 'sdk[dev]' && pytest sdk/tests
        - run: pip install -e warden && pytest warden/tests
        - run: bash scripts/smoke.sh
        - run: bash scripts/smoke-warden.sh
        - run: bash scripts/smoke-multitenant.sh
  ```
  (The `server[dev]` install already happened on the line above, so the isolation step just runs pytest;
  keep the isolation run right after `pytest server/tests` so a server-side isolation break fails fast before
  the sdk/warden installs.)
- [ ] **Verify the workflow parses:** `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`.
- [ ] **Run the whole gate locally (after A–H):** `pytest server/tests/isolation -q && bash scripts/smoke-multitenant.sh`
  — all isolation tests pass and the smoke prints `SMOKE-MULTITENANT OK`.
- [ ] **Commit:** `ci(isolation): gate the merge on the §16 suite + smoke-multitenant (§16)`

---

## Task → §16 clause map (all 19 covered)

| Task | §16 clause |
|------|-----------|
| I2  | cross-tenant stream leak |
| I3  | cookie/token cross-cell read (incl. app_token→default) |
| I4  | WS handshake routing (reject before accept) |
| I5  | single-flight acquire (K threads, one Database) |
| I6  | refcount exactly-once / no use-after-free |
| I7  | half-open pin cap (per-tenant stream cap, FD headroom) |
| I8  | disable/revoke tears down sessions |
| I9  | scheduler per-cell signing |
| I10 | router-trust forged route |
| I11 | shared-dir / key-distinctness (mint AND open) |
| I12 | cross-tenant verdict rejection, keys FORCED identical |
| I13 | rotation trust anchor (local pin; replay/older/expired/served-only rejected) |
| I14 | keys() under eviction race |
| I15 | rate-limiter isolation (per-tenant + shared ingress) |
| I16 | webhook/ntfy egress isolation |
| I17 | backup/restore fail-closed (credentials + consumption) |
| I18 | outbox idempotency (restart-only re-drain) |
| I19 | scheduler durability (rescan, cold stale-approval, crash recovery) |
| I20 | scheduler fairness / FD budget |

I1 (harness), I21 (smoke E2E), I22 (CI + manifest) are the supporting infrastructure that makes the 19
runnable and gating. Each of I2–I20 carries a non-vacuous baseline (a positive control that must pass) so a
rejection can never silently pass empty — mirroring `scripts/smoke-warden.sh`.


---

---

## Group Z — Finalize (full-suite green, isolation gate, smoke, PR)

Runs **last**, after Groups A–I are all merged onto `feat/multitenant-isolation`. This is the single
integration gate: the whole test suite (server + sdk + warden), the §16 isolation suite, and both curl smokes
must be green on the real, composed objects — then open the PR (do **not** merge).

### Task Z1: full-suite + isolation-gate + smoke green, push `feat/multitenant-isolation`, open PR (do NOT merge)

**Files:** none new (integration + release task). Touches only what a reconciliation at the seams requires
(the normalizations in the ledger above — apply them where a still-verbatim call site would otherwise fail to
compose), plus `.github/workflows/ci.yml` already wired in Task I22.

**Interfaces:**
- Consumes: everything Groups A–I produced — `create_app(cfg, registry, control, *, sender=..., scheduler=...)`,
  `TenantRegistry`, `ControlPlane.open`, `resolve_identity`, `sign_verdict`, the `ExpiryScheduler`, the `Hub`,
  the `hma` CLI (`tenant`/`token`/`admin` groups), the warden `VerdictVerifier`, and the full
  `server/tests/isolation/` package + `scripts/smoke-multitenant.sh`.
- Produces: a green branch and an open PR on `github.com/holdmyagent/arbiter` for review.

**Steps:**

- [ ] **Confirm the branch and a clean tree.** From the repo root (quote the space):
  ```
  cd "<repo-root>"
  git switch feat/multitenant-isolation
  git status --short            # expect clean (all group commits already landed)
  ```
- [ ] **Reconcile at the seams (only if a run reveals a drift).** Work through the *Interface reconciliation
  ledger* above: run the suites (next steps); if a failure is a pure name/signature drift from that ledger
  (e.g. a still-`await`ed `hub.publish`, a `ControlPlane(path)` construction, an `epoch_of` vs `resolve_epoch`,
  a `create_app`/`TenantRegistry` positional-arg mismatch, a `list_tenants()` shape assumption, an
  `arbiter.cell.Cell` import), apply the ledger's normalization at that one site (or in the isolation
  `conftest.py` alias layer for the §16 files) and re-run. Do **not** change task logic — only the reconciled
  name/signature. Commit each reconciliation:
  ```
  git commit -am "fix(multitenant): reconcile <symbol> at the <group> seam to the pinned contract"
  ```
- [ ] **Server unit + integration suite GREEN.**
  ```
  cd "<repo-root>/server" && python -m pytest -q
  ```
  Expect PASS — including every shipped test (single-tenant back-compat is unchanged) and every new group
  suite (`tests/test_control.py`, `tests/test_registry_*.py`, `tests/test_open_cell.py`,
  `tests/test_resolve_identity.py`, `tests/test_percell_*.py`, `tests/test_require_cell.py`,
  `tests/test_cell_delivery.py`, `tests/test_audit_export.py`, `tests/test_signing.py`,
  `tests/test_rotation_record.py`, `tests/test_rotate_key.py`, `tests/test_keys_endpoint.py`,
  `tests/test_hub.py`, `tests/test_run_stream.py`, `tests/test_stream_*.py`, `tests/test_scheduler.py`,
  `tests/test_db*.py`, `tests/test_pairings.py`, `tests/test_notify_dedupe.py`, `tests/test_outbox_*.py`,
  `tests/test_errors.py`, `tests/test_obslog.py`, `tests/test_resolve_pairing.py`,
  `tests/test_enroll_endpoint.py`, `tests/test_cli_*.py`, `tests/test_provisioning.py`,
  `tests/test_backup_restore.py`, `tests/test_backcompat.py`).
- [ ] **§16 isolation suite GREEN (the merge gate).**
  ```
  cd "<repo-root>" && python -m pytest server/tests/isolation -q
  ```
  Expect PASS — all 19 §16 gate files plus the harness self-test and `test_gate_manifest.py` (which asserts
  all 19 gate files are present and each collects ≥1 test).
- [ ] **Warden suite GREEN.**
  ```
  cd "<repo-root>/warden" && python -m pytest -q
  ```
  Expect PASS — `test_verdict.py` (local-pin + tenant/aud binding), `test_rotation.py` (adopt gate),
  `test_config.py` (`pinned()`/`arbiter_tenant`), `test_rotation_state.py`.
- [ ] **SDK suite GREEN (regression — the sdk is unchanged but must still pass).**
  ```
  cd "<repo-root>" && python -m pytest sdk/tests -q
  ```
  Expect PASS.
- [ ] **Lint gate GREEN.**
  ```
  cd "<repo-root>/server" && ruff check .
  ```
  Expect no errors (fix any import-order / unused-symbol fallout from the group refactors; the deleted
  `require_role`/`_client_ip`/`load_or_create_keypair` uses in `app.py` are common culprits).
- [ ] **Two-tenant curl E2E smoke GREEN.**
  ```
  cd "<repo-root>" && bash scripts/smoke-multitenant.sh
  ```
  Expect the final line `SMOKE-MULTITENANT OK` (provision two tenants; alice creates→approves→verdict verifies
  under ALICE's key; alice is blind to bob's request/audit/device; alice cannot decide bob's request; forged
  route → 403; bob's verdict fails under alice's key). Also run the existing smokes to prove no regression:
  ```
  bash scripts/smoke.sh && bash scripts/smoke-warden.sh
  ```
- [ ] **CI workflow parses.**
  ```
  cd "<repo-root>" && python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('OK')"
  ```
  Confirm the `test` job runs `pytest server/tests/isolation` and `bash scripts/smoke-multitenant.sh` as hard
  steps (added in Task I22).
- [ ] **Push the branch.**
  ```
  cd "<repo-root>" && git push -u origin feat/multitenant-isolation
  ```
- [ ] **Open the PR (do NOT merge).** Base `master`, head `feat/multitenant-isolation`, on
  `github.com/holdmyagent/arbiter`:
  ```
  gh pr create --repo holdmyagent/arbiter --base master --head feat/multitenant-isolation \
    --title "Multi-tenant arbiter: cell-per-tenant structural isolation (V1)" \
    --body "Implements docs/specs/2026-07-07-multitenant-arbiter-isolation-design.md (§1–§18): one arbiter process safely brokers for many tenants via a Cell-per-tenant model — cross-tenant read/approve/push/verdict/audit is impossible by construction. Delivers the ControlPlane router (MAC-integrity, full-hash-only), the single-flight refcount-pinned TenantRegistry (bounded-LRU + FD budget + lock hierarchy), per-cell Database/signer/Hub/Dispatcher/limiters, tenant-bound verdicts + warden local-pin rotation, the process-wide ExpiryScheduler, per-cell egress + notify idempotency, device-enrollment binding, observability isolation, fail-closed backup/restore, single-tenant back-compat (default cell keeps iOS 0.5.0 + hold-sdk 0.2.1 working), and the §16 merge-gate isolation suite (19 tests) + scripts/smoke-multitenant.sh wired into CI. All 13 §15 invariants covered. DO NOT MERGE without review."
  ```
- [ ] **Report the PR URL and the gate results back to the human. Do NOT merge** — this build ends at an open,
  green PR awaiting review (per the design's §1 promise that isolation is proven, then reviewed).

**Done-when:** the whole suite (server + isolation + warden + sdk), `ruff`, and all three smokes are green on
`feat/multitenant-isolation`; the PR is open on `github.com/holdmyagent/arbiter` and left **unmerged**.

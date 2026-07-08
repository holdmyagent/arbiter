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
        self.db_path = db_path  # the live control.db file (backup_fleet snapshots this LAST, §12)
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

    def is_disabled(self, tenant_id: str) -> bool:
        with self._lock:
            r = self.conn.execute(
                "SELECT disabled_at FROM tenants"
                " WHERE tenant_id=? AND tombstoned_at IS NULL", (tenant_id,)).fetchone()
        if r is None:
            return True                            # absent live row -> fail closed
        return r["disabled_at"] is not None

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

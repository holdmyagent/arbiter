"""Warden persistence — proposals + receipts in one SQLite table (WAL).

One shared connection guarded by a threading.Lock: the warden is a single
process (uvicorn worker threads + the tick loop), same shape as the arbiter
server. Retention contract (spec §4.5): `hma-warden serve` calls
purge_older_than(cfg.retention_days) ONCE at startup — no background pruning.

Proposal statuses: pending | executing | executed | denied | expired | failed.
On an (agent, idempotency_key) collision create_proposal raises
sqlite3.IntegrityError — callers check get_by_idem first.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals(
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  action TEXT NOT NULL,
  params TEXT NOT NULL,
  canonical TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  request_id TEXT,
  idempotency_key TEXT,
  status TEXT NOT NULL,
  result TEXT,
  receipt TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_proposals_idem
  ON proposals(agent, idempotency_key) WHERE idempotency_key IS NOT NULL;
"""

# iOS 0.6 A3: the warden has no migration ladder, so new columns land as
# idempotent ALTERs applied at every startup - "duplicate column" is the
# already-applied signal, not an error.
_REPORT_COLUMNS = [
    "ALTER TABLE proposals ADD COLUMN report_pending INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE proposals ADD COLUMN report_attempts INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE proposals ADD COLUMN report_next_at TEXT",
    "ALTER TABLE proposals ADD COLUMN report_payload TEXT",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WardenDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            for stmt in _REPORT_COLUMNS:
                try:
                    self._conn.execute(stmt)
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).lower():
                        raise
            self._conn.commit()

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        d["result"] = json.loads(d["result"]) if d["result"] else None
        d["receipt"] = json.loads(d["receipt"]) if d["receipt"] else None
        return d

    def create_proposal(self, *, agent: str, action: str, params: dict, canonical: str,
                        action_hash: str, request_id: str, idempotency_key: str | None) -> dict:
        pid = str(uuid.uuid4())
        now = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO proposals(id, agent, action, params, canonical, action_hash,"
                " request_id, idempotency_key, status, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,'pending',?,?)",
                (pid, agent, action, json.dumps(params, sort_keys=True), canonical,
                 action_hash, request_id, idempotency_key, now, now),
            )
            self._conn.commit()
        created = self.get(pid)
        assert created is not None
        return created

    def get(self, proposal_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()
        return self._to_dict(row) if row else None

    def get_by_idem(self, agent: str, idempotency_key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM proposals WHERE agent=? AND idempotency_key=?",
                (agent, idempotency_key)).fetchone()
        return self._to_dict(row) if row else None

    def pending(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM proposals WHERE status IN ('pending','executing')"
                " ORDER BY created_at").fetchall()
        return [self._to_dict(r) for r in rows]

    def set_status(self, proposal_id: str, status: str, *, result: dict | None = None,
                   receipt: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE proposals SET status=?, updated_at=?,"
                " result=COALESCE(?, result), receipt=COALESCE(?, receipt) WHERE id=?",
                (status, _now(),
                 json.dumps(result) if result is not None else None,
                 json.dumps(receipt) if receipt is not None else None,
                 proposal_id),
            )
            self._conn.commit()

    def mark_report_pending(self, proposal_id: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE proposals SET report_pending=1, report_payload=?, updated_at=?"
                " WHERE id=?",
                (json.dumps(payload), _now(), proposal_id))
            self._conn.commit()

    def clear_report_pending(self, proposal_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE proposals SET report_pending=0, updated_at=? WHERE id=?",
                (_now(), proposal_id))
            self._conn.commit()

    def bump_report_attempt(self, proposal_id: str, next_at: str) -> int:
        with self._lock:
            self._conn.execute(
                "UPDATE proposals SET report_attempts=report_attempts+1,"
                " report_next_at=?, updated_at=? WHERE id=?",
                (next_at, _now(), proposal_id))
            self._conn.commit()
            row = self._conn.execute(
                "SELECT report_attempts FROM proposals WHERE id=?",
                (proposal_id,)).fetchone()
            return int(row["report_attempts"]) if row else 0

    def reports_due(self, now: str) -> list[dict]:
        # ISO-8601 UTC strings compare lexicographically - same convention as
        # the rest of this file.
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM proposals WHERE status='executed' AND report_pending=1"
                " AND (report_next_at IS NULL OR report_next_at <= ?)"
                " ORDER BY created_at", (now,)).fetchall()
            return [dict(r) for r in rows]

    def purge_older_than(self, days: int) -> int:
        """Startup retention (spec §4.5): serve calls this once at boot with
        cfg.retention_days; there is no background pruning task."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM proposals WHERE created_at < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount

    def take_secret_result(self, proposal_id: str) -> dict | None:
        """Single-read secret release: returns the result exactly once, then NULLs
        it. SELECT + guarded UPDATE run under the connection lock, so two racing
        callers see exactly one winner; the rowcount check is belt-and-braces."""
        with self._lock:
            row = self._conn.execute(
                "SELECT result FROM proposals WHERE id=? AND result IS NOT NULL",
                (proposal_id,)).fetchone()
            if row is None:
                return None
            cur = self._conn.execute(
                "UPDATE proposals SET result=NULL, updated_at=?"
                " WHERE id=? AND result IS NOT NULL",
                (_now(), proposal_id))
            self._conn.commit()
            if cur.rowcount != 1:
                return None
            return json.loads(row["result"])

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

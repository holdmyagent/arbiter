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


def test_checkpoint_closes_on_execute_error(tmp_path, monkeypatch):
    # Even if checkpoint or commit raises, close() must run to avoid leaking the connection.
    db = Database(str(tmp_path / "t.sqlite3"))

    class MockConnection:
        def __init__(self, real_conn):
            self._real = real_conn
            self._closed = False

        def execute(self, *args, **kwargs):
            if self._closed:
                # After close(), delegate to real connection to get the actual error
                return self._real.execute(*args, **kwargs)
            raise sqlite3.OperationalError("test error")

        def commit(self):
            return self._real.commit()

        def close(self):
            self._closed = True
            return self._real.close()

        def __getattr__(self, name):
            return getattr(self._real, name)

    real_conn = db.conn
    mock_conn = MockConnection(real_conn)
    monkeypatch.setattr(db, "conn", mock_conn)

    with pytest.raises(sqlite3.OperationalError, match="test error"):
        db.checkpoint_and_close()

    # Verify connection is closed: ping() must raise ProgrammingError
    with pytest.raises(sqlite3.ProgrammingError):
        db.ping()

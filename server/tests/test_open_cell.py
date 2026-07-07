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

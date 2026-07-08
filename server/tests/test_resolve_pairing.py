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

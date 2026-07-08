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
from arbiter.registry import TenantRegistry, Cell
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
    """APNs stand-in that records which cell each push came from (egress test).
    Signature matches the real Dispatcher call site (arbiter/notify/apns.py
    send_with_retry -> `sender.send(device_token, payload)`, called positionally)."""
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


def pubkey_for(client: TestClient, hdr: dict):
    """Fetch a tenant's own JWKS via a bearer belonging to that tenant."""
    return jwks_pubkey(client.get("/v1/keys", headers=hdr).json())


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
        epoch = control.create_tenant(name, str(d))
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
    sender = FakeSender()
    registry = TenantRegistry(control, cfg=cfg, sender=sender)
    handles = _provision(control, registry, root)
    app = create_app(cfg, registry, control, sender=sender)
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

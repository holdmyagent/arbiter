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


def test_mint_pair_code_raw_code_has_sufficient_entropy(tmp_path):
    # unguessable: not just the hash, the raw secret itself must carry real
    # entropy (secrets.token_hex(24) => 48 hex chars of the 24-byte payload).
    ctrl = FakeControl(tmp_path)
    code, _ = _mint_pair_code(ctrl, "acme", minutes=15)
    assert code.startswith("hma_pair_")
    assert len(code[len("hma_pair_"):]) == 48


def test_mint_pair_code_end_to_end_through_real_enroll_route(tmp_path):
    """Closes the G1->G7->G8->G9 loop: a code minted by the CLI helper
    actually enrolls a device through the real HTTP resolve_pairing/enroll
    path — proving the mint wires BOTH the control route and the cell row."""
    from fastapi.testclient import TestClient

    from arbiter.apns import APNsSender
    from arbiter.app import create_app
    from arbiter.config import Config
    from tests.conftest import build_registry_env

    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.auth.agent_token = "test-agent"
    cfg.auth.app_token = "test-app"
    cfg.auth.admin_password = "test-admin"
    cfg.auth.session_secret = "test-secret"
    cfg.server.db_path = str(tmp_path / "t.sqlite3")

    env = build_registry_env(cfg, tmp_path / "env")
    app = create_app(cfg, env.registry, env.control, sender=APNsSender(cfg))

    code, _ = _mint_pair_code(env.control, "default", minutes=15)

    with TestClient(app) as c:
        r = c.post("/v1/devices/enroll",
                   headers={"Authorization": f"Bearer {code}"},
                   json={"apns_token": "tok-1", "name": "iPhone"})
        assert r.status_code == 200 and r.json()["tenant_id"] == "default"
        assert [d["apns_token"] for d in env.default_db.list_devices()] == ["tok-1"]

        # single-use: the same code cannot enroll a second device
        r2 = c.post("/v1/devices/enroll",
                    headers={"Authorization": f"Bearer {code}"},
                    json={"apns_token": "tok-2", "name": "iPhone2"})
        assert r2.status_code == 403

import hashlib, base64, hmac, struct, time
import pytest
from fastapi import HTTPException
from arbiter import step_up
from arbiter.app import capabilities_for, assert_cap
from arbiter.auth import Identity


def _totp(secret_b32, now, step=30):
    key = base64.b32decode(secret_b32)
    counter = int(now // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    val = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{val:06d}"


def test_verify_totp_accepts_current_and_adjacent_window():
    secret = base64.b32encode(b"0123456789").decode()
    now = 1_700_000_000.0
    assert step_up.verify_totp(secret, _totp(secret, now), now)
    assert step_up.verify_totp(secret, _totp(secret, now - 30), now)     # prev step
    assert step_up.verify_totp(secret, _totp(secret, now + 30), now)     # next step
    assert not step_up.verify_totp(secret, _totp(secret, now - 90), now)
    assert not step_up.verify_totp(secret, "000000", now) or _totp(secret, now) == "000000"


def test_capabilities_role_defaults():
    app_id = Identity(name="app", role="app", tenant_id="default")
    agent_id = Identity(name="gate", role="agent", tenant_id="default")
    assert "policy:write" in capabilities_for(app_id)
    assert capabilities_for(agent_id) == {"policy:read-resolved"}


def test_capabilities_explicit_scope_wins():
    tok = Identity(name="bot", role="agent", tenant_id="default",
                   scopes={"capabilities": ["policy:read-resolved", "policy:read"]})
    assert capabilities_for(tok) == {"policy:read-resolved", "policy:read"}


def test_assert_cap_denies():
    agent_id = Identity(name="gate", role="agent", tenant_id="default")
    with pytest.raises(HTTPException) as e:
        assert_cap(agent_id, "policy:write")
    assert e.value.status_code == 403

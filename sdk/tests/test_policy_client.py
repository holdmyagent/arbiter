"""Gate-facing policy client methods on ArbiterClient, exercised against the
REAL in-process arbiter app (not a mock, so the wire contract can't drift).

Scope (ratified controller decision, 2026-07-24): the SDK carries ONLY the
gate-facing surface the agent token can authorize — `policy:read-resolved`
(role "agent"): the resolved policy the gate consumes, and the gate-status
telemetry the gate/sync reports. The app-role write/admin surface (presets,
overlay, active, test, gate-status readout) has NO Python consumer in this
campaign — it is served by the macOS app's ArbiterKit (Swift) — so it is
deliberately NOT added here. The constructor signature is left unchanged
(no app_token reinstatement); 0.3.0's app_token removal stands.
"""
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from arbiter.app import create_app
from arbiter.config import Config
from arbiter.control import ControlPlane
from arbiter.registry import TenantRegistry
from hold_sdk.client import ArbiterClient


def _client():
    """ArbiterClient wired to a live in-process app (via TestClient as _http,
    the same bridge the existing SDK tests use), using the legacy config
    agent_token "A" (role "agent" -> {policy:read-resolved}), the exact cap the
    gate holds."""
    root = Path(tempfile.mkdtemp())
    cfg = Config.load(str(root / "absent.toml"))
    cfg.auth.agent_token = "A"
    cfg.auth.app_token = "P"
    cfg.auth.admin_password = "pw"
    cfg.auth.session_secret = "s"
    control = ControlPlane.open(root / "control", root / "cells")
    control.create_tenant("default", str(root / "cells" / "default"))
    reg = TenantRegistry(control, cfg=cfg)
    app = create_app(cfg, reg, control)
    ac = ArbiterClient("http://testserver", "A")
    ac._http = TestClient(app, base_url="http://testserver",
                          raise_server_exceptions=False)
    return ac


def test_sdk_get_resolved_policy_is_most_restrictive_default():
    ac = _client()
    r = ac.get_resolved_policy()
    # Non-empty resolved doc; nothing configured -> most-restrictive default.
    assert r["default_decision"] == "ask"
    assert r["active_preset"] is None
    assert r["tool_allowlist"] == []
    assert "version" in r and "etag" in r


def test_sdk_report_gate_status_roundtrips():
    ac = _client()
    rec = ac.report_gate_status(version=3, etag="abc123",
                                fetched_at="2026-07-24T00:00:00+00:00",
                                most_restrictive=True)
    # The stored record echoes what the gate reported, plus a server stamp.
    assert rec["version"] == 3
    assert rec["etag"] == "abc123"
    assert rec["fetched_at"] == "2026-07-24T00:00:00+00:00"
    assert rec["most_restrictive"] is True
    assert rec["reported_at"]  # server-stamped, non-empty

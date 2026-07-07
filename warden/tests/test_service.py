"""Orchestrator tests - fake arbiter/verifier, real db + canonicalization.

No sleeps anywhere: tick() is called directly and time is driven by
monkeypatching hold_warden.service._utcnow.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

import pytest

from hold_warden.arbiter import (
    ArbiterAuthError,
    ArbiterConflict,
    ArbiterStale,
    ArbiterUnavailable,
)
from hold_warden.canonical import canonicalize
from hold_warden.config import ActionSpec, ParamSpec, ParamValidationError, WardenConfig
from hold_warden.db import WardenDB
from hold_warden.verdict import Verdict, VerdictError

from hold_warden import service
from hold_warden.service import Orchestrator, UnknownActionError, UnknownAgentError


def make_param(**overrides) -> ParamSpec:
    base = dict(type="string", values=None, pattern=None, max_len=None, min=None, max=None)
    base.update(overrides)
    return ParamSpec(**base)


def make_action(**overrides) -> ActionSpec:
    base = dict(name="", adapter="command", severity="low", ttl_seconds=300,
                description="", argv=None, url=None, method=None,
                body_template=None, headers=None, secret=None, params={})
    base.update(overrides)
    return ActionSpec(**base)


def make_cfg() -> WardenConfig:
    return WardenConfig(
        arbiter_url="http://127.0.0.1:9",  # never dialed - tests use fakes
        arbiter_token_ref="env:HMA_WARDEN_TOKEN",
        arbiter_pubkey="deadbeef:QUFBQQ",
        warden_name="test-warden",
        bind="127.0.0.1",
        port=8646,
        retention_days=7,
        agents={"hermes": "env:WARDEN_AGENT_HERMES"},
        actions={
            "greet": make_action(
                name="greet", adapter="command", severity="low",
                description="echo a greeting", argv=["echo", "{word}"],
                params={"word": make_param(type="enum", values=["hello", "goodbye"])}),
            "post_status": make_action(
                name="post_status", adapter="http", severity="medium",
                description="post a status",
                url="https://api.example.test/v1/status", method="POST",
                body_template='{"text": "{text}"}',
                headers={"Authorization": "secret:api_bearer"},
                params={"text": make_param(type="string", pattern="^[a-z ]*$", max_len=100)}),
            "release_key": make_action(
                name="release_key", adapter="secret", severity="critical",
                description="release the deploy key", secret="secret:deploy_key"),
        },
        secrets={"api_bearer": "env:TEST_API_BEARER",
                 "deploy_key": "env:TEST_DEPLOY_KEY"},
    )


class FakeArbiter:
    """In-memory stand-in for hold_warden.arbiter.ArbiterClient."""

    def __init__(self):
        self.created: list[dict] = []
        self.create_error: Exception | None = None
        self.request_status = "pending"
        self.request_error: Exception | None = None
        self.verdict_jws = "header.payload.signature"
        self.verdict_error: Exception | None = None
        self.consume_error: Exception | None = None
        self.consumed: list[str] = []

    def create_request(self, *, title, description, action_type, severity,
                       ttl_seconds, payload, canonical_action, action_hash,
                       idempotency_key):
        if self.create_error is not None:
            raise self.create_error
        self.created.append(dict(
            title=title, description=description, action_type=action_type,
            severity=severity, ttl_seconds=ttl_seconds, payload=payload,
            canonical_action=canonical_action, action_hash=action_hash,
            idempotency_key=idempotency_key))
        return {"id": f"req-{len(self.created)}", "status": "pending",
                "expires_at": "2026-07-06T00:05:00+00:00"}

    def get_request(self, rid):
        if self.request_error is not None:
            raise self.request_error
        return {"id": rid, "status": self.request_status}

    def get_verdict(self, rid):
        if self.verdict_error is not None:
            raise self.verdict_error
        return self.verdict_jws

    def consume(self, rid):
        if self.consume_error is not None:
            raise self.consume_error
        self.consumed.append(rid)


class FakeVerifier:
    """In-memory stand-in for hold_warden.verdict.VerdictVerifier."""

    def __init__(self):
        self.verdict: Verdict | None = None
        self.error: Exception | None = None
        self.calls: list[tuple] = []

    def verify(self, jws, expected_request_id, expected_action_hash):
        self.calls.append((jws, expected_request_id, expected_action_hash))
        if self.error is not None:
            raise self.error
        return self.verdict


@pytest.fixture()
def orch(tmp_path):
    cfg = make_cfg()
    db = WardenDB(tmp_path / "warden.sqlite3")
    return Orchestrator(cfg, db, FakeArbiter(), FakeVerifier())


# ---------------------------------------------------------------- propose

def test_propose_persists_and_returns_pending(orch):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    assert out["status"] == "pending"
    assert out["request_id"] == "req-1"
    assert out["expires_at"] == "2026-07-06T00:05:00+00:00"
    row = orch.db.get(out["id"])
    assert row is not None and row["agent"] == "hermes"
    expected_canonical, expected_hash = canonicalize(
        "greet", "command", {"word": "hello"},
        {"argv": ["echo", "hello"]}, "test-warden")
    assert row["canonical"] == expected_canonical
    assert row["action_hash"] == expected_hash
    sent = orch.arbiter.created[0]
    assert sent["canonical_action"] == expected_canonical
    assert sent["action_hash"] == expected_hash
    assert sent["severity"] == "low" and sent["ttl_seconds"] == 300
    assert isinstance(sent["idempotency_key"], str) and sent["idempotency_key"]


def test_propose_idempotent_replay_returns_original(orch):
    first = orch.propose("hermes", "greet", {"word": "hello"}, "key-1")
    second = orch.propose("hermes", "greet", {"word": "hello"}, "key-1")
    assert second["id"] == first["id"]
    assert len(orch.arbiter.created) == 1
    expected_idem = hashlib.sha256(("hermes" + ":" + "key-1").encode()).hexdigest()
    assert orch.arbiter.created[0]["idempotency_key"] == expected_idem
    assert "expires_at" in second


def test_propose_unknown_agent(orch):
    with pytest.raises(UnknownAgentError):
        orch.propose("mallory", "greet", {"word": "hello"}, None)


def test_propose_unknown_action(orch):
    with pytest.raises(UnknownActionError):
        orch.propose("hermes", "rm_rf_slash", {}, None)


def test_propose_invalid_params(orch):
    with pytest.raises(ParamValidationError):
        orch.propose("hermes", "greet", {"word": "not-in-enum"}, None)


def test_propose_arbiter_unavailable_raises_with_no_side_effects(orch):
    orch.arbiter.create_error = ArbiterUnavailable("connect refused")
    with pytest.raises(ArbiterUnavailable):
        orch.propose("hermes", "greet", {"word": "hello"}, None)
    assert orch.db.pending() == []


def test_propose_arbiter_auth_error_logs_critical_and_raises(orch, caplog):
    orch.arbiter.create_error = ArbiterAuthError("401 unauthorized")
    with caplog.at_level(logging.CRITICAL, logger="hold_warden.service"):
        with pytest.raises(ArbiterAuthError):
            orch.propose("hermes", "greet", {"word": "hello"}, None)
    assert any("warden token" in r.getMessage() for r in caplog.records)
    assert orch.db.pending() == []


# ------------------------------------------------------------------- tick

def approve(orch, out, decision="approved"):
    """Point the fakes at a decided request + matching verdict for proposal `out`."""
    orch.arbiter.request_status = decision
    orch.verifier.verdict = Verdict(
        request_id=out["request_id"], action_hash=out["action_hash"],
        decision=decision, decided_at="2026-07-06T00:01:00+00:00",
        approval_ttl_seconds=600)


@pytest.fixture()
def fake_command(monkeypatch):
    from hold_warden.adapters import CommandResult
    calls: list[dict] = []

    def _fake(argv, timeout_s, extra_env=None):
        calls.append({"argv": list(argv), "timeout_s": timeout_s})
        return CommandResult(exit_code=0, stdout_tail="hello\n",
                             stderr_tail="", duration_ms=5)

    monkeypatch.setattr(service, "run_command", _fake)
    return calls


def test_tick_pending_request_stays_pending(orch):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    orch.tick()
    assert orch.db.get(out["id"])["status"] == "pending"
    assert orch.verifier.calls == []


def test_tick_approved_verifies_consumes_and_executes(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert orch.verifier.calls == [
        ("header.payload.signature", out["request_id"], out["action_hash"])]
    assert orch.arbiter.consumed == [out["request_id"]]
    assert fake_command == [{"argv": ["echo", "hello"],
                             "timeout_s": service.EXEC_TIMEOUT_S}]
    result = row["result"]
    assert result["exit_code"] == 0 and result["stdout_tail"] == "hello\n"
    receipt = row["receipt"]
    assert set(receipt) == {"request_id", "action_hash", "decision", "decided_at",
                            "verdict_jws", "executed_at"}
    assert receipt["decision"] == "approved"
    assert receipt["verdict_jws"] == "header.payload.signature"
    assert receipt["executed_at"] is not None


def test_tick_denied_records_receipt_and_never_executes(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out, decision="denied")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "denied"
    assert row["receipt"]["decision"] == "denied"
    assert row["receipt"]["executed_at"] is None
    assert fake_command == []
    assert orch.arbiter.consumed == []


def test_tick_expired_verdict_records_expired(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out, decision="expired")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "expired"
    assert row["receipt"]["decision"] == "expired"
    assert fake_command == [] and orch.arbiter.consumed == []


def test_tick_registry_drift_fails_before_consume(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    # Operator edits the action between approval and execution:
    orch.cfg.actions["greet"].argv = ["echo", "tampered", "{word}"]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "drift" in row["result"]["error"]
    assert orch.arbiter.consumed == []
    assert fake_command == []


# ----------------------------------------------------- fail-closed table

def test_tick_verdict_error_fails_and_never_executes(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.verifier.error = VerdictError("signature mismatch")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "verdict verification failed" in row["result"]["error"]
    assert orch.arbiter.consumed == [] and fake_command == []


def test_tick_consume_conflict_fails_and_never_executes(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.consume_error = ArbiterConflict("409 already consumed")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "consumed" in row["result"]["error"]
    assert fake_command == []


def test_tick_consume_stale_expires(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.consume_error = ArbiterStale("410 stale approval")
    orch.tick()
    assert orch.db.get(out["id"])["status"] == "expired"
    assert fake_command == []


def test_tick_consume_unavailable_stays_pending(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.consume_error = ArbiterUnavailable("connect refused")
    orch.tick()  # must not raise
    assert orch.db.get(out["id"])["status"] == "pending"
    assert fake_command == []


def test_tick_auth_error_fails_logs_critical_daemon_lives(orch, caplog):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    orch.arbiter.request_error = ArbiterAuthError("403 revoked")
    with caplog.at_level(logging.CRITICAL, logger="hold_warden.service"):
        orch.tick()  # must not raise
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert any("warden token" in r.getMessage() for r in caplog.records)


def test_tick_arbiter_unreachable_stays_pending_then_expires(orch, monkeypatch):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    orch.arbiter.request_error = ArbiterUnavailable("connect refused")
    created = datetime.fromisoformat(str(orch.db.get(out["id"])["created_at"]))
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    monkeypatch.setattr(service, "_utcnow", lambda: created + timedelta(seconds=10))
    orch.tick()
    assert orch.db.get(out["id"])["status"] == "pending"
    monkeypatch.setattr(service, "_utcnow", lambda: created + timedelta(seconds=301))
    orch.tick()
    assert orch.db.get(out["id"])["status"] == "expired"


def test_tick_unknown_decision_fails(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out, decision="banana")
    orch.tick()
    assert orch.db.get(out["id"])["status"] == "failed"
    assert fake_command == []


def test_tick_executing_row_from_crash_fails_closed(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    orch.db.set_status(out["id"], "executing")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "outcome unknown" in row["result"]["error"]
    assert fake_command == []


# ------------------------------------------------------- http + secret

def test_tick_http_adapter_resolves_headers_and_body(orch, monkeypatch):
    from hold_warden.adapters import HttpResult
    monkeypatch.setenv("TEST_API_BEARER", "bearer-value")
    calls: list[dict] = []

    def fake_http(method, url, headers, body, timeout_s):
        calls.append(dict(method=method, url=url, headers=headers,
                          body=body, timeout_s=timeout_s))
        return HttpResult(status=200, body_sha256="cafe" * 16, body_head="ok")

    monkeypatch.setattr(service, "run_http", fake_http)
    out = orch.propose("hermes", "post_status", {"text": "hello world"}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert calls == [{
        "method": "POST", "url": "https://api.example.test/v1/status",
        "headers": {"Authorization": "bearer-value"},
        "body": '{"text": "hello world"}',
        "timeout_s": service.EXEC_TIMEOUT_S}]
    assert row["result"] == {"http_status": 200, "body_sha256": "cafe" * 16,
                             "body_head": "ok"}


def test_render_body_refuses_hash_mismatch(orch):
    spec = orch.cfg.actions["post_status"]
    with pytest.raises(RuntimeError):
        orch._render_body(spec, {"text": "hello"}, {"body_sha256": "0" * 64})


def test_tick_secret_adapter_stores_value_single_read(orch, monkeypatch):
    monkeypatch.setenv("TEST_DEPLOY_KEY", "s3cr3t-value")
    out = orch.propose("hermes", "release_key", {}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["result"] == {"secret": "s3cr3t-value"}
    assert "s3cr3t-value" not in str(row["receipt"])
    assert "s3cr3t-value" not in row["canonical"]
    assert orch.db.take_secret_result(out["id"]) == {"secret": "s3cr3t-value"}
    assert orch.db.take_secret_result(out["id"]) is None


def test_tick_secret_resolution_failure_fails_closed(orch, monkeypatch):
    from hold_warden.secrets import SecretResolutionError

    def boom(ref, timeout_s=10):
        raise SecretResolutionError("resolver exited 2")

    monkeypatch.setattr(service, "resolve", boom)
    out = orch.propose("hermes", "release_key", {}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "secret resolution failed" in row["result"]["error"]


def test_tick_adapter_error_fails_with_attempt_receipt(orch, monkeypatch):
    def boom(argv, timeout_s, extra_env=None):
        raise TimeoutError("command timed out")

    monkeypatch.setattr(service, "run_command", boom)
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "adapter error" in row["result"]["error"]
    assert row["receipt"]["executed_at"] is not None

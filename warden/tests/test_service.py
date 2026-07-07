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

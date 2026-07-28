"""hold_warden.service — retry of a dropped execution report.

_report_exec_result used to fire once after set_status(executed) and swallow
every exception: a warden death in that window lost the outcome forever, and
a 409/404 was indistinguishable from a 502. This pins the fix: the owed
report is persisted (report_pending) BEFORE the first attempt, tick() sweeps
rows still owed a report, 409/404/401/403/other-4xx are terminal (never
retried), and only network errors / 5xx requeue with bounded backoff.

No sleeps: report_next_at is either left in the future (checked directly) or
backdated straight in SQL, same trick as test_db.py's purge_older_than test.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from hold_warden.arbiter import (
    ArbiterAuthError,
    ArbiterConflict,
    ArbiterNotFound,
    ArbiterReportRejected,
    ArbiterUnavailable,
)
from hold_warden.config import ActionSpec, ParamSpec, WardenConfig
from hold_warden.db import WardenDB
from hold_warden.verdict import Verdict

from hold_warden import service
from hold_warden.service import Orchestrator


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
        arbiter_tenant="test-tenant",
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
            "release_key": make_action(
                name="release_key", adapter="secret", severity="critical",
                description="release the deploy key", secret="secret:deploy_key"),
        },
        secrets={"deploy_key": "env:TEST_DEPLOY_KEY"},
    )


class FakeArbiter:
    """In-memory stand-in for hold_warden.arbiter.ArbiterClient (mirrors
    test_service.py's FakeArbiter). report_execution is queue-scriptable so a
    test can make it fail N times then succeed, or fail forever."""

    def __init__(self):
        self.created: list[dict] = []
        self.request_status = "pending"
        self.verdict_jws = "header.payload.signature"
        self.consume_error: Exception | None = None
        self.consumed: list[str] = []
        self.reported: list[dict] = []
        self.report_errors: list[Exception] = []      # popped in order; empty -> succeed
        self.report_always_raises: Exception | None = None  # takes priority; never consumed

    def create_request(self, *, title, description, action_type, severity,
                       ttl_seconds, payload, canonical_action, action_hash,
                       idempotency_key):
        self.created.append(dict(idempotency_key=idempotency_key))
        return {"id": f"req-{len(self.created)}", "status": "pending",
                "expires_at": "2026-07-06T00:05:00+00:00"}

    def get_request(self, rid):
        return {"id": rid, "status": self.request_status}

    def get_verdict(self, rid):
        return self.verdict_jws

    def consume(self, rid):
        if self.consume_error is not None:
            raise self.consume_error
        self.consumed.append(rid)

    def report_execution(self, rid, *, exit_code, ran, output, kind):
        if self.report_always_raises is not None:
            raise self.report_always_raises
        if self.report_errors:
            raise self.report_errors.pop(0)
        self.reported.append(dict(rid=rid, exit_code=exit_code, ran=ran,
                                  output=output, kind=kind))


def approve(orch, out, decision="approved"):
    """Point the fake arbiter at a decided request + matching verdict for proposal `out`."""
    orch.arbiter.request_status = decision
    orch.verifier.verdict = Verdict(
        request_id=out["request_id"], action_hash=out["action_hash"],
        decision=decision, decided_at="2026-07-06T00:01:00+00:00",
        approval_ttl_seconds=600)


class FakeVerifier:
    """In-memory stand-in for hold_warden.verdict.VerdictVerifier."""

    def __init__(self):
        self.verdict: Verdict | None = None

    def verify(self, jws, expected_request_id, expected_action_hash):
        return self.verdict


@pytest.fixture()
def orch(tmp_path):
    cfg = make_cfg()
    db = WardenDB(tmp_path / "warden.sqlite3")
    return Orchestrator(cfg, db, FakeArbiter(), FakeVerifier())


@pytest.fixture()
def fake_command(monkeypatch):
    from hold_warden.adapters import CommandResult

    calls: list[dict] = []

    def _fake(argv, timeout_s, extra_env=None, cwd=None):
        calls.append({"argv": list(argv), "timeout_s": timeout_s})
        return CommandResult(exit_code=0, stdout_tail="hello\n", stderr_tail="", duration_ms=5)

    monkeypatch.setattr(service, "run_command", _fake)
    return calls


# --------------------------------------------------------------------- tests

def test_dropped_report_is_retried_on_next_tick_and_lands(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterUnavailable("connect refused")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 1
    assert row["report_payload"] is not None
    assert orch.arbiter.reported == []

    # Force report_next_at into the past (no sleeping).
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    orch.db._conn.execute("UPDATE proposals SET report_next_at=? WHERE id=?",
                          (past, out["id"]))
    orch.db._conn.commit()

    orch.tick()
    row = orch.db.get(out["id"])
    assert row["report_pending"] == 0
    assert len(orch.arbiter.reported) == 1
    assert orch.arbiter.reported[0]["rid"] == out["request_id"]


def test_409_conflict_clears_flag_without_retry(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterConflict("already reported")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 0
    assert row["report_attempts"] == 0

    orch.tick()  # even if it were due, a cleared flag means no further call
    assert orch.arbiter.reported == []


def test_404_clears_flag(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterNotFound("request gone")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 0
    assert row["report_attempts"] == 0
    orch.tick()
    assert orch.arbiter.reported == []


def test_auth_error_is_terminal(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterAuthError("401 revoked")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 0
    assert row["report_attempts"] == 0
    orch.tick()
    assert orch.arbiter.reported == []


def test_report_rejected_is_terminal(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterReportRejected("422 bad payload")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 0
    assert row["report_attempts"] == 0


def test_5xx_requeues_with_backoff(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterUnavailable("arbiter error 502")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 1
    assert row["report_attempts"] == 1
    assert row["report_next_at"] is not None
    next_at = datetime.fromisoformat(row["report_next_at"])
    assert next_at > datetime.now(timezone.utc)

    # A tick right now (before report_next_at) must not call the arbiter again.
    orch.tick()
    assert orch.arbiter.reported == []
    row = orch.db.get(out["id"])
    assert row["report_attempts"] == 1  # unchanged: not retried yet


def test_gives_up_after_max_attempts(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.arbiter.report_errors = [ArbiterUnavailable("down")]
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["report_pending"] == 1
    assert row["report_attempts"] == 1

    # Seed attempts to one below the cap and drive a final, always-failing attempt.
    orch.db._conn.execute("UPDATE proposals SET report_attempts=? WHERE id=?",
                          (service.REPORT_MAX_ATTEMPTS - 1, out["id"]))
    orch.db._conn.commit()
    orch.arbiter.report_always_raises = ArbiterUnavailable("still down")
    orch._attempt_report(out["id"], out["request_id"],
                         {"exit_code": 0, "ran": "echo hello", "output": "x", "kind": "command"})

    row = orch.db.get(out["id"])
    assert row["report_attempts"] == service.REPORT_MAX_ATTEMPTS
    assert row["report_pending"] == 0
    assert row["status"] == "executed"  # a failed report never changes proposal status


def test_crash_recovery_unchanged(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    orch.db.set_status(out["id"], "executing")
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "failed"
    assert "outcome unknown" in row["result"]["error"]
    assert fake_command == []


def test_secret_adapter_sets_no_flag(orch, monkeypatch):
    monkeypatch.setenv("TEST_DEPLOY_KEY", "s3cr3t-value")
    out = orch.propose("hermes", "release_key", {}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 0
    assert orch.arbiter.reported == []


def test_survives_process_restart(tmp_path):
    """The scenario this task exists for: the warden dies between
    set_status(executed) and a landed report. A fresh process (fresh WardenDB
    + Orchestrator over the same file) must still land the owed report on its
    first tick. Also exercises reports_due's NULL-next_at branch and the
    idempotent-ALTER path re-running against an already-migrated DB."""
    db_path = tmp_path / "warden.sqlite3"
    seed_db = WardenDB(db_path)
    payload = {"exit_code": 0, "ran": "echo hello", "output": "hello\n", "kind": "command"}
    seed_db._conn.execute(
        "INSERT INTO proposals(id, agent, action, params, canonical, action_hash,"
        " request_id, idempotency_key, status, report_pending, report_next_at,"
        " report_payload, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("prop-1", "hermes", "greet", '{"word": "hello"}', "canon", "ab" * 32,
         "req-1", None, "executed", 1, None, json.dumps(payload),
         "2026-07-06T00:00:00+00:00", "2026-07-06T00:00:00+00:00"))
    seed_db._conn.commit()
    seed_db._conn.close()  # simulate the warden process exiting

    fresh_db = WardenDB(db_path)  # re-runs the idempotent ALTERs against a migrated DB
    orch = Orchestrator(make_cfg(), fresh_db, FakeArbiter(), FakeVerifier())
    orch.tick()

    row = orch.db.get("prop-1")
    assert row["report_pending"] == 0
    assert len(orch.arbiter.reported) == 1
    assert orch.arbiter.reported[0]["rid"] == "req-1"


def test_report_bookkeeping_error_never_fails_the_proposal(orch, fake_command, monkeypatch):
    """A DB error while attempting the report (locked db, disk full) must not
    unwind into tick()'s except-clause, which would set_status(failed) on a
    proposal that already ran — a stricter regression than "a failed report
    doesn't change status", since this path raises from inside
    _report_exec_result itself, called directly from _execute. Since 0.7 S2 the
    payload is armed by set_status, so the failure seam is the attempt's own
    bookkeeping (clear_report_pending), not a separate mark_report_pending.

    A bookkeeping failure AFTER a successful report leaves the row still
    sweepable (report_pending never cleared), so tick()'s own reports_due pass
    may legitimately re-deliver the same report within this same tick — the
    arbiter's write-once consume makes a redelivery a terminal 409, harmless.
    Asserting an exact report count here would pin tick()'s internal two-loop
    shape rather than the actual durability contract, so this only asserts
    "at least once" (never zero, never an unhandled raise)."""
    def _boom(*a, **kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(orch.db, "clear_report_pending", _boom)

    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.tick()  # must not raise
    row = orch.db.get(out["id"])
    assert row["status"] == "executed"
    assert row["report_pending"] == 1     # still owed: the clear never landed
    assert len(orch.arbiter.reported) >= 1


def test_corrupt_report_payload_is_self_limiting(orch, fake_command):
    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    orch.tick()
    row = orch.db.get(out["id"])
    assert row["status"] == "executed" and row["report_pending"] == 0
    assert len(orch.arbiter.reported) == 1

    # Simulate a corrupt report_payload on a still-pending row (belt-and-braces:
    # this shouldn't happen via set_status, which always json.dumps a real
    # dict, but the sweep must not spin forever if it ever does).
    orch.db._conn.execute(
        "UPDATE proposals SET report_pending=1, report_payload=? WHERE id=?",
        ("not valid json", out["id"]))
    orch.db._conn.commit()

    orch.tick()
    row = orch.db.get(out["id"])
    assert row["report_pending"] == 0
    assert row["report_attempts"] == 0  # never counted as a retry attempt


def test_executed_and_owed_report_survive_a_kill_mid_report(orch, fake_command, monkeypatch):
    """The 0.6 residual, closed. KeyboardInterrupt stands in for the process
    being killed mid-report: it is a BaseException, so it escapes every
    `except Exception` guard in the stack exactly as SIGKILL/SIGINT would end
    the process. The row it leaves behind must still owe the report."""
    sent = {}

    def _die(rid, **payload):
        sent.update(payload)
        raise KeyboardInterrupt("killed mid-report")

    monkeypatch.setattr(orch.arbiter, "report_execution", _die)

    out = orch.propose("hermes", "greet", {"word": "hello"}, None)
    approve(orch, out)
    with pytest.raises(KeyboardInterrupt):
        orch.tick()

    row = orch.db.get(out["id"])
    assert row["status"] == "executed"          # both fields landed together
    assert row["report_pending"] == 1
    assert json.loads(row["report_payload"]) == sent

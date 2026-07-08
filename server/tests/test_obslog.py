import logging

from arbiter.obslog import scoped_log, SAFE_KEYS


def test_scoped_log_goes_to_tenant_logger(caplog):
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "device_registered", count=3)
    recs = [r for r in caplog.records if r.name == "arbiter.tenant.acme"]
    assert len(recs) == 1
    assert "device_registered" in recs[0].getMessage()
    assert "3" in recs[0].getMessage()


def test_scoped_log_never_emits_pii_fields(caplog):
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "created",
                   title="Wire $50k to Bob",
                   description="secret",
                   payload={"iban": "X"},
                   dir="/srv/tenants/acme",
                   error="no such column: foo",
                   severity="high")          # severity is safe metadata
    msg = caplog.records[-1].getMessage()
    for leaked in ("Wire $50k", "secret", "iban", "/srv/tenants/acme", "no such column"):
        assert leaked not in msg
    assert "high" in msg                     # non-PII field survives


def test_allowlist_covers_the_named_safe_surfaces():
    assert {"request_id", "event", "count", "status", "severity", "role",
            "epoch", "attempt", "outcome", "reason_code", "duration_ms",
            "code"} <= SAFE_KEYS


def test_scoped_log_drops_unlisted_keys(caplog):
    # `reason` is not on the allowlist (unlike `reason_code`) — a caller
    # might stuff schema-internals or free text into it. Must be dropped.
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "query_failed", reason="no such column: tenants.foo",
                    note="internal note", context="whatever")
    msg = caplog.records[-1].getMessage()
    assert "no such column" not in msg
    assert "internal note" not in msg
    assert "reason=" not in msg
    assert "note=" not in msg
    assert "context=" not in msg


def test_scoped_log_redacts_nested_structured_values(caplog):
    # Even under an ALLOWLISTED key, a dict/list/tuple value can smuggle
    # PII — never stringify a nested container into the log, allowlisted
    # key or not.
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "created", status={"title": "Wire $50k"})
    msg = caplog.records[-1].getMessage()
    assert "Wire $50k" not in msg
    assert "title" not in msg
    assert "redacted" in msg                 # allowlisted key still logs, value is redacted


def test_scoped_log_key_matching_ignores_case_and_whitespace(caplog):
    # A case/space variant of a PII-ish key name must not sneak a value in
    # by bypassing the (stripped, lowercased) allowlist check — "Title " /
    # "DESCRIPTION" are not "title" / "description", but should still drop.
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "created", **{" Title ": "Wire $50k to Bob",
                                          "DESCRIPTION": "secret"})
    msg = caplog.records[-1].getMessage()
    assert "Wire $50k" not in msg
    assert "secret" not in msg

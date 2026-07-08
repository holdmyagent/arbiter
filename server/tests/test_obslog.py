import logging

from arbiter.obslog import scoped_log, tenant_logger, PII_KEYS


def test_scoped_log_goes_to_tenant_logger(caplog):
    with caplog.at_level(logging.INFO, logger="arbiter.tenant.acme"):
        scoped_log("acme", "device_registered", device_count=3)
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


def test_pii_blocklist_covers_the_named_surfaces():
    assert {"title", "description", "payload", "body", "dir", "error"} <= PII_KEYS

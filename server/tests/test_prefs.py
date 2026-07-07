import asyncio

from arbiter.db import SCHEMA_VERSION
from arbiter.notify import Dispatcher
from arbiter.config import Config
from arbiter.models import RequestCreate


def test_schema_v3_and_migration(tmp_path, db):
    assert SCHEMA_VERSION >= 5  # bumped by migrations 4+5 (tokens table, request enforcement cols)
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(devices)")}
    assert "severities" in cols and "badge" in cols


def test_register_roundtrip_with_map(client, app_headers):
    body = {"apns_token": "t1", "name": "iPhone", "severities":
            {"low": False, "medium": True, "high": True, "critical": True}, "badge": True}
    d = client.post("/v1/devices", headers=app_headers, json=body).json()
    assert d["severities"]["low"] is False and d["badge"] == 1


def test_register_without_map_keeps_threshold(client, app_headers):
    d = client.post("/v1/devices", headers=app_headers,
                    json={"apns_token": "t2", "min_severity": "high"}).json()
    assert d["severities"] is None and d["min_severity"] == "high"


# ── fan-out truth table ──────────────────────────────────────────────────────

class FakeSender:
    def __init__(self):
        self.sent = []

    async def send(self, token, payload):
        self.sent.append((token, payload))
        return "sent"


def _cfg(tmp_path):
    c = Config.load(str(tmp_path / "absent.toml"))
    c.auth.agent_token = "a"
    c.auth.app_token = "b"
    return c


def _rc(severity):
    return RequestCreate(title="t", severity=severity)


def test_map_beats_threshold(tmp_path, db):
    sender = FakeSender()
    d = Dispatcher(_cfg(tmp_path), db, sender=sender)
    # map says: send on low, NOT on high — even though a low-threshold would also fire on high.
    db.register_device("map-tok", "Mapped", severities={"low": True, "high": False})
    asyncio.run(d.request_created(db.create_request(_rc("low"))))
    asyncio.run(d.request_created(db.create_request(_rc("high"))))
    sevs = [p["severity"] for (t, p) in sender.sent if t == "map-tok"]
    assert "low" in sevs
    assert "high" not in sevs


def test_map_absent_falls_back_to_threshold(tmp_path, db):
    sender = FakeSender()
    d = Dispatcher(_cfg(tmp_path), db, sender=sender)
    # no map → min_severity threshold governs: high fires, low does not.
    db.register_device("thr-tok", "Threshold", min_severity="high")
    asyncio.run(d.request_created(db.create_request(_rc("high"))))
    asyncio.run(d.request_created(db.create_request(_rc("low"))))
    sevs = [p["severity"] for (t, p) in sender.sent if t == "thr-tok"]
    assert "high" in sevs
    assert "low" not in sevs


def test_badge_present_only_when_enabled(tmp_path, db):
    sender = FakeSender()
    d = Dispatcher(_cfg(tmp_path), db, sender=sender)
    db.register_device("badge-on", "On", badge=True)
    db.register_device("badge-off", "Off", badge=False)
    db.create_request(_rc("critical"))          # first pending request
    req = db.create_request(_rc("critical"))    # second pending request
    asyncio.run(d.request_created(req))
    pending = len(db.list_requests("pending"))
    on = [p for (t, p) in sender.sent if t == "badge-on"]
    off = [p for (t, p) in sender.sent if t == "badge-off"]
    assert on and on[-1]["aps"]["badge"] == pending == 2
    assert off and "badge" not in off[-1]["aps"]

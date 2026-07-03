import asyncio
from arbiter.apns import build_payload, APNsSender

def _req(**kw): return {"id":"r1","title":"Deploy","severity":"critical", **kw}

def test_build_payload():
    p = build_payload(_req())
    assert p["aps"]["alert"]["title"]=="Deploy"
    assert p["request_id"]=="r1"
    assert p["aps"]["interruption-level"]=="critical"

def test_skipped_when_unconfigured(cfg):
    # cfg fixture leaves apns unset -> not configured
    assert asyncio.run(APNsSender(cfg).send("tok", build_payload(_req())))=="skipped"

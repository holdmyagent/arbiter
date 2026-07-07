import httpx
from hold_sdk import request_approval

def _transport(status_after=1, decision="approved", capture=None):
    state = {"polls": 0}
    def handler(request):
        if capture is not None and request.method == "POST":
            import json
            capture.update(json.loads(request.read()))
        if request.method == "POST":
            return httpx.Response(200, json={"id": "r1", "status": "pending"})
        state["polls"] += 1
        st = decision if state["polls"] >= status_after else "pending"
        return httpx.Response(200, json={"id": "r1", "status": st})
    return httpx.MockTransport(handler)

def test_approved_and_fields_sent(monkeypatch):
    monkeypatch.setenv("HMA_SERVER_URL", "http://test")
    monkeypatch.setenv("HMA_AGENT_TOKEN", "t")
    sent = {}
    out = request_approval("Deploy?", severity="high", target="prod", poll_interval=0,
                           _transport=_transport(capture=sent))
    assert out == "approved" and sent["target"] == "prod" and sent["severity"] == "high"

def test_missing_config_is_denied(monkeypatch):
    monkeypatch.delenv("HMA_SERVER_URL", raising=False)
    monkeypatch.delenv("HMA_AGENT_TOKEN", raising=False)
    assert request_approval("x") == "denied"

def test_server_down_is_denied(monkeypatch):
    monkeypatch.setenv("HMA_SERVER_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("HMA_AGENT_TOKEN", "t")
    assert request_approval("x", timeout=1, poll_interval=0) == "denied"

def test_idempotency_key_and_callback_url_sent(monkeypatch):
    monkeypatch.setenv("HMA_SERVER_URL", "http://test")
    monkeypatch.setenv("HMA_AGENT_TOKEN", "t")
    sent = {}
    out = request_approval("Deploy?", poll_interval=0,
                           idempotency_key="idem-1",
                           callback_url="http://cb.local/hook",
                           _transport=_transport(capture=sent))
    assert out == "approved"
    assert sent["idempotency_key"] == "idem-1"
    assert sent["callback_url"] == "http://cb.local/hook"

def test_optional_fields_omitted_when_unset(monkeypatch):
    """A 0.3.0 SDK against an older server: unknown keys are never sent unless set."""
    monkeypatch.setenv("HMA_SERVER_URL", "http://test")
    monkeypatch.setenv("HMA_AGENT_TOKEN", "t")
    sent = {}
    request_approval("Deploy?", poll_interval=0, _transport=_transport(capture=sent))
    assert "idempotency_key" not in sent
    assert "callback_url" not in sent

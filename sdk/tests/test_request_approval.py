import httpx
from hold_sdk import request_approval
from hold_sdk.client import ArbiterClient

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

def _seq_transport(create_id="r1", get_statuses=(), get_errors_first=0):
    """MockTransport: POST /v1/requests -> {id}; then GETs raise ConnectError for the
    first `get_errors_first` calls, then serve get_statuses in order (last repeats)."""
    calls = {"get": 0}

    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"id": create_id})
        calls["get"] += 1
        if calls["get"] <= get_errors_first:
            raise httpx.ConnectError("transient", request=request)
        i = min(calls["get"] - get_errors_first, len(get_statuses)) - 1
        return httpx.Response(200, json={"status": get_statuses[i]})

    return httpx.MockTransport(handler), calls


def test_server_expired_is_reported_not_denied():
    t, _ = _seq_transport(get_statuses=("pending", "expired"))
    out = request_approval("t", server_url="http://x", token="tk",
                           poll_interval=0, timeout=30, _transport=t)
    assert out == "expired"


def test_expired_surfaces_via_final_read_after_local_deadline():
    # deadline already past (timeout=0): the while loop never runs; the final
    # read observes the server's expiry instead of collapsing to "denied".
    t, calls = _seq_transport(get_statuses=("expired",))
    out = request_approval("t", server_url="http://x", token="tk",
                           poll_interval=0, timeout=0, _transport=t)
    assert out == "expired"
    assert calls["get"] == 1          # exactly the final read


def test_transient_poll_error_does_not_deny():
    t, _ = _seq_transport(get_errors_first=2, get_statuses=("approved",))
    out = request_approval("t", server_url="http://x", token="tk",
                           poll_interval=0, timeout=30, _transport=t)
    assert out == "approved"          # pre-fix: first ConnectError -> "denied"


def test_unreachable_all_the_way_is_denied():
    t, _ = _seq_transport(get_errors_first=10**6)
    out = request_approval("t", server_url="http://x", token="tk",
                           poll_interval=0, timeout=0.2, _transport=t)
    assert out == "denied"            # fail-closed: outcome genuinely unknown


def _make_client(transport):
    c = ArbiterClient("http://x", "tk")
    c._http = httpx.Client(base_url="http://x", transport=transport)
    return c


def test_client_server_expired_is_reported_not_denied():
    t, _ = _seq_transport(get_statuses=("pending", "expired"))
    c = _make_client(t)
    out = c.request_approval("t", poll_interval=0, timeout=30)
    assert out == "expired"


def test_client_expired_surfaces_via_final_read_after_local_deadline():
    t, calls = _seq_transport(get_statuses=("expired",))
    c = _make_client(t)
    out = c.request_approval("t", poll_interval=0, timeout=0)
    assert out == "expired"
    assert calls["get"] == 1          # exactly the final read


def test_client_transient_poll_error_does_not_deny():
    t, _ = _seq_transport(get_errors_first=2, get_statuses=("approved",))
    c = _make_client(t)
    out = c.request_approval("t", poll_interval=0, timeout=30)
    assert out == "approved"          # pre-fix: first ConnectError -> "denied"


def test_client_unreachable_all_the_way_is_denied():
    t, _ = _seq_transport(get_errors_first=10**6)
    c = _make_client(t)
    out = c.request_approval("t", poll_interval=0, timeout=0.2)
    assert out == "denied"            # fail-closed: outcome genuinely unknown

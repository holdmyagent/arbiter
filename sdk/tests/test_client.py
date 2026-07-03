import threading, time
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response
from fastapi.testclient import TestClient
from arbiter.app import create_app
from arbiter.config import Config
from arbiter.db import Database
from hold_sdk.client import ArbiterClient

def _server():
    cfg = Config("A","P",":memory:",None,None,None,"com.holdmyagent.HoldMyAgent",True)
    db = Database(":memory:")
    class S:
        async def send(self,t,p): return "skipped"
    return create_app(cfg, db, S()), db

def test_approved():
    app, db = _server()
    # TestClient is an httpx.Client subclass that properly bridges sync→async ASGI
    tc = TestClient(app, base_url="http://test", raise_server_exceptions=False)
    client = ArbiterClient("http://test","A",app_token="P")
    client._http = tc
    # create via SDK in a thread, approve out-of-band
    result = {}
    def run(): result["r"] = client.request_approval("t", severity="low", ttl=300, poll_interval=0.05)
    th = threading.Thread(target=run); th.start(); time.sleep(0.2)
    rid = db.list_requests("pending")[0]["id"]
    db.set_decision(rid, "approve", "iPhone")
    th.join(timeout=5); assert result["r"]=="approved"

def test_failclosed_bad_url():
    client = ArbiterClient("http://127.0.0.1:1","A")
    assert client.request_approval("t", ttl=1, poll_interval=0.1, timeout=0.5)=="denied"

def test_failclosed_server_500_on_create():
    """Server returns HTTP 500 on POST /v1/requests → fail-closed (denied)."""
    fapp = FastAPI()

    @fapp.post("/v1/requests")
    def _create_error():
        return Response(status_code=500)

    tc = TestClient(fapp, base_url="http://test", raise_server_exceptions=False)
    client = ArbiterClient("http://test", "A")
    client._http = tc
    assert client.request_approval("t", ttl=5, poll_interval=0.05, timeout=1) == "denied"

def test_failclosed_garbage_poll_body():
    """Poll response is not valid JSON → fail-closed (denied)."""
    fapp = FastAPI()

    @fapp.post("/v1/requests")
    def _create_ok():
        return {"id": "stub-x"}

    @fapp.get("/v1/requests/{rid}")
    def _get_garbage(rid: str):
        return PlainTextResponse("not-json!!!")

    tc = TestClient(fapp, base_url="http://test", raise_server_exceptions=False)
    client = ArbiterClient("http://test", "A")
    client._http = tc
    assert client.request_approval("t", ttl=5, poll_interval=0.05, timeout=1) == "denied"

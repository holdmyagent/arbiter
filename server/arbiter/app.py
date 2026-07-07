import asyncio
import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import Identity, require_role, SlidingWindowLimiter
from .models import RequestCreate, Decision, DeviceRegister
from .notify import Dispatcher
from .signing import load_or_create_keypair, public_jwks, sign_verdict
from .stream import Hub
from .web import build_router, session_valid

log = logging.getLogger("arbiter.app")


def create_app(cfg, db, sender, hub: Hub | None = None, ws_heartbeat: float = 30.0, dispatcher=None):
    hub = hub or Hub()
    dispatcher = dispatcher or Dispatcher(cfg, db, sender=sender)
    notify_tasks: set = set()

    config_dir = Path(cfg.loaded_path).expanduser().parent if cfg.loaded_path \
        else Path("~/.config/holdmyagent").expanduser()
    kid, signing_key = load_or_create_keypair(config_dir)

    def _expire_pass(now=None) -> list[dict]:
        """One sweep: flip overdue pending rows to expired and sign an 'expired'
        verdict for each. Sync + clock-injectable so tests drive it directly
        (no sleeping on the 1s loop)."""
        out = []
        for req in db.expire_due(now):
            jws = sign_verdict(kid, signing_key, request_id=req["id"],
                               action_hash=req["action_hash"], decision="expired",
                               decided_at=req["expires_at"],
                               approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
            db.set_verdict(req["id"], jws, kid)
            out.append(db.get_request(req["id"]))
        return out

    def _spawn(coro):
        # Hold a strong reference until done — a bare create_task() result is
        # GC-eligible mid-flight (asyncio only keeps weak refs to tasks).
        t = asyncio.create_task(coro)
        notify_tasks.add(t)
        t.add_done_callback(notify_tasks.discard)
        return t

    @asynccontextmanager
    async def lifespan(app):
        async def sweep():
            while True:
                try:
                    for req in _expire_pass():
                        _spawn(dispatcher.request_decided(req))
                        await hub.publish("request.expired", "request", req)
                except Exception as exc:
                    log.warning("sweep iteration failed: %s", exc)
                await asyncio.sleep(1)
        task = asyncio.create_task(sweep())
        yield
        task.cancel()
    app = FastAPI(title="Arbiter", lifespan=lifespan)
    app.state.hub = hub
    app.state.notify_tasks = notify_tasks
    limiter = SlidingWindowLimiter(10, 60.0)
    app.state.login_limiter = SlidingWindowLimiter(5, 60.0)
    app.state.expire_pass = _expire_pass
    app.state.verdict_kid = kid
    # require_role deps read these three off request.app.state:
    app.state.auth_limiter = limiter
    app.state.cfg = cfg
    app.state.db = db
    appdep = Depends(require_role("app"))

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")), name="static")
    app.include_router(build_router(cfg, db, hub))
    app.state.session_check = lambda v: session_valid(cfg, v)

    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        ct = resp.headers.get("content-type", "")
        if ct.startswith("text/html") and not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
            resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        return resp

    # ── Utility / pairing ────────────────────────────────────────────────────

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/dashboard", status_code=302)

    @app.get("/dashboard", include_in_schema=False)
    def dash_root():
        return RedirectResponse("/dashboard/requests", status_code=302)

    @app.get("/pair", include_in_schema=False)
    def old_pair():
        return RedirectResponse("/dashboard/pair", status_code=302)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/v1/keys")
    def keys():
        return public_jwks(kid, signing_key)

    # ── API v1 ───────────────────────────────────────────────────────────────

    @app.post("/v1/requests")
    async def create(body: RequestCreate,
                     identity: Identity = Depends(require_role("agent", "warden"))):
        # Legacy config tokens (identity.legacy, set by resolve_identity only
        # for config tokens) stay unstamped (requested_by NULL) for
        # back-compat reads; DB tokens are stamped with their name.
        requested_by = None if identity.legacy else identity.name
        if (body.canonical_action is None) != (body.action_hash is None):
            raise HTTPException(422, "canonical_action and action_hash must be supplied together")
        if body.canonical_action is not None:
            computed = hashlib.sha256(body.canonical_action.encode()).hexdigest()
            if computed != body.action_hash:
                raise HTTPException(422, "action_hash does not match canonical_action")
        req = db.create_request(body, requested_by=requested_by)
        _spawn(dispatcher.request_created(req))
        await hub.publish("request.created", "request", req)
        return req

    @app.get("/v1/requests", dependencies=[appdep])
    def list_(status: str | None = None):
        return db.list_requests(status)

    @app.get("/v1/requests/{rid}")
    def get_(rid: str,
             identity: Identity = Depends(require_role("agent", "warden", "app"))):
        r = db.get_request(rid)
        if not r:
            raise HTTPException(404, "not found")
        if identity.role in ("agent", "warden"):
            if identity.legacy:
                # Legacy config agent token (deprecated): sees exactly the
                # legacy-created rows — requested_by IS NULL (its own creates
                # stamp NULL too, so "its own" is the same set).
                if r.get("requested_by") is not None:
                    raise HTTPException(404, "not found")
            elif r.get("requested_by") != identity.name:
                raise HTTPException(404, "not found")
        return r

    @app.get("/v1/requests/{rid}/verdict")
    def get_verdict(rid: str,
                    identity: Identity = Depends(require_role("agent", "warden", "app"))):
        r = db.get_request(rid)
        if r and identity.role in ("agent", "warden"):   # app tokens: unrestricted
            rb = r.get("requested_by")
            if identity.legacy:                 # legacy config token: unstamped rows only
                if rb is not None:
                    r = None
            elif rb != identity.name:           # DB tokens (agent AND warden): own rows only
                r = None
        if not r:
            raise HTTPException(404, "not found")
        if not r.get("verdict_jws"):
            raise HTTPException(404, "no verdict yet")
        return {"verdict": r["verdict_jws"], "kid": r["verdict_kid"]}

    @app.post("/v1/requests/{rid}/decision")
    async def decide(rid: str, body: Decision,
                     identity: Identity = Depends(require_role("app"))):
        r = db.get_request(rid)
        if not r:
            raise HTTPException(404, "not found")
        if identity.name == "app" and identity.role == "app":
            devices = db.list_devices()
            decided_by = devices[0]["name"] if len(devices) == 1 else "app"
        else:
            decided_by = identity.name
        updated = db.set_decision(rid, body.decision, decided_by)
        if not updated:
            raise HTTPException(409, f"not pending (status={r['status']})")
        jws = sign_verdict(kid, signing_key, request_id=updated["id"],
                           action_hash=updated["action_hash"],
                           decision=updated["status"],
                           decided_at=updated["decided_at"],
                           approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
        db.set_verdict(updated["id"], jws, kid)
        updated = db.get_request(rid)
        _spawn(dispatcher.request_decided(updated))
        await hub.publish("request.decided", "request", updated)
        return updated

    @app.post("/v1/devices", dependencies=[appdep])
    async def register(body: DeviceRegister):
        dev = db.register_device(body.apns_token, body.name, body.min_severity,
                                  body.notifications_enabled, body.sound,
                                  severities=body.severities, badge=body.badge)
        await hub.publish("device.updated", "device", dev)
        return dev

    @app.get("/v1/devices", dependencies=[appdep])
    def devices():
        return db.list_devices()

    @app.get("/v1/notify/policy", dependencies=[appdep])
    def notify_policy():
        return dict(cfg.notify_severities)

    @app.websocket("/v1/stream")
    async def stream(ws: WebSocket):
        auth = ws.headers.get("authorization", "")
        cookie = ws.cookies.get("hma_session", "")
        token_ok = auth.startswith("Bearer ") and secrets.compare_digest(
            auth.removeprefix("Bearer ").encode(), cfg.auth.app_token.encode())
        if not (token_ok or app.state.session_check(cookie)):
            await ws.close(code=4401)
            return
        await ws.accept()
        q = hub.subscribe()
        async def heartbeat():
            while True:
                await asyncio.sleep(ws_heartbeat)
                await hub.publish("ping", "data", {})
        hb = asyncio.create_task(heartbeat())
        try:
            while True:
                await ws.send_json(await q.get())
        except WebSocketDisconnect:
            pass
        finally:
            hb.cancel()
            hub.unsubscribe(q)

    return app

import asyncio
import hashlib
import json
import logging
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .auth import Identity, SlidingWindowLimiter, require_role, resolve_identity
from .models import RequestCreate, Decision, DeviceRegister
from .notify import Dispatcher, callback_allowed
from .policy import evaluate_create
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
        """One sweep: (1) flip overdue pending rows to expired and sign an
        'expired' verdict for each; (2) flip stale unconsumed approvals to
        expired, KEEPING the original decision verdict. Sync + clock-injectable
        so tests drive it directly (no sleeping on the 1s loop)."""
        out = []
        for req in db.expire_due(now):
            jws = sign_verdict(kid, signing_key, request_id=req["id"],
                               action_hash=req["action_hash"], decision="expired",
                               decided_at=req["expires_at"],
                               approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
            db.set_verdict(req["id"], jws, kid)
            db.add_audit(req["id"], "verdict_issued", {"decision": "expired", "kid": kid})
            out.append(db.get_request(req["id"]))
        out.extend(db.expire_stale_approvals(cfg.policy.approval_ttl_seconds, now))
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
    create_limiter = SlidingWindowLimiter(cfg.policy.rate_limit_per_minute, 60.0)
    app.state.create_limiter = create_limiter
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
        try:
            db.ping()
        except Exception:
            return JSONResponse(status_code=503, content={"ok": False, "db": False})
        return {"ok": True, "db": True}

    @app.get("/v1/keys")
    def keys():
        return public_jwks(kid, signing_key)

    @app.get("/v1/audit/export")
    def audit_export(request: Request, format: str = "jsonl"):
        # app-role bearer OR a valid admin dashboard session
        authorized = False
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            ident = resolve_identity(db, cfg, auth.removeprefix("Bearer "))
            authorized = ident is not None and ident.role == "app"
        if not authorized and app.state.session_check(request.cookies.get("hma_session", "")):
            authorized = True
        if not authorized:
            raise HTTPException(403, "app token or admin session required")
        if format != "jsonl":
            raise HTTPException(422, "unsupported format (only jsonl)")
        def gen():
            for row in db.iter_audit():
                yield json.dumps(row) + "\n"
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    # ── API v1 ───────────────────────────────────────────────────────────────

    @app.post("/v1/requests")
    async def create(body: RequestCreate,
                     identity: Identity = Depends(require_role("agent", "warden"))):
        # Legacy config tokens (identity.legacy, set by resolve_identity only
        # for config tokens) stay unstamped (requested_by NULL) for
        # back-compat reads; DB tokens are stamped with their name.
        requested_by = None if identity.legacy else identity.name
        scopes = db.get_token_scopes(identity.name) if requested_by else None
        result = evaluate_create(cfg, identity, body, scopes=scopes)
        if not result.allowed:
            db.add_audit("-", "policy_denied",
                         {"identity": identity.name, "action_type": body.action_type,
                          "reason": result.reason})
            raise HTTPException(403, f"policy: {result.reason}")
        body.severity = result.effective_severity   # stored severity = effective
        if create_limiter.blocked(identity.name):
            db.add_audit("-", "rate_limited", {"identity": identity.name})
            raise HTTPException(429, "rate limited")
        create_limiter.record_failure(identity.name)  # count this create in the window
        if body.callback_url and not callback_allowed(cfg.callback_allowlist,
                                                      body.callback_url):
            raise HTTPException(422, "callback_url not in allowlist")
        # ttl clamp: out-of-range values are clamped, never rejected
        body.ttl_seconds = max(cfg.policy.ttl_min_seconds,
                               min(cfg.policy.ttl_max_seconds, body.ttl_seconds))
        # idempotency replay: same identity + key -> the original row (200, no new request)
        if body.idempotency_key:
            existing = db.get_request_by_idem(requested_by, body.idempotency_key)
            if existing:
                return existing
        if (body.canonical_action is None) != (body.action_hash is None):
            raise HTTPException(422, "canonical_action and action_hash must be supplied together")
        if body.canonical_action is not None:
            computed = hashlib.sha256(body.canonical_action.encode()).hexdigest()
            if computed != body.action_hash:
                raise HTTPException(422, "action_hash does not match canonical_action")
        # duplicate-collapse (spec key action_hash|title): an identical action
        # already pending -> that row. Hash-bound creates match on action_hash;
        # unbound creates (action_hash NULL) match on title.
        dup = db.find_duplicate_pending(requested_by, body.action_hash, body.title)
        if dup:
            return dup
        try:
            req = db.create_request(body, requested_by=requested_by)
        except sqlite3.IntegrityError:
            # concurrent identical create lost the unique(requested_by, idempotency_key) race
            existing = db.get_request_by_idem(requested_by, body.idempotency_key) \
                if body.idempotency_key else None
            if existing:
                return existing
            raise
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
            cur = db.get_request(rid)
            # a pending row that refused the guarded UPDATE is expired-by-clock
            shown = "expired" if cur["status"] == "pending" else cur["status"]
            raise HTTPException(409, f"not pending (status={shown})")
        jws = sign_verdict(kid, signing_key, request_id=updated["id"],
                           action_hash=updated["action_hash"],
                           decision=updated["status"],
                           decided_at=updated["decided_at"],
                           approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
        db.set_verdict(updated["id"], jws, kid)
        db.add_audit(updated["id"], "verdict_issued",
                     {"decision": updated["status"], "kid": kid})
        updated = db.get_request(rid)
        _spawn(dispatcher.request_decided(updated))
        await hub.publish("request.decided", "request", updated)
        return updated

    @app.post("/v1/requests/{rid}/consume")
    def consume(rid: str, identity: Identity = Depends(require_role("warden"))):
        # Sync (not async) on purpose: it runs in the threadpool, so concurrent
        # consumes genuinely race and the guarded UPDATE decides the winner.
        code, row = db.consume_request(
            rid, approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
        if code == 404:
            raise HTTPException(404, "not found")
        if code == 410:
            raise HTTPException(410, "approval stale")
        if code == 409:
            raise HTTPException(
                409, f"not consumable (status={row['status']}, consumed_at={row['consumed_at']})")
        db.add_audit(rid, "consumed", {"by": identity.name})
        return {"consumed_at": row["consumed_at"]}

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

import asyncio
import hashlib
import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .auth import SlidingWindowLimiter, resolve_identity, trusted_client_id
from .enroll import resolve_pairing
from .errors import generic_403
from .models import RequestCreate, Decision, DeviceRegister
from .notify import callback_allowed
from .notify.outbox import Outbox, drain_all_at_startup
from .policy import evaluate_create
from .signing import sign_verdict
from .stream import run_stream
from .web import build_router, session_valid

log = logging.getLogger("arbiter.app")


def _spawn_publish(app, tenant_id, epoch, event, req):
    """Background outbox publish that pins ITS OWN cell for its lifetime (§15.4):
    the HTTP request's pin is gone by the time this runs, so re-acquire by object
    via registry.hold and release exactly once. Held strongly in notify_tasks so
    it isn't GC'd mid-flight."""
    st = app.state
    async def run():
        try:
            async with st.registry.hold(tenant_id, epoch) as cell:
                await Outbox(cell.db, cell.dispatcher).publish(event, req)
        except Exception as exc:
            log.warning("background publish failed for %s: %s", tenant_id, exc)
    t = asyncio.create_task(run())
    st.notify_tasks.add(t)
    t.add_done_callback(st.notify_tasks.discard)
    return t


def require_cell(*roles: str):
    """Authenticate the bearer → (Identity, Cell); pin the cell for the whole
    request; release exactly once on EVERY exit path; enforce role. All
    tenant state comes from the returned cell — never app.state. Module-level
    (not nested in create_app): it closes over nothing tenant-scoped, reading
    everything off request.app.state, so it can be imported directly (the
    brief's inline sketch nests it inside create_app, but that would make it
    unimportable as `arbiter.app.require_cell` — module scope is equivalent
    and matches the require_role precedent in auth.py).

    The fleet auth-failure limiter (§13) is keyed on trusted_client_id, which
    with no configured trusted proxy IS the bare peer IP — so it is only ever
    consulted on a FAILED auth (missing/invalid bearer, disabled tenant, wrong
    role). A bearer that resolves successfully is never pre-blocked by that
    key's failure count: otherwise a flood of bad tokens from one shared
    ingress IP would 429 every OTHER tenant's valid traffic sharing that IP —
    the exact fleet-DoS §13 forbids. Blocked-and-still-failing sources still
    get a uniform 429 (checked after the failed resolve, not before)."""
    async def dep(request: Request):
        st = request.app.state
        key = trusted_client_id(request, st.cfg)
        try:
            identity, cell = await resolve_identity(request, st.registry, st.control)
        except HTTPException:
            if st.auth_limiter.blocked(key):
                raise HTTPException(429, "too many failed auth attempts")
            st.auth_limiter.record_failure(key)   # count the failed auth
            raise
        try:
            if roles and identity.role not in roles:
                if st.auth_limiter.blocked(key):
                    raise HTTPException(429, "too many failed auth attempts")
                st.auth_limiter.record_failure(key)
                raise HTTPException(403, "forbidden")   # generic (§11)
            yield (identity, cell)
        finally:
            st.registry.release(cell)                  # exactly once (§15.4)
    return dep


def create_app(cfg, registry, control, *, sender=None, scheduler=None,
                ws_heartbeat: float = 30.0, ws_send_timeout: float = 10.0):
    # sender/ws_send_timeout: accepted-and-stored for later groups (per-cell
    # dispatch already flows through TenantRegistry(sender=...); ws_send_timeout
    # is unused until the stream group (F) wires bounded sends) — pinned here
    # so the signature is stable across Groups C-F (reconciliation ledger #7).
    notify_tasks: set = set()

    def _spawn(coro):
        # Hold a strong reference until done — a bare create_task() result is
        # GC-eligible mid-flight (asyncio only keeps weak refs to tasks).
        t = asyncio.create_task(coro)
        notify_tasks.add(t)
        t.add_done_callback(notify_tasks.discard)
        return t

    @asynccontextmanager
    async def lifespan(app):
        # §9: outbox re-drain is bounded to PROCESS-RESTART only, never cell-open.
        await drain_all_at_startup(registry, control)
        # §16 eviction-race test/ops seam: TenantRegistry.try_evict_idle() is
        # async and its locks bind to whichever loop first uses them -- THIS
        # lifespan's loop. A plain thread (e.g. a test's churn loop) cannot
        # await it directly, so expose a synchronous driver that hops onto
        # this loop via run_coroutine_threadsafe, mirroring scheduler_tick
        # below.
        _loop = asyncio.get_running_loop()

        def evict_tick(timeout: float = 5.0) -> int:
            return asyncio.run_coroutine_threadsafe(
                registry.try_evict_idle(), _loop).result(timeout=timeout)

        app.state.evict_tick = evict_tick
        sched_task = asyncio.create_task(scheduler.run()) if scheduler is not None else None
        if scheduler is not None:
            # §16 test/ops seam: a SYNCHRONOUS, clock-injectable one-shot that
            # drains every entry due at `now` across ALL cells, reusing the
            # scheduler's real firing path (_fire_due/_fire_one -> registry.hold
            # -> cell.signer/db) so the signed verdict lands under the firing
            # cell's own key, exactly like a real background firing. Additive:
            # the async run() loop above stays the only production path.
            #
            # The registry's own locks (e.g. _map_lock) bind to whichever event
            # loop first uses them -- THIS lifespan's loop, via seed() above --
            # so the drain must execute on that same loop, never a fresh one in
            # the calling thread (that would raise "bound to a different event
            # loop"). run_coroutine_threadsafe + a blocking result() does that;
            # safe because scheduler_tick is called from OUTSIDE this loop's
            # thread (a test's main thread, an ops script), never from a live
            # request or from code already running on this loop (that would
            # deadlock on the blocking .result()).
            loop = asyncio.get_running_loop()

            def scheduler_tick(now: datetime | None = None) -> list[dict]:
                now_ts = (now or datetime.now(timezone.utc)).timestamp()

                async def _drain():
                    fired: list[dict] = []
                    while True:
                        batch = await scheduler._fire_due(now=now_ts)
                        if not batch:
                            return fired
                        fired.extend(batch)

                return asyncio.run_coroutine_threadsafe(_drain(), loop).result()

            app.state.scheduler_tick = scheduler_tick
        try:
            yield
        finally:
            if scheduler is not None:
                scheduler.stop()
                if sched_task is not None:
                    await sched_task
                for t in list(scheduler._bg):
                    await t
            for t in list(notify_tasks):
                t.cancel()

    app = FastAPI(title="Arbiter", lifespan=lifespan)
    # app.state holds NOTHING tenant-scoped (§15.1):
    app.state.registry = registry
    app.state.control = control
    app.state.cfg = cfg                         # process-global policy/server/auth(session) ONLY
    app.state.auth_limiter = SlidingWindowLimiter(10, 60.0)   # fleet auth-failure limiter (§13)
    app.state.notify_tasks = notify_tasks
    app.state.session_check = lambda v: session_valid(cfg, v)

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")), name="static")
    app.include_router(build_router(cfg, registry, control))   # dashboard group re-signs build_router

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
    async def health():
        try:
            epoch = control.epoch_of("default")
            if epoch is None:
                raise RuntimeError("default tenant not provisioned")
            async with registry.hold("default", epoch) as cell:
                cell.db.ping()
        except Exception:
            return JSONResponse(status_code=503, content={"ok": False, "db": False})
        return {"ok": True, "db": True}

    @app.get("/v1/keys")
    def keys(ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
        # Tenant is derived from the credential only, and require_cell already
        # pins the resolved cell for this handler's whole lifetime and releases
        # it exactly once (§15.4). This explicit check is the last-line invariant
        # check before serving JWKS: it fails CLOSED (500) rather than ever
        # handing a pairing fetch a neighbour's keys (§7, §15.2, §16
        # eviction-race row). Explicit raise survives python -O (asserts strip).
        identity, cell = ctx
        if identity.tenant_id != cell.tenant_id:
            raise HTTPException(status_code=500, detail="tenant/cell binding mismatch")
        return cell.signer.public_jwks()

    @app.get("/v1/audit/export")
    async def audit_export(request: Request, format: str = "jsonl"):
        # app-role bearer -> its own cell, OR a valid admin dashboard session ->
        # the 'default' cell (back-compat, §14/§16). Inline (not require_cell)
        # because of the bearer-OR-cookie split, but with the same limiter +
        # auth_failure discipline (§13): blocked-check first, record_failure +
        # log on any failed attempt. Tenant is derived from the credential ONLY
        # (§15.2) -- never a query/header hint.
        st = app.state
        key = trusted_client_id(request, st.cfg)
        if st.auth_limiter.blocked(key):
            raise HTTPException(429, "too many failed auth attempts")
        cell = None
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            try:
                identity, resolved = await resolve_identity(request, st.registry, st.control)
            except HTTPException:
                identity, resolved = None, None
            if identity is not None and identity.role == "app":
                cell = resolved
            elif resolved is not None:
                st.registry.release(resolved)          # resolved but not app-role: drop the pin
        if cell is None and st.session_check(request.cookies.get("hma_session", "")):
            # admin dashboard session -> default cell (back-compat, §14).
            # is_disabled is read on EVERY resolution — the same guard
            # resolve_identity applies on the bearer path (it also fails
            # closed on an absent live row), so a disabled default tenant
            # gets the same generic denial on the session path too.
            if not st.control.is_disabled("default"):
                default_epoch = st.control.epoch_of("default")
                if default_epoch is not None:
                    cell = await st.registry.acquire("default", default_epoch)
        if cell is None:
            st.auth_limiter.record_failure(key)
            reason = "invalid_token" if auth.startswith("Bearer ") else "missing_bearer"
            log.warning("auth_failure key=%s reason=%s", key, reason)  # never log the supplied value
            raise HTTPException(403, "app token or admin session required")
        if format != "jsonl":
            st.registry.release(cell)
            raise HTTPException(422, "unsupported format (only jsonl)")
        def gen():
            try:
                for row in cell.db.iter_audit():
                    yield json.dumps(row) + "\n"
            finally:
                st.registry.release(cell)               # release after the stream drains (§15.4)
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")

    # ── API v1 ───────────────────────────────────────────────────────────────

    @app.post("/v1/requests")
    async def create(body: RequestCreate,
                     ctx: tuple = Depends(require_cell("agent", "warden"))):
        identity, cell = ctx
        db = cell.db
        # Legacy config tokens (identity.legacy, set by resolve_identity only
        # for config tokens) stay unstamped (requested_by NULL) for
        # back-compat reads; DB tokens are stamped with their name.
        requested_by = None if identity.legacy else identity.name
        scopes = None if identity.legacy else identity.scopes
        result = evaluate_create(cfg, identity, body, scopes=scopes)
        if not result.allowed:
            db.add_audit("-", "policy_denied",
                         {"identity": identity.name, "action_type": body.action_type,
                          "reason": result.reason})
            raise HTTPException(403, f"policy: {result.reason}")
        body.severity = result.effective_severity   # stored severity = effective
        if cell.create_limiter.blocked(identity.name):
            db.add_audit("-", "rate_limited", {"identity": identity.name})
            raise HTTPException(429, "rate limited")
        cell.create_limiter.record_failure(identity.name)  # count this create in the window
        if body.callback_url and not callback_allowed(
                cell.dispatcher.cfg.callback_allowlist, body.callback_url):
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
        if scheduler is not None:
            scheduler.schedule(req["expires_at"], cell.tenant_id, req["id"])
        _spawn_publish(app, cell.tenant_id, cell.epoch, "request.created", req)
        cell.hub.publish({"event": "request.created", "request": req})
        return req

    @app.get("/v1/requests")
    def list_(status: str | None = None, ctx: tuple = Depends(require_cell("app"))):
        _identity, cell = ctx
        return cell.db.list_requests(status)

    @app.get("/v1/requests/{rid}")
    def get_(rid: str, ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
        identity, cell = ctx
        r = cell.db.get_request(rid)
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
    def get_verdict(rid: str, ctx: tuple = Depends(require_cell("agent", "warden", "app"))):
        identity, cell = ctx
        r = cell.db.get_request(rid)
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
    async def decide(rid: str, body: Decision, ctx: tuple = Depends(require_cell("app"))):
        identity, cell = ctx
        db = cell.db
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
        jws = sign_verdict(cell.signer, request_id=updated["id"],
                           action_hash=updated["action_hash"],
                           decision=updated["status"],
                           decided_at=updated["decided_at"],
                           approval_ttl=cfg.policy.approval_ttl_seconds,
                           tenant_id=cell.tenant_id)
        db.set_verdict(updated["id"], jws, cell.signer.kid)
        db.add_audit(updated["id"], "verdict_issued",
                     {"decision": updated["status"], "kid": cell.signer.kid})
        updated = db.get_request(rid)
        if scheduler is not None and updated["status"] == "approved":
            deadline = (datetime.fromisoformat(updated["decided_at"])
                        + timedelta(seconds=cfg.policy.approval_ttl_seconds)).isoformat()
            scheduler.schedule(deadline, cell.tenant_id, rid)
        _spawn_publish(app, cell.tenant_id, cell.epoch, "request.decided", updated)
        cell.hub.publish({"event": "request.decided", "request": updated})
        return updated

    @app.post("/v1/requests/{rid}/consume")
    def consume(rid: str, ctx: tuple = Depends(require_cell("warden"))):
        # Sync (not async) on purpose: it runs in the threadpool, so concurrent
        # consumes genuinely race and the guarded UPDATE decides the winner.
        identity, cell = ctx
        code, row = cell.db.consume_request(
            rid, approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
        if code == 404:
            raise HTTPException(404, "not found")
        if code == 410:
            raise HTTPException(410, "approval stale")
        if code == 409:
            raise HTTPException(
                409, f"not consumable (status={row['status']}, consumed_at={row['consumed_at']})")
        cell.db.add_audit(rid, "consumed", {"by": identity.name})
        return {"consumed_at": row["consumed_at"]}

    @app.post("/v1/devices")
    async def register(body: DeviceRegister, ctx: tuple = Depends(require_cell("app"))):
        _identity, cell = ctx
        dev = cell.db.register_device(body.apns_token, body.name, body.min_severity,
                                      body.notifications_enabled, body.sound,
                                      severities=body.severities, badge=body.badge)
        cell.hub.publish({"event": "device.updated", "device": dev})
        return dev

    @app.post("/v1/devices/enroll")
    async def enroll(body: DeviceRegister, request: Request):
        # Phone-facing enrollment (§10). Tenant is derived SOLELY from the
        # single-use pairing credential — no caller hint. The device row is
        # written only to the credential's cell (no global device table), so
        # push tokens are namespaced per tenant by construction.
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise generic_403()
        code = auth.removeprefix("Bearer ")
        async with resolve_pairing(code, request.app.state.registry,
                                   request.app.state.control) as cell:
            dev = cell.db.register_device(
                body.apns_token, body.name, body.min_severity,
                body.notifications_enabled, body.sound,
                severities=body.severities, badge=body.badge)
            cell.hub.publish({"event": "device.updated", "device": dev})
            return {**dev, "tenant_id": cell.tenant_id}

    @app.get("/v1/devices")
    def devices(ctx: tuple = Depends(require_cell("app"))):
        _identity, cell = ctx
        return cell.db.list_devices()

    @app.get("/v1/notify/policy")
    def notify_policy(ctx: tuple = Depends(require_cell("app"))):
        _identity, cell = ctx
        return dict(cell.dispatcher.cfg.notify_severities)

    @app.websocket("/v1/stream")
    async def stream(ws: WebSocket):
        await run_stream(ws, ws.app.state.registry, ws.app.state.control,
                         resolve=resolve_identity,
                         heartbeat=ws_heartbeat, send_timeout=ws_send_timeout)

    return app

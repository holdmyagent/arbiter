import hashlib, hmac
from pathlib import Path
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, TimestampSigner

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
MAX_AGE = 7 * 24 * 3600

# Logged-out session values. Deliberately a single-process in-memory revocation
# list: the server is single-instance by design, so no shared store is needed.
# A restart clears revocations, but the signature + max_age check still bounds
# exposure of any not-yet-expired value.
_REVOKED: set[str] = set()

def _signer(cfg) -> TimestampSigner:
    return TimestampSigner(cfg.auth.session_secret)

def make_session(cfg) -> str:
    return _signer(cfg).sign(b"admin").decode()

def session_valid(cfg, value: str) -> bool:
    if not value: return False
    if value in _REVOKED: return False
    try:
        _signer(cfg).unsign(value.encode(), max_age=MAX_AGE); return True
    except BadSignature:
        return False

def csrf_token(cfg, session_value: str) -> str:
    return hmac.new(cfg.auth.session_secret.encode(),
                    b"csrf:" + session_value.encode(), hashlib.sha256).hexdigest()

def require_session(cfg):
    def dep(request: Request):
        v = request.cookies.get("hma_session", "")
        if not session_valid(cfg, v):
            raise HTTPException(303, headers={"Location": "/dashboard/login"})
        return v
    return dep

def _check_csrf(cfg, session_value: str, supplied: str):
    if not hmac.compare_digest(csrf_token(cfg, session_value), supplied or ""):
        raise HTTPException(403, "bad csrf token")

def _set_cookie(resp, request: Request, value: str):
    secure = request.url.scheme == "https" or \
             request.headers.get("x-forwarded-proto", "") == "https"
    resp.set_cookie("hma_session", value, httponly=True, samesite="lax",
                    secure=secure, max_age=MAX_AGE)

def build_router(cfg, db, hub) -> APIRouter:
    r = APIRouter(prefix="/dashboard")
    session = Depends(require_session(cfg))

    @r.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return TEMPLATES.TemplateResponse(request, "login.html", {"error": None})

    @r.post("/login")
    def login(request: Request, password: str = Form(...)):
        import secrets as s
        lim = request.app.state.login_limiter
        ip = request.client.host if request.client else "unknown"
        if lim.blocked(ip):
            raise HTTPException(429, "too many attempts")
        if not s.compare_digest(password, cfg.auth.admin_password):
            lim.record_failure(ip)
            return TEMPLATES.TemplateResponse(request, "login.html",
                                              {"error": "Wrong password"}, status_code=401)
        resp = RedirectResponse("/dashboard", status_code=303)
        _set_cookie(resp, request, make_session(cfg))
        return resp

    @r.post("/logout")
    def logout(request: Request, sv: str = session, csrf: str = Form(default="")):
        _check_csrf(cfg, sv, csrf)
        _REVOKED.add(sv)  # invalidate server-side too — deleting the cookie alone leaves the value replayable
        resp = RedirectResponse("/dashboard/login", status_code=303)
        resp.delete_cookie("hma_session")
        return resp

    @r.get("/pair", response_class=HTMLResponse)
    def pair(request: Request, sv: str = session):
        import io, segno
        from ..pair import build_pairing_payload, local_ip
        base = f"http://{local_ip()}:{cfg.server.port}"
        payload = build_pairing_payload(base, cfg.auth.app_token)
        buf = io.BytesIO()
        segno.make(payload).save(buf, kind="svg", xmldecl=False, nl=False, scale=4)
        return TEMPLATES.TemplateResponse(request, "pair.html", {
            "svg": buf.getvalue().decode(), "base": base,
            "csrf": csrf_token(cfg, sv)})

    @r.get("/requests", response_class=HTMLResponse)
    def requests_page(request: Request, sv: str = session, fragment: int = 0):
        reqs = db.list_requests()
        ctx = {"requests": reqs, "csrf": csrf_token(cfg, sv)}
        tpl = "_request_rows.html" if fragment else "requests.html"
        return TEMPLATES.TemplateResponse(request, tpl, ctx)

    @r.get("/requests/{rid}", response_class=HTMLResponse)
    def request_detail(request: Request, rid: str, sv: str = session):
        req = db.get_request(rid)
        if not req: raise HTTPException(404)
        return TEMPLATES.TemplateResponse(request, "request_detail.html",
            {"r": req, "audit": db.list_audit(rid), "csrf": csrf_token(cfg, sv)})

    @r.get("/devices", response_class=HTMLResponse)
    def devices_page(request: Request, sv: str = session):
        return TEMPLATES.TemplateResponse(request, "devices.html",
            {"devices": db.list_devices(), "csrf": csrf_token(cfg, sv)})

    @r.post("/devices/{did}/rename")
    def device_rename(request: Request, did: str, sv: str = session,
                      name: str = Form(...), csrf: str = Form(default="")):
        _check_csrf(cfg, sv, csrf)
        if not db.rename_device(did, name): raise HTTPException(404)
        return RedirectResponse("/dashboard/devices", status_code=303)

    @r.post("/devices/{did}/delete")
    def device_delete(request: Request, did: str, sv: str = session, csrf: str = Form(default="")):
        _check_csrf(cfg, sv, csrf)
        if not db.delete_device(did): raise HTTPException(404)
        return RedirectResponse("/dashboard/devices", status_code=303)

    @r.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, sv: str = session, request_id: str | None = None):
        return TEMPLATES.TemplateResponse(request, "audit.html",
            {"events": db.list_audit(request_id), "request_id": request_id or ""})

    @r.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, sv: str = session):
        return TEMPLATES.TemplateResponse(request, "settings.html", {
            "cfg": cfg, "csrf": csrf_token(cfg, sv)})

    @r.post("/settings/rotate")
    def rotate(request: Request, sv: str = session,
               which: str = Form(...), csrf: str = Form(default="")):
        import secrets as s, tomlkit
        from pathlib import Path
        from ..config import Config
        _check_csrf(cfg, sv, csrf)
        if which not in ("agent", "app"): raise HTTPException(400)
        new = s.token_hex(32)
        path = Path(Config.default_path())
        doc = tomlkit.parse(path.read_text()) if path.exists() else tomlkit.document()
        doc.setdefault("auth", tomlkit.table())[f"{which}_token"] = new
        path.write_text(tomlkit.dumps(doc))
        setattr(cfg.auth, f"{which}_token", new)
        db.add_audit("-", "token_rotated", {"which": which})
        return RedirectResponse("/dashboard/settings", status_code=303)

    return r

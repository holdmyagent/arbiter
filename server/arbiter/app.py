import asyncio
import html
import io
import secrets
from contextlib import asynccontextmanager
from importlib.metadata import version as _pkg_version

import segno
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from .auth import require_agent, require_app
from .models import RequestCreate, Decision, DeviceRegister, severity_rank
from .apns import build_payload, send_with_retry
from .pair import build_pairing_payload, local_ip

try:
    _VERSION = _pkg_version("arbiter-server")
except Exception:
    _VERSION = "unknown"


def _build_svg(payload: str, scale: int = 4) -> str:
    """Render *payload* as an inline SVG QR code (no XML declaration)."""
    buf = io.BytesIO()
    segno.make(payload).save(buf, kind="svg", xmldecl=False, nl=False, scale=scale)
    return buf.getvalue().decode("utf-8")


def create_app(cfg, db, sender):
    @asynccontextmanager
    async def lifespan(app):
        async def sweep():
            while True:
                db.expire_due(); await asyncio.sleep(1)
        task = asyncio.create_task(sweep())
        yield
        task.cancel()
    app = FastAPI(title="Arbiter", lifespan=lifespan)
    agent = Depends(require_agent(cfg)); appdep = Depends(require_app(cfg))

    # ── Utility / pairing ────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def root():
        return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Hold My Agent</title></head>
<body>
<h1>Hold My Agent — server</h1>
<ul>
  <li><a href="/pair">Pair the iOS app</a> — scan this QR code to connect</li>
  <li><a href="/health">Health check</a></li>
  <li><a href="/docs">API docs</a></li>
</ul>
</body></html>""")

    @app.get("/health")
    def health():
        return {"status": "ok", "version": _VERSION}

    @app.get("/pair", response_class=HTMLResponse)
    def pair(request: Request):
        # Resolve base URL from the incoming request (works behind reverse proxies too)
        base = str(request.base_url).rstrip("/")
        if not base or base == "http://testclient":
            base = f"http://{local_ip()}:8000"
        token = cfg.app_token
        # Auth gate: the token is a long-lived credential — never reveal it on an
        # unauthenticated page. The operator (who set ARBITER_APP_TOKEN) views this
        # by appending ?token=<app token>; unauthenticated scanners cannot exfiltrate it.
        supplied = request.query_params.get("token", "")
        if not (supplied and secrets.compare_digest(supplied, token)):
            gate = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Pair — Hold My Agent</title></head>
<body style="font-family:-apple-system,system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;color:#111">
  <h1>Pair Hold My Agent</h1>
  <p>To protect your app token, this page requires it. Open
     <code>/pair?token=YOUR_APP_TOKEN</code> (the value you set as
     <code>ARBITER_APP_TOKEN</code>), or run the safer terminal command
     <code>python -m arbiter.pair</code> which never exposes the token over HTTP.</p>
</body></html>"""
            return HTMLResponse(gate, status_code=401)
        payload = build_pairing_payload(base, token)
        svg = _build_svg(payload)
        run_cmd = f"python -m arbiter.pair --host {base} --token {token}"
        # Escape every interpolated value — the base URL derives from the client-controlled
        # Host header, so unescaped interpolation would be reflected XSS.
        token = html.escape(token, quote=True)
        payload = html.escape(payload, quote=True)
        run_cmd = html.escape(run_cmd, quote=True)
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Pair — Hold My Agent</title>
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
            margin: 2rem auto; padding: 0 1rem; color: #111; }}
    .qr  {{ text-align: center; margin: 1.5rem 0; }}
    .qr svg {{ max-width: 260px; height: auto; }}
    code {{ background: #f4f4f4; padding: 0.2em 0.4em; border-radius: 4px;
             word-break: break-all; font-size: 0.9em; }}
    pre  {{ background: #f4f4f4; padding: 0.8em; border-radius: 6px; overflow-x: auto; }}
    .warn {{ background: #fff3cd; border-left: 4px solid #ffc107;
              padding: 0.6em 1em; border-radius: 4px; margin-top: 1.5rem; }}
  </style>
</head>
<body>
  <h1>Pair Hold My Agent</h1>
  <p>Scan the QR code with the iOS app, or copy the values below for manual entry.</p>

  <div class="qr">{svg}</div>

  <h2>App token</h2>
  <p><code id="tok">{token}</code></p>

  <h2>Deep-link payload</h2>
  <p><code>{payload}</code></p>

  <h2>CLI — print QR in the terminal</h2>
  <pre>{run_cmd}</pre>

  <div class="warn">
    <strong>Security notice:</strong> Show this page only on a trusted network —
    it reveals your app token.  The CLI path (<code>python -m arbiter.pair</code>)
    is safer for remote setups because it never exposes the token over HTTP.
  </div>

  <p style="margin-top:2rem"><a href="/">← Back</a> &nbsp;·&nbsp;
     <a href="/health">Health</a></p>
</body>
</html>"""
        return HTMLResponse(page)

    # ── API v1 ───────────────────────────────────────────────────────────────

    @app.post("/v1/requests", dependencies=[agent])
    async def create(body: RequestCreate):
        req = db.create_request(body)
        req_rank = severity_rank(req["severity"])
        for dev in db.list_devices():
            if not dev["notifications_enabled"]:
                continue
            if severity_rank(dev["min_severity"]) <= req_rank:
                payload = build_payload(req, sound=bool(dev["sound"]))
                # fire-and-forget; S3 wraps this in send_with_retry
                asyncio.create_task(send_with_retry(sender, dev["apns_token"], payload))
        return req

    @app.get("/v1/requests", dependencies=[appdep])
    def list_(status: str | None = None):
        return db.list_requests(status)

    @app.get("/v1/requests/{rid}")
    def get_(rid: str):
        r = db.get_request(rid)
        if not r: raise HTTPException(404, "not found")
        return r

    @app.post("/v1/requests/{rid}/decision", dependencies=[appdep])
    def decide(rid: str, body: Decision):
        r = db.get_request(rid)
        if not r: raise HTTPException(404, "not found")
        devices = db.list_devices()
        decided_by = devices[0]["name"] if len(devices) == 1 else "app"
        updated = db.set_decision(rid, body.decision, decided_by)
        if not updated: raise HTTPException(409, f"not pending (status={r['status']})")
        return updated

    @app.post("/v1/devices", dependencies=[appdep])
    def register(body: DeviceRegister):
        return db.register_device(body.apns_token, body.name, body.min_severity,
                                  body.notifications_enabled, body.sound)

    return app

import hashlib
import json
import logging
import os
import secrets as pysecrets
import sqlite3
import sys
import time
from pathlib import Path
import click
import httpx

from .config import Config

class _JsonFormatter(logging.Formatter):
    def format(self, rec):
        return json.dumps({"ts": self.formatTime(rec), "level": rec.levelname,
                           "logger": rec.name, "msg": rec.getMessage()})

def _base_url(url_option: str | None, cfg: Config) -> str:
    """--url flag beats HMA_URL env beats the localhost default."""
    return url_option or os.environ.get("HMA_URL") or f"http://127.0.0.1:{cfg.server.port}"

CONFIG_TEMPLATE = """# Hold My Agent — Arbiter server configuration
[server]
host = "127.0.0.1"          # use "0.0.0.0" (or `hma serve --lan`) so phones can reach it
port = 8000
db_path = "~/.local/share/holdmyagent/arbiter.sqlite3"

[auth]
agent_token = "{agent}"
app_token = "{app}"
admin_password = "{admin}"
session_secret = "{session}"

[policy]                    # create-time policy (0.4.0)
ttl_min_seconds = 30
ttl_max_seconds = 86400
approval_ttl_seconds = 600  # how long an approval stays consumable
rate_limit_per_minute = 30  # per-identity create rate limit
deny_action_types = []      # e.g. ["db.drop"]
# [policy.severity_floors]  # e.g. deploy = "high"

[notify]                    # restrict per-request callback_url destinations
callback_allowlist = []     # e.g. ["10.0.0.0/8", "https://hooks.example.com/*"]; [] = allow all (legacy)
                            # entries must be scheme://host[:port]/path URL patterns or CIDR strings
                            # — bare hostnames match nothing (fail-closed). For URL patterns, scheme
                            # and host are literal (a leading "*." on the host matches subdomains
                            # only); "*" in the path is path-only and never crosses the host boundary.
                            # Ports: omit to match any port; a pinned port is exact and NOT
                            # default-normalized (":443" rejects a URL with no explicit port).

[notify.apns]               # optional — bring your own Apple Developer key
key_path = ""
key_id = ""
team_id = ""
bundle_id = "com.holdmyagent.HoldMyAgent"
sandbox = false

[notify.ntfy]               # optional — phone alerts with no Apple account
url = "https://ntfy.sh"
topic = ""
token = ""

[notify.webhook]            # optional — generic integration
url = ""
secret = ""

# [notify.severities]       # server-wide push policy — managed from the dashboard (Settings → Alert severities)
"""

@click.group()
def main():
    """Hold My Agent — self-hosted, fail-closed approvals for AI agents."""

@main.command()
@click.option("--force", is_flag=True, help="Overwrite an existing config file.")
def init(force):
    """Write a fresh config with random credentials."""
    path = Path(Config.default_path())
    if path.exists():
        if not force:
            raise click.ClickException(f"{path} exists (use --force to overwrite)")
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    creds = dict(agent=pysecrets.token_hex(32), app=pysecrets.token_hex(32),
                 admin=pysecrets.token_urlsafe(16), session=pysecrets.token_hex(32))
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(CONFIG_TEMPLATE.format(**creds))
    click.echo(f"Wrote {path}")
    click.echo(f"  agent token:    {creds['agent']}")
    click.echo(f"  app token:      {creds['app']}")
    click.echo(f"  admin password: {creds['admin']}  (dashboard login)")
    click.echo("Shown once — they live in the config file from now on.")

@main.command()
@click.option("--config", "config_path", default=None, help="Path to config.toml")
@click.option("--lan", is_flag=True, help="Bind 0.0.0.0 and print the LAN pairing URL.")
@click.option("--log-json", is_flag=True, help="Emit logs as JSON lines.")
def serve(config_path, lan, log_json):
    """Run the Arbiter server."""
    import uvicorn
    from .pair import local_ip
    if log_json:
        h = logging.StreamHandler()
        h.setFormatter(_JsonFormatter())
        logging.basicConfig(level=logging.INFO, handlers=[h])
    else:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = Config.load(config_path)
    problems = cfg.validate_for_serve()
    if problems:
        raise click.ClickException("refusing to start:\n  - " + "\n  - ".join(problems))
    from .provisioning import (ServeLockError, acquire_serve_lock, control_path_for,
                               ensure_default_cell, tenants_root_for)
    try:
        acquire_serve_lock(cfg)   # raw fd stays open for the process lifetime
    except ServeLockError as exc:
        raise click.ClickException(str(exc))
    host = "0.0.0.0" if lan else cfg.server.host
    if lan or host == "0.0.0.0":
        click.echo(f"Pair page: http://{local_ip()}:{cfg.server.port}/dashboard/pair")
    from .notify import APNsSender
    from .app import create_app
    from .control import ControlPlane
    from .registry import TenantRegistry
    from .scheduler import ExpiryScheduler
    # Single-tenant back-compat boot (iOS 0.5.0): one control plane + one
    # provisioned "default" cell rooted alongside the configured db_path —
    # mirrors arbiter/main.py's boot (task C1).
    # control_path_for/tenants_root_for are the single source of truth for
    # this layout — the tenant CLI resolves through the same helpers, so
    # `hma tenant create` and `hma serve` always agree on one control.db.
    # ensure_default_cell auto-migrates a legacy single-tenant DB instead of
    # minting an empty default, so serve-before-migrate on an upgraded install
    # stays back-compat safe (§14/C1) regardless of operator ordering.
    tenants_root = tenants_root_for(cfg)
    control = ControlPlane.open(control_path_for(cfg).parent, tenants_root)
    ensure_default_cell(cfg, control, tenants_root)
    sender = APNsSender(cfg)
    registry = TenantRegistry(control, cfg=cfg, sender=sender)
    scheduler = ExpiryScheduler(registry, control,
                                approval_ttl_seconds=cfg.policy.approval_ttl_seconds)
    app = create_app(cfg, registry, control, sender=sender, scheduler=scheduler)
    # log_config=None: leave uvicorn's loggers unconfigured so they propagate to
    # the root handler set up above (JSON or plain) instead of uvicorn's own
    # dictConfig (which sets propagate=False with plain formatters).
    uvicorn.run(app, host=host, port=cfg.server.port, log_config=None)

@main.command()
@click.option("--config", "config_path", default=None)
@click.option("--host", "host_url", default=None, help="Server base URL for the QR (default http://<LAN-IP>:<port>)")
def pair(config_path, host_url):
    """Print the pairing QR code in the terminal."""
    import segno
    from .pair import build_pairing_payload, local_ip
    cfg = Config.load(config_path)
    if not cfg.auth.app_token:
        raise click.ClickException("no app_token in config — run `hma init` first")
    base = host_url or f"http://{local_ip()}:{cfg.server.port}"
    payload = build_pairing_payload(base, cfg.auth.app_token)
    click.echo(segno.make(payload).terminal(compact=True))
    click.echo(f"URL:     {base}")
    click.echo(f"Payload: {payload}")

def _gather_status(client: httpx.Client, app_token: str) -> dict:
    hdr = {"Authorization": f"Bearer {app_token}"}
    r = client.get("/health")
    r.raise_for_status()
    d = client.get("/v1/devices", headers=hdr)
    d.raise_for_status()
    p = client.get("/v1/requests", headers=hdr, params={"status": "pending"})
    p.raise_for_status()
    return {"ok": r.json().get("ok", False), "devices": d.json(), "pending": p.json()}

def _audit_export(client: httpx.Client, app_token: str, fmt: str,
                  out_path: str | None) -> int:
    r = client.get("/v1/audit/export",
                   headers={"Authorization": f"Bearer {app_token}"},
                   params={"format": fmt})
    r.raise_for_status()
    text = r.text
    if out_path:
        Path(out_path).write_text(text)
    else:
        click.echo(text, nl=False)
    return sum(1 for line in text.splitlines() if line.strip())

@main.command()
@click.option("--config", "config_path", default=None)
@click.option("--url", "url_option", default=None,
              help="Server base URL (or HMA_URL env; default http://127.0.0.1:<port>).")
def status(config_path, url_option):
    """Show server health, devices, and pending requests."""
    cfg = Config.load(config_path)
    base = _base_url(url_option, cfg)
    try:
        with httpx.Client(base_url=base, timeout=5) as c:
            st = _gather_status(c, cfg.auth.app_token)
    except httpx.HTTPStatusError as exc:
        raise click.ClickException(f"server error at {base}: {exc}")
    except httpx.HTTPError as exc:
        raise click.ClickException(f"server unreachable at {base}: {exc}")
    ok, devices, pending = st["ok"], st["devices"], st["pending"]
    click.echo(f"health:  {'ok' if ok else 'NOT OK'}")
    click.echo(f"notifiers: apns={'on' if cfg.apns.configured else 'off'} "
               f"ntfy={'on' if cfg.ntfy.enabled else 'off'} webhook={'on' if cfg.webhook.enabled else 'off'}")
    click.echo(f"devices: {len(devices)}")
    for d in devices:
        click.echo(f"  - {d['name']} (min severity {d['min_severity']})")
    click.echo(f"pending requests: {len(pending)}")

def _ask(client: httpx.Client, agent_token: str, *, title: str, severity: str,
         target: str | None, ttl: int, description: str) -> tuple[int, dict]:
    hdr = {"Authorization": f"Bearer {agent_token}"}
    try:
        r = client.post("/v1/requests", headers=hdr, json={
            "title": title, "description": description, "severity": severity,
            "target": target, "ttl_seconds": ttl})
        r.raise_for_status()
        req = r.json()
        deadline = time.time() + ttl + 5
        while time.time() < deadline:
            g = client.get(f"/v1/requests/{req['id']}", headers=hdr)
            g.raise_for_status()
            cur = g.json()
            if cur["status"] != "pending":
                return (0 if cur["status"] == "approved" else 1), cur
            time.sleep(1)
        return 1, {**req, "status": "expired"}
    except Exception as exc:
        return 2, {"error": str(exc)}

@main.command()
@click.argument("title")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]), default="medium")
@click.option("--target", default=None)
@click.option("--ttl", type=int, default=300)
@click.option("--description", default="")
@click.option("--url", "url_option", default=None,
              help="Server base URL (or HMA_URL env; default http://127.0.0.1:<port>).")
@click.option("--config", "config_path", default=None)
def ask(title, severity, target, ttl, description, url_option, config_path):
    """Create an approval request and block until it is decided.

    Exit codes: 0 approved · 1 denied/expired · 2 error (fail-closed: treat nonzero as no).
    """
    cfg = Config.load(config_path)
    base = _base_url(url_option, cfg)
    with httpx.Client(base_url=base, timeout=10) as client:
        code, decision = _ask(client, cfg.auth.agent_token, title=title,
                              severity=severity, target=target, ttl=ttl, description=description)
    click.echo(json.dumps(decision, indent=2))
    sys.exit(code)

# ── per-identity tokens (stored hashed; see `tokens` table, migration 4) ────

_RESERVED_TOKEN_NAMES = {"agent", "app"}  # fixed identity names of the legacy config tokens

def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def _build_scopes(action_types, max_severity):
    if not (action_types or max_severity):
        return None
    scopes = {}
    if action_types:
        scopes["action_types"] = [a.strip() for a in action_types.split(",") if a.strip()]
    if max_severity:
        scopes["max_severity"] = max_severity
    return scopes

def _expiry_iso(expires_days):
    if expires_days is None:
        return None
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

def _cell_db_for(control, tenant_id):
    from .db import Database
    return Database(str(Path(control.tenant_dir(tenant_id)) / "arbiter.sqlite3"))

@main.group()
def token():
    """Manage per-identity API tokens (secrets shown once, stored as sha256)."""

@token.command("create")
@click.argument("name")
@click.option("--role", type=click.Choice(["agent", "warden", "app"]), required=True,
              help="agent: create+read own · warden: create/read-own/consume · app: decide/list.")
@click.option("--tenant", "tenant_id", default=None,
              help="Tenant cell to mint into (multi-tenant installs; defaults to 'default').")
@click.option("--action-types", default=None,
              help="Comma-separated action_type allowlist scope (e.g. deploy,restart).")
@click.option("--max-severity", type=click.Choice(["low", "medium", "high", "critical"]),
              default=None, help="Severity cap scope.")
@click.option("--expires-days", type=int, default=None, help="Expire the token after N days.")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def token_create(name, role, tenant_id, action_types, max_severity, expires_days, config_path):
    """Mint a token for NAME. The secret is printed ONCE and never stored."""
    from .db import Database
    from .provisioning import control_path_for, mint_cell_token
    if name in _RESERVED_TOKEN_NAMES:
        raise click.ClickException(
            f"'{name}' is reserved for the legacy config-token identity")
    cfg = Config.load(config_path)
    scopes, expires_at = _build_scopes(action_types, max_severity), _expiry_iso(expires_days)
    control_path = control_path_for(cfg)
    if tenant_id or control_path.exists():
        tid = tenant_id or "default"
        control = _control(cfg)
        if control.epoch_of(tid) is None:
            raise click.ClickException(f"no such tenant '{tid}'")
        cell = _cell_db_for(control, tid)
        try:
            value = mint_cell_token(control, cell, tid, name, role, scopes, expires_at)
        except sqlite3.IntegrityError:
            raise click.ClickException(f"token name '{name}' already exists in tenant '{tid}'")
    else:
        db = Database(cfg.db_path_expanded())
        value = f"hma_{role}_{pysecrets.token_hex(24)}"
        try:
            db.create_token(name, role, _hash_token(value), scopes, expires_at)
        except sqlite3.IntegrityError:
            raise click.ClickException(f"token name '{name}' already exists")
        db.add_audit("-", "token_created",
                     {"name": name, "role": role, "scopes": scopes, "expires_at": expires_at})
    click.echo(f"token: {value}")
    click.echo("Shown once — only its sha256 hash is stored.")

@token.command("list")
@click.option("--tenant", "tenant_id", default=None, help="Tenant cell to list (default 'default').")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def token_list(tenant_id, config_path):
    """List tokens (never shows secrets or hashes)."""
    from .db import Database
    from .provisioning import control_path_for
    cfg = Config.load(config_path)
    control_path = control_path_for(cfg)
    if tenant_id or control_path.exists():
        tid = tenant_id or "default"
        control = _control(cfg)
        if control.epoch_of(tid) is None:
            raise click.ClickException(f"no such tenant '{tid}'")
        db = _cell_db_for(control, tid)
    else:
        db = Database(cfg.db_path_expanded())
    rows = db.list_tokens()
    if not rows:
        click.echo("no tokens")
        return
    for t in rows:
        state = "revoked" if t["revoked_at"] else "active"
        click.echo(f"{t['name']}  role={t['role']}  {state}  created={t['created_at']}  "
                   f"expires={t['expires_at'] or '-'}  last_used={t['last_used_at'] or '-'}")

@token.command("revoke")
@click.argument("name")
@click.option("--tenant", "tenant_id", default=None, help="Tenant cell (default 'default').")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def token_revoke(name, tenant_id, config_path):
    """Revoke the token named NAME (takes effect on its next request)."""
    from .db import Database
    from .provisioning import control_path_for, revoke_cell_token
    cfg = Config.load(config_path)
    control_path = control_path_for(cfg)
    if tenant_id or control_path.exists():
        control = _control(cfg)
        tid = tenant_id or "default"
        if control.epoch_of(tid) is None:
            raise click.ClickException(f"no such tenant '{tid}'")
        cell = _cell_db_for(control, tid)
        try:
            revoke_cell_token(control, cell, name)
        except KeyError:
            raise click.ClickException(f"no token named '{name}'")
    else:
        db = Database(cfg.db_path_expanded())
        if db.revoke_token(name) is None:
            raise click.ClickException(f"no token named '{name}'")
        db.add_audit("-", "token_revoked", {"name": name})
    click.echo(f"revoked {name}")

def _mint_pair_code(control, tenant_id: str, minutes: int, secret: str | None = None) -> tuple[str, str]:
    """Mint a single-use, short-expiry pairing credential for TENANT.

    Writes the pairing row into the tenant's OWN cell db (single-use authority)
    and registers the routing hash in control.db (admin path) so the phone can
    reach the tenant with the credential alone. Returns (code, code_hash)."""
    from datetime import datetime, timedelta, timezone
    from .db import Database
    code = secret or f"hma_pair_{pysecrets.token_hex(24)}"
    code_hash = _hash_token(code)
    cell_db_path = str(Path(control.tenant_dir(tenant_id)) / "arbiter.sqlite3")
    db = Database(cell_db_path)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
    db.mint_pairing(code_hash, expires_at)
    control.add_route(code_hash, tenant_id)
    return code, code_hash


@main.group()
def tenant():
    """Manage tenants (admin-credentialed provisioning)."""


def _control(cfg):
    from .control import ControlPlane
    from .provisioning import control_path_for, tenants_root_for
    # 3-arg real class via its B1 factory: control_dir = control.db's parent,
    # tenants_root so create_tenant's under-root + §15.7 checks resolve correctly.
    return ControlPlane.open(control_path_for(cfg).parent, tenants_root_for(cfg))


@tenant.command("create")
@click.argument("tenant_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_create(tenant_id, config_path):
    """Provision a fresh isolated cell for TENANT_ID; print its first app + warden tokens."""
    from .provisioning import provision_tenant, tenants_root_for, TenantDirError
    cfg = Config.load(config_path)
    try:
        res = provision_tenant(_control(cfg), tenants_root_for(cfg), tenant_id)
    except TenantDirError as exc:
        raise click.ClickException(str(exc))
    except (FileExistsError, sqlite3.IntegrityError, ValueError) as exc:
        raise click.ClickException(f"cannot create tenant '{tenant_id}': {exc}")
    click.echo(f"tenant '{res.tenant_id}' created (epoch {res.epoch})")
    click.echo(f"  dir:          {res.dir}")
    click.echo(f"  app token:    {res.app_token}")
    click.echo(f"  warden token: {res.warden_token}")
    click.echo("Shown once — only sha256 hashes are stored.")


@tenant.command("list")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_list(config_path):
    """List tenants with epoch and disabled state."""
    from .provisioning import control_path_for
    cfg = Config.load(config_path)
    path = control_path_for(cfg)
    if not path.exists():
        click.echo("no tenants (single-tenant install — run `hma admin migrate`)")
        return
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            "SELECT tenant_id, epoch, disabled_at, dir FROM tenants ORDER BY tenant_id").fetchall()
    finally:
        conn.close()
    if not rows:
        click.echo("no tenants")
        return
    for tid, epoch, disabled_at, d in rows:
        state = "disabled" if disabled_at else "active"
        click.echo(f"{tid}  epoch={epoch}  {state}  dir={d}")


@tenant.command("disable")
@click.argument("tenant_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_disable(tenant_id, config_path):
    """Disable TENANT_ID; the server drops its live sessions on the next heartbeat."""
    cfg = Config.load(config_path)
    control = _control(cfg)
    # disable_tenant is a 0-row no-op UPDATE on an absent/typo'd tenant_id — check
    # existence first so a typo fails loudly instead of printing a false "disabled".
    if control.epoch_of(tenant_id) is None:
        raise click.ClickException(f"no such tenant '{tenant_id}'")
    control.disable_tenant(tenant_id)
    click.echo(f"disabled {tenant_id} (running streams close on next heartbeat; next HTTP 403s)")


@tenant.command("delete")
@click.argument("tenant_id")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_delete(tenant_id, config_path):
    """Tombstone TENANT_ID — its epoch and dir are never recycled."""
    cfg = Config.load(config_path)
    control = _control(cfg)
    # Same existence check as disable: tombstone_tenant is a 0-row no-op UPDATE
    # on an absent (or already-tombstoned) tenant_id.
    if control.epoch_of(tenant_id) is None:
        raise click.ClickException(f"no such tenant '{tenant_id}'")
    control.tombstone_tenant(tenant_id)
    click.echo(f"tombstoned {tenant_id} (epoch + dir permanently retired)")


@tenant.command("pair-code")
@click.argument("tenant_id")
@click.option("--minutes", type=int, default=15, help="Credential lifetime (default 15).")
@click.option("--host", "host_url", default=None, help="Server base URL for the QR payload.")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def tenant_pair_code(tenant_id, minutes, host_url, config_path):
    """Mint a single-use pairing credential for TENANT_ID and print its deep-link."""
    from .pair import build_pairing_payload, local_ip
    cfg = Config.load(config_path)
    control = _control(cfg)
    try:
        code, _ = _mint_pair_code(control, tenant_id, minutes)
    except (KeyError, ValueError) as exc:
        raise click.ClickException(f"cannot mint pairing code for '{tenant_id}': {exc}")
    base = host_url or f"http://{local_ip()}:{cfg.server.port}"
    click.echo(f"pairing code: {code}")
    click.echo(f"deep-link:    {build_pairing_payload(base, code)}")
    click.echo(f"Single-use, expires in {minutes} min. Shown once.")


@main.group()
def admin():
    """Fleet backup / restore / migrate (admin = local filesystem access)."""


@admin.command("backup")
@click.option("--out", "out_dir", required=True, help="Directory to write the snapshot into.")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def admin_backup(out_dir, config_path):
    """Online snapshot every cell (then control.db LAST) — fail-closed ordering."""
    from .provisioning import backup_fleet
    cfg = Config.load(config_path)
    backup_fleet(_control(cfg), Path(out_dir))
    click.echo(f"backup written to {out_dir}")
    click.echo("Restore is fail-closed: in-flight approvals are re-minted (see `hma admin restore`).")


@admin.command("restore")
@click.option("--backup-dir", required=True, help="Snapshot dir produced by `hma admin backup`.")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def admin_restore(backup_dir, config_path):
    """Restore a fleet snapshot (stop the server first). Fail-closed: in-flight
    approvals are re-minted and credential routes are reconciled."""
    from .provisioning import restore_fleet, control_path_for
    cfg = Config.load(config_path)
    restore_fleet(control_path_for(cfg), Path(backup_dir))
    click.echo("restore complete — in-flight approvals invalidated; agents must re-propose")


@admin.command("migrate")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def admin_migrate(config_path):
    """Wrap a single-tenant install as the 'default' cell (idempotent, §14)."""
    from .provisioning import migrate_to_multitenant, tenants_root_for
    cfg = Config.load(config_path)
    migrate_to_multitenant(cfg, _control(cfg), tenants_root_for(cfg))
    click.echo("migrated single-tenant DB to the 'default' cell "
               "(legacy app_token + existing devices → default)")


@main.group()
def audit():
    """Audit-log utilities."""


@audit.command("export")
@click.option("--format", "fmt", type=click.Choice(["jsonl"]), default="jsonl")
@click.option("--out", "out_path", default=None, help="Write to a file instead of stdout.")
@click.option("--url", "url_option", default=None,
              help="Server base URL (or HMA_URL env; default http://127.0.0.1:<port>).")
@click.option("--config", "config_path", default=None)
def audit_export(fmt, out_path, url_option, config_path):
    """Export the append-only audit log as JSONL (app token auth)."""
    cfg = Config.load(config_path)
    base = _base_url(url_option, cfg)
    try:
        with httpx.Client(base_url=base, timeout=30) as client:
            n = _audit_export(client, cfg.auth.app_token, fmt, out_path)
    except httpx.HTTPError as exc:
        raise click.ClickException(f"export failed against {base}: {exc}")
    if out_path:
        click.echo(f"wrote {n} audit events to {out_path}")

if __name__ == "__main__":
    main()

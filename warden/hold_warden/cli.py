"""hma-warden CLI: init | serve | doctor | hash."""
from __future__ import annotations

import logging
import os
import socket
import sys
import threading
from pathlib import Path
from secrets import token_hex

import click
import httpx
import uvicorn

from hold_warden.api import create_asgi_app
from hold_warden.arbiter import ArbiterClient
from hold_warden.canonical import canonicalize
from hold_warden.config import ConfigError, ParamValidationError, WardenConfig
from hold_warden.db import WardenDB
from hold_warden.secrets import SecretResolutionError, doctor_check, resolve
from hold_warden.service import Orchestrator
from hold_warden.verdict import VerdictVerifier

log = logging.getLogger("hold_warden.cli")

DEFAULT_CONFIG = Path.home() / ".config" / "hold-warden" / "warden.toml"


def _data_dir() -> Path:
    return Path(os.environ.get(
        "HOLD_WARDEN_DATA_DIR",
        str(Path.home() / ".local" / "share" / "hold-warden")))


def _load_config(config_path: Path) -> WardenConfig:
    try:
        return WardenConfig.load(config_path)
    except ConfigError as exc:
        raise click.ClickException(f"config error: {exc}")


@click.group()
def main() -> None:
    """hma-warden - the trusted component that executes approved actions."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")


_CONFIG_TEMPLATE = """\
# hold-warden configuration - see docs/warden.md
# Secrets appear here only as references (env: / file: / cmd:), never as values.

[warden]
arbiter_url = "{arbiter_url}"
# warden-role token minted on the arbiter host: hma token create <name> --role warden
arbiter_token = "env:HMA_WARDEN_TOKEN"
# Ed25519 verdict key pinned from GET /v1/keys at init. The warden only trusts
# verdicts signed by this key; re-run init (or edit) after a key rotation.
arbiter_pubkey = "{pinned_key}"
name = "{warden_name}"
bind = "127.0.0.1"
port = 8646
retention_days = 7

# Agent-facing bearer tokens, one per agent identity.
[agents.default]
token = "file:{token_path}"

# Starter action: harmless and end-to-end testable.
[actions.echo]
adapter = "command"
severity = "low"
ttl_seconds = 300
description = "Prove the approval loop end to end (echoes a marker)"
argv = ["echo", "warden-echo-ok"]

[secrets]
"""


@main.command()
@click.option("--arbiter-url", required=True, help="Base URL of the arbiter server")
@click.option("--config", "config_path", type=click.Path(path_type=Path),
              default=DEFAULT_CONFIG, show_default=True)
def init(arbiter_url: str, config_path: Path) -> None:
    """Pair with the arbiter and scaffold warden.toml (agent token prints ONCE)."""
    if config_path.exists():
        raise click.ClickException(
            f"{config_path} already exists - refusing to overwrite")
    base = arbiter_url.rstrip("/")
    try:
        resp = httpx.get(f"{base}/v1/keys", timeout=10.0)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
    except (httpx.HTTPError, ValueError) as exc:
        raise click.ClickException(f"could not fetch {base}/v1/keys: {exc}")
    if not keys:
        raise click.ClickException(
            "arbiter returned no verdict keys - is it holdmyagent 0.4.0+?")
    key = keys[0]
    pinned = f"{key['kid']}:{key['x']}"

    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    agent_token = token_hex(32)
    token_path = config_path.parent / "agent.default.token"
    token_path.write_text(agent_token + "\n")
    os.chmod(token_path, 0o600)

    config_path.write_text(_CONFIG_TEMPLATE.format(
        arbiter_url=base, pinned_key=pinned,
        warden_name=f"{socket.gethostname()}-warden",
        token_path=token_path))
    os.chmod(config_path, 0o600)

    click.echo(f"Wrote {config_path} (0600)")
    click.echo(f"Pinned arbiter verdict key: {pinned}")
    click.echo("")
    click.echo("Agent token for [agents.default] - shown ONCE, give it to your agent:")
    click.echo(f"  {agent_token}")
    click.echo("")
    click.echo("Next: export HMA_WARDEN_TOKEN=<token from `hma token create ... --role warden`>")
    click.echo("Then: hma-warden doctor && hma-warden serve")


@main.command("hash")
@click.argument("action")
@click.option("--config", "config_path", type=click.Path(path_type=Path),
              default=DEFAULT_CONFIG, show_default=True)
@click.option("--param", "param_kv", multiple=True,
              help="Action parameter as key=value (repeatable)")
def hash_cmd(action: str, config_path: Path, param_kv: tuple[str, ...]) -> None:
    """Print the canonical action document, then its sha256 action hash.

    This is exactly what a human's approval gets cryptographically bound to.
    """
    cfg = _load_config(config_path)
    spec = cfg.actions.get(action)
    if spec is None:
        known = ", ".join(sorted(cfg.actions)) or "none"
        raise click.ClickException(f"unknown action: {action} (known: {known})")
    params: dict[str, str] = {}
    for kv in param_kv:
        if "=" not in kv:
            raise click.ClickException(f"--param expects key=value, got: {kv}")
        key, value = kv.split("=", 1)
        params[key] = value
    try:
        spec.validate_params(params)
    except ParamValidationError as exc:
        raise click.ClickException(str(exc))
    resolved = spec.resolve_template(params)
    canonical, digest = canonicalize(action, spec.adapter, params, resolved,
                                     cfg.warden_name)
    click.echo(canonical)
    click.echo(digest)


@main.command()
@click.option("--config", "config_path", type=click.Path(path_type=Path),
              default=DEFAULT_CONFIG, show_default=True)
def doctor(config_path: Path) -> None:
    """Dry-run every secret resolver + check arbiter reachability and pinned key.

    Never prints resolved values - only `ok (non-empty)` / `FAILED (exit N)`.
    Exit code 0 when everything passes, 1 on any failure.
    """
    failures = 0
    try:
        cfg = WardenConfig.load(config_path)
        click.echo(f"config: ok ({config_path})")
    except ConfigError as exc:
        click.echo(f"config: FAILED ({exc})")
        sys.exit(1)

    refs: dict[str, str] = {"warden.arbiter_token": cfg.arbiter_token_ref}
    for name, ref in cfg.agents.items():
        refs[f"agents.{name}"] = ref
    for name, ref in cfg.secrets.items():
        refs[f"secrets.{name}"] = ref
    for label, ref in refs.items():
        res = doctor_check(ref)
        click.echo(f"{label} [{res.ref_scheme}]: "
                   f"{'ok (non-empty)' if res.ok else res.detail}")
        if not res.ok:
            failures += 1

    base = cfg.arbiter_url.rstrip("/")
    try:
        healthy = httpx.get(f"{base}/health", timeout=10.0).status_code == 200
    except httpx.HTTPError:
        healthy = False
    click.echo(f"arbiter /health: {'ok' if healthy else 'FAILED (unreachable or not 200)'}")
    if not healthy:
        failures += 1

    try:
        resp = httpx.get(f"{base}/v1/keys", timeout=10.0)
        keys = resp.json().get("keys", []) if resp.status_code == 200 else []
    except (httpx.HTTPError, ValueError):
        keys = []
    kid, _, x = cfg.arbiter_pubkey.partition(":")
    match = any(k.get("kid") == kid and k.get("x") == x for k in keys)
    click.echo(f"arbiter /v1/keys matches pinned key: "
               f"{'ok' if match else 'FAILED (key mismatch)'}")
    if not match:
        failures += 1

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

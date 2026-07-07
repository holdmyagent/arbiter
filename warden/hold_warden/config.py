"""Warden configuration: warden.toml -> WardenConfig.

Secrets appear in config only as references (env:/file:/cmd:/secret:) and are
never resolved here.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_ADAPTERS = ("command", "http", "secret")
_SEVERITIES = ("low", "medium", "high", "critical")
_PARAM_TYPES = ("enum", "string", "int")


class ConfigError(Exception):
    """warden.toml is missing, unparseable, or invalid. Message says how to fix it."""


@dataclass
class ParamSpec:
    type: str  # "enum" | "string" | "int"
    values: list[str] | None = None
    pattern: str | None = None
    max_len: int | None = None
    min: int | None = None
    max: int | None = None


@dataclass
class ActionSpec:
    name: str
    adapter: str
    severity: str
    ttl_seconds: int
    description: str
    argv: list[str] | None
    url: str | None
    method: str | None
    body_template: str | None
    headers: dict[str, str] | None
    secret: str | None
    params: dict[str, ParamSpec] = field(default_factory=dict)


@dataclass
class WardenConfig:
    arbiter_url: str
    arbiter_token_ref: str
    arbiter_pubkey: str  # pinned "kid:b64url"
    warden_name: str
    bind: str
    port: int
    retention_days: int
    agents: dict[str, str]  # agent name -> token secret ref
    actions: dict[str, ActionSpec]
    secrets: dict[str, str]  # secret name -> secret ref

    @classmethod
    def load(cls, path: Path) -> "WardenConfig":
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ConfigError(
                f"cannot read config {path}: {exc.strerror} — "
                f"run 'hma-warden init' to create one") from exc
        try:
            doc = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

        warden = doc.get("warden")
        if not isinstance(warden, dict):
            raise ConfigError(f"{path}: missing [warden] table")
        for key in ("arbiter_url", "arbiter_token", "arbiter_pubkey", "name"):
            if not warden.get(key):
                raise ConfigError(f"{path}: [warden] requires {key} = \"...\"")

        agents: dict[str, str] = {}
        for agent_name, tbl in doc.get("agents", {}).items():
            token = tbl.get("token") if isinstance(tbl, dict) else None
            if not token:
                raise ConfigError(
                    f"{path}: [agents.{agent_name}] requires token = \"<secret ref>\"")
            agents[agent_name] = token

        secrets = dict(doc.get("secrets", {}))
        actions: dict[str, ActionSpec] = {}
        for action_name, tbl in doc.get("actions", {}).items():
            actions[action_name] = _parse_action(path, action_name, tbl)

        return cls(
            arbiter_url=warden["arbiter_url"],
            arbiter_token_ref=warden["arbiter_token"],
            arbiter_pubkey=warden["arbiter_pubkey"],
            warden_name=warden["name"],
            bind=warden.get("bind", "127.0.0.1"),
            port=int(warden.get("port", 8646)),
            retention_days=int(warden.get("retention_days", 7)),
            agents=agents,
            actions=actions,
            secrets=secrets,
        )


def _parse_action(path: Path, name: str, tbl: object) -> ActionSpec:
    if not isinstance(tbl, dict):
        raise ConfigError(f"{path}: [actions.{name}] must be a table")
    adapter = tbl.get("adapter")
    if adapter not in _ADAPTERS:
        raise ConfigError(
            f"{path}: [actions.{name}] adapter must be one of: {', '.join(_ADAPTERS)}")
    severity = tbl.get("severity", "medium")
    if severity not in _SEVERITIES:
        raise ConfigError(
            f"{path}: [actions.{name}] severity must be one of: {', '.join(_SEVERITIES)}")
    params: dict[str, ParamSpec] = {}
    for pname, ptbl in tbl.get("params", {}).items():
        if not isinstance(ptbl, dict) or ptbl.get("type") not in _PARAM_TYPES:
            raise ConfigError(
                f"{path}: [actions.{name}.params.{pname}] type must be one of: "
                f"{', '.join(_PARAM_TYPES)}")
        params[pname] = ParamSpec(
            type=ptbl["type"], values=ptbl.get("values"), pattern=ptbl.get("pattern"),
            max_len=ptbl.get("max_len"), min=ptbl.get("min"), max=ptbl.get("max"))
    return ActionSpec(
        name=name, adapter=adapter, severity=severity,
        ttl_seconds=int(tbl.get("ttl_seconds", 300)),
        description=tbl.get("description", ""),
        argv=tbl.get("argv"), url=tbl.get("url"), method=tbl.get("method"),
        body_template=tbl.get("body_template"), headers=tbl.get("headers"),
        secret=tbl.get("secret"), params=params)

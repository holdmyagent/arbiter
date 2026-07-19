"""Warden configuration: warden.toml -> WardenConfig.

Params are constrained-only (enum / pattern+max_len / int ranges). Each
"{param}" placeholder must occupy an ENTIRE argv element (or a bounded segment
of url/body_template) — embedded interpolation like "--flag={x}" is rejected
at load time so params can never splice flags or shell syntax.
Secrets appear in config only as references (env:/file:/cmd:/secret:) and are
never resolved here.
"""
from __future__ import annotations

import base64
import hashlib
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

_ADAPTERS = ("command", "http", "secret")
_SEVERITIES = ("low", "medium", "high", "critical")
_PARAM_TYPES = ("enum", "string", "int")


class ConfigError(Exception):
    """warden.toml is missing, unparseable, or invalid. Message says how to fix it."""


class ParamValidationError(Exception):
    """Agent-supplied params failed validation against the action's ParamSpecs."""


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
    cwd: str | None = None
    env: dict[str, str] | None = None
    exec_timeout_s: int | None = None  # per-action adapter cap; None -> global EXEC_TIMEOUT_S (60s)
    params: dict[str, ParamSpec] = field(default_factory=dict)

    def validate_params(self, params: dict[str, str]) -> None:
        """Raise ParamValidationError unless params exactly match the declared specs."""
        unknown = sorted(set(params) - set(self.params))
        if unknown:
            raise ParamValidationError(
                f"unknown params for action {self.name}: {', '.join(unknown)}")
        missing = sorted(set(self.params) - set(params))
        if missing:
            raise ParamValidationError(
                f"missing params for action {self.name}: {', '.join(missing)}")
        for pname, spec in self.params.items():
            value = params[pname]
            if not isinstance(value, str):
                raise ParamValidationError(f"param {pname} must be a string")
            if spec.type == "enum":
                if value not in (spec.values or []):
                    raise ParamValidationError(
                        f"param {pname} must be one of: {', '.join(spec.values or [])}")
            elif spec.type == "string":
                if spec.max_len is not None and len(value) > spec.max_len:
                    raise ParamValidationError(
                        f"param {pname} is longer than max_len {spec.max_len}")
                if spec.pattern is not None and re.fullmatch(spec.pattern, value) is None:
                    raise ParamValidationError(
                        f"param {pname} does not match pattern {spec.pattern}")
            elif spec.type == "int":
                try:
                    number = int(value, 10)
                except ValueError:
                    raise ParamValidationError(f"param {pname} must be an integer") from None
                if spec.min is not None and number < spec.min:
                    raise ParamValidationError(f"param {pname} must be >= {spec.min}")
                if spec.max is not None and number > spec.max:
                    raise ParamValidationError(f"param {pname} must be <= {spec.max}")

    def resolve_template(self, params: dict[str, str]) -> dict:
        """Return the canonical `resolved` shape for this adapter.

        Secret VALUES never appear here: http headers contribute sorted NAMES
        only (values may be secret refs and stay references in self.headers);
        the secret adapter contributes the secret NAME only.
        Call validate_params() first — this method assumes params are valid.
        """
        if self.adapter == "command":
            argv = []
            for element in self.argv or []:
                match = _PLACEHOLDER_RE.fullmatch(element)
                argv.append(params[match.group(1)] if match else element)
            resolved: dict = {"argv": argv}
            if self.cwd is not None:
                resolved["cwd"] = _substitute(self.cwd, params)
            if self.env:
                resolved["env_names"] = sorted(self.env.keys())
            return resolved
        if self.adapter == "http":
            url = _substitute(self.url or "", params)
            header_names = sorted((self.headers or {}).keys())
            body_sha256 = None
            if self.body_template is not None:
                body = _substitute(self.body_template, params)
                body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
            return {"method": self.method, "url": url,
                    "header_names": header_names, "body_sha256": body_sha256}
        # load() guarantees adapter is command|http|secret
        return {"secret": (self.secret or "").removeprefix("secret:")}


def _substitute(template: str, params: dict[str, str]) -> str:
    return _PLACEHOLDER_RE.sub(lambda m: params[m.group(1)], template)


@dataclass
class WardenConfig:
    arbiter_url: str
    arbiter_token_ref: str
    arbiter_pubkey: str  # initial pinned "kid:b64url"
    arbiter_tenant: str  # paired tenant_id; the verifier's trust boundary
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
        for key in ("arbiter_url", "arbiter_token", "arbiter_pubkey", "arbiter_tenant", "name"):
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
            spec = _parse_action(path, action_name, tbl)
            _validate_action(path, spec, secrets)
            actions[action_name] = spec

        return cls(
            arbiter_url=warden["arbiter_url"],
            arbiter_token_ref=warden["arbiter_token"],
            arbiter_pubkey=warden["arbiter_pubkey"],
            arbiter_tenant=warden["arbiter_tenant"],
            warden_name=warden["name"],
            bind=warden.get("bind", "127.0.0.1"),
            port=int(warden.get("port", 8646)),
            retention_days=int(warden.get("retention_days", 7)),
            agents=agents,
            actions=actions,
            secrets=secrets,
        )

    def pinned(self) -> dict[str, bytes]:
        """The initial locally-pinned key set from arbiter_pubkey ('kid:b64url').

        kid itself may contain colons (kid = f"{tenant}:{hash8}"), so the
        split is on the LAST colon, not the first. Key bytes are validated
        eagerly as a shape-valid Ed25519 public key here - at config load /
        CLI startup - so a malformed pin is a loud ConfigError, never a bare
        ValueError deferred to the first verdict verification.
        """
        kid, sep, x = self.arbiter_pubkey.rpartition(":")
        if not sep or not kid or not x:
            raise ConfigError(
                f"invalid arbiter_pubkey (expected 'kid:b64url'): "
                f"{self.arbiter_pubkey!r}")
        try:
            raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
            Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise ConfigError(f"invalid arbiter_pubkey key bytes: {exc}") from exc
        return {kid: raw}


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
        secret=tbl.get("secret"), cwd=tbl.get("cwd"), env=tbl.get("env"),
        exec_timeout_s=(int(tbl["exec_timeout_s"])
                        if tbl.get("exec_timeout_s") is not None else None),
        params=params)


def _validate_action(path: Path, spec: ActionSpec, secrets: dict[str, str]) -> None:
    """Adapter shape + template rules, enforced at load so a bad registry never serves."""
    declared = set(spec.params)
    if spec.adapter == "command":
        if not spec.argv:
            raise ConfigError(f"{path}: [actions.{spec.name}] command adapter requires argv")
        for element in spec.argv:
            names = _PLACEHOLDER_RE.findall(element)
            if names and _PLACEHOLDER_RE.fullmatch(element) is None:
                raise ConfigError(
                    f"{path}: [actions.{spec.name}] argv element {element!r} embeds a param "
                    f"inside a larger string; each {{param}} must be an entire argv element "
                    f"(split \"--flag={{x}}\" into \"--flag\", \"{{x}}\")")
            for pname in names:
                if pname not in declared:
                    raise ConfigError(
                        f"{path}: [actions.{spec.name}] argv references undeclared param "
                        f"{{{pname}}} — declare [actions.{spec.name}.params.{pname}]")
        if spec.cwd is not None:
            if not spec.cwd.startswith("/"):
                raise ConfigError(
                    f"{path}: [actions.{spec.name}] cwd must be an absolute path")
            for pname in _PLACEHOLDER_RE.findall(spec.cwd):
                if pname not in declared:
                    raise ConfigError(
                        f"{path}: [actions.{spec.name}] cwd references undeclared param "
                        f"{{{pname}}} — declare [actions.{spec.name}.params.{pname}]")
                if spec.params[pname].type != "enum":
                    raise ConfigError(
                        f"{path}: [actions.{spec.name}] cwd param {{{pname}}} must be "
                        f"type \"enum\" (path-traversal guard) — free-form string/int "
                        f"params are not allowed in cwd")
    elif spec.adapter == "http":
        if not spec.url or not spec.method:
            raise ConfigError(
                f"{path}: [actions.{spec.name}] http adapter requires url and method")
        for source, text in (("url", spec.url), ("body_template", spec.body_template or "")):
            for pname in _PLACEHOLDER_RE.findall(text):
                if pname not in declared:
                    raise ConfigError(
                        f"{path}: [actions.{spec.name}] {source} references undeclared param "
                        f"{{{pname}}} — declare [actions.{spec.name}.params.{pname}]")
        for hname, hval in (spec.headers or {}).items():
            if hval.startswith("secret:") and hval.removeprefix("secret:") not in secrets:
                raise ConfigError(
                    f"{path}: [actions.{spec.name}] header {hname} references "
                    f"{hval!r} but [secrets] has no {hval.removeprefix('secret:')!r}")
    else:  # secret adapter
        if not spec.secret or not spec.secret.startswith("secret:"):
            raise ConfigError(
                f"{path}: [actions.{spec.name}] secret adapter requires "
                f"secret = \"secret:<name>\"")
        sname = spec.secret.removeprefix("secret:")
        if sname not in secrets:
            raise ConfigError(
                f"{path}: [actions.{spec.name}] references secret:{sname} but "
                f"[secrets] has no {sname!r}")
    for ename, evalue in (spec.env or {}).items():
        if evalue.startswith("secret:") and evalue.removeprefix("secret:") not in secrets:
            raise ConfigError(
                f"{path}: [actions.{spec.name}] env {ename} references "
                f"{evalue!r} but [secrets] has no {evalue.removeprefix('secret:')!r}")

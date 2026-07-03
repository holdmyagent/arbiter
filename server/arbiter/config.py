import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

def _b(v: str) -> bool:
    return v.strip().lower() in ("1", "true")

@dataclass
class ServerCfg:
    host: str = "127.0.0.1"
    port: int = 8000
    db_path: str = "~/.local/share/holdmyagent/arbiter.sqlite3"

@dataclass
class AuthCfg:
    agent_token: str = ""
    app_token: str = ""
    admin_password: str = ""
    session_secret: str = ""

@dataclass
class ApnsCfg:
    key_path: str = ""
    key_id: str = ""
    team_id: str = ""
    bundle_id: str = "com.holdmyagent.HoldMyAgent"
    sandbox: bool = False
    @property
    def configured(self) -> bool:
        return bool(self.key_path and self.key_id and self.team_id)

@dataclass
class NtfyCfg:
    url: str = "https://ntfy.sh"
    topic: str = ""
    token: str = ""
    @property
    def enabled(self) -> bool:
        return bool(self.topic)

@dataclass
class WebhookCfg:
    url: str = ""
    secret: str = ""
    @property
    def enabled(self) -> bool:
        return bool(self.url)

_DEFAULT_TOKENS = {"dev-agent-token", "dev-app-token"}

@dataclass
class Config:
    server: ServerCfg = field(default_factory=ServerCfg)
    auth: AuthCfg = field(default_factory=AuthCfg)
    apns: ApnsCfg = field(default_factory=ApnsCfg)
    ntfy: NtfyCfg = field(default_factory=NtfyCfg)
    webhook: WebhookCfg = field(default_factory=WebhookCfg)

    @staticmethod
    def default_path() -> str:
        return os.environ.get("HMA_CONFIG") or str(Path("~/.config/holdmyagent/config.toml").expanduser())

    @staticmethod
    def load(path: str | None = None) -> "Config":
        cfg = Config()
        p = Path(path or Config.default_path()).expanduser()
        if p.is_file():
            with open(p, "rb") as f:
                doc = tomllib.load(f)
            s = doc.get("server", {})
            a = doc.get("auth", {})
            n = doc.get("notify", {})
            for k in ("host", "port", "db_path"):
                if k in s:
                    setattr(cfg.server, k, s[k])
            for k in ("agent_token", "app_token", "admin_password", "session_secret"):
                if k in a:
                    setattr(cfg.auth, k, a[k])
            for k in ("key_path", "key_id", "team_id", "bundle_id", "sandbox"):
                if k in n.get("apns", {}):
                    setattr(cfg.apns, k, n["apns"][k])
            for k in ("url", "topic", "token"):
                if k in n.get("ntfy", {}):
                    setattr(cfg.ntfy, k, n["ntfy"][k])
            for k in ("url", "secret"):
                if k in n.get("webhook", {}):
                    setattr(cfg.webhook, k, n["webhook"][k])
        env = os.environ
        m = [("HMA_HOST", cfg.server, "host", str), ("HMA_PORT", cfg.server, "port", int),
             ("HMA_DB_PATH", cfg.server, "db_path", str),
             ("HMA_AGENT_TOKEN", cfg.auth, "agent_token", str), ("HMA_APP_TOKEN", cfg.auth, "app_token", str),
             ("HMA_ADMIN_PASSWORD", cfg.auth, "admin_password", str),
             ("HMA_SESSION_SECRET", cfg.auth, "session_secret", str),
             ("HMA_APNS_KEY_PATH", cfg.apns, "key_path", str), ("HMA_APNS_KEY_ID", cfg.apns, "key_id", str),
             ("HMA_APNS_TEAM_ID", cfg.apns, "team_id", str), ("HMA_APNS_BUNDLE_ID", cfg.apns, "bundle_id", str),
             ("HMA_APNS_SANDBOX", cfg.apns, "sandbox", _b),
             ("HMA_NTFY_URL", cfg.ntfy, "url", str), ("HMA_NTFY_TOPIC", cfg.ntfy, "topic", str),
             ("HMA_NTFY_TOKEN", cfg.ntfy, "token", str),
             ("HMA_WEBHOOK_URL", cfg.webhook, "url", str), ("HMA_WEBHOOK_SECRET", cfg.webhook, "secret", str)]
        for name, obj, attr, cast in m:
            if name in env:
                setattr(obj, attr, cast(env[name]))
        return cfg

    def validate_for_serve(self) -> list[str]:
        p: list[str] = []
        a = self.auth
        if not a.agent_token:
            p.append("auth.agent_token is empty — run `hma init`")
        if not a.app_token:
            p.append("auth.app_token is empty — run `hma init`")
        if not a.admin_password:
            p.append("auth.admin_password is empty — run `hma init`")
        if not a.session_secret:
            p.append("auth.session_secret is empty — run `hma init`")
        if a.agent_token in _DEFAULT_TOKENS or a.app_token in _DEFAULT_TOKENS:
            p.append("refusing to run with default dev tokens")
        if a.agent_token and a.agent_token == a.app_token:
            p.append("agent_token and app_token must differ")
        return p

    def db_path_expanded(self) -> str:
        path = Path(self.server.db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)

import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Config:
    agent_token: str
    app_token: str
    db_path: str
    apns_key_path: str | None
    apns_key_id: str | None
    apns_team_id: str | None
    apns_bundle_id: str
    apns_sandbox: bool

    @staticmethod
    def from_env() -> "Config":
        return Config(
            agent_token=os.environ.get("ARBITER_AGENT_TOKEN", "dev-agent-token"),
            app_token=os.environ.get("ARBITER_APP_TOKEN", "dev-app-token"),
            db_path=os.environ.get("ARBITER_DB_PATH", "arbiter.sqlite3"),
            apns_key_path=os.environ.get("APNS_KEY_PATH"),
            apns_key_id=os.environ.get("APNS_KEY_ID"),
            apns_team_id=os.environ.get("APNS_TEAM_ID"),
            apns_bundle_id=os.environ.get("APNS_BUNDLE_ID", "com.holdmyagent.HoldMyAgent"),
            apns_sandbox=os.environ.get("APNS_SANDBOX", "1") == "1",
        )

    @property
    def apns_configured(self) -> bool:
        return bool(self.apns_key_path and self.apns_key_id and self.apns_team_id)

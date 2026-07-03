import os
import sys

from .config import Config
from .db import Database
from .apns import APNsSender
from .app import create_app

# module-level init is the uvicorn entrypoint pattern; tests use create_app() directly
cfg = Config.from_env()

_DEFAULT_TOKENS = {"dev-agent-token", "dev-app-token"}
if (cfg.agent_token in _DEFAULT_TOKENS or cfg.app_token in _DEFAULT_TOKENS) and \
        os.environ.get("ARBITER_ALLOW_DEFAULT_TOKENS") != "1":
    sys.exit(
        "Refusing to start with default tokens; set ARBITER_AGENT_TOKEN and "
        "ARBITER_APP_TOKEN, or ARBITER_ALLOW_DEFAULT_TOKENS=1 for local dev"
    )

db = Database(cfg.db_path)
sender = APNsSender(cfg)
app = create_app(cfg, db, sender)

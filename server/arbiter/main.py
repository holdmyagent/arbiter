import sys
from .config import Config
from .db import Database
from .apns import APNsSender
from .app import create_app

cfg = Config.load()
problems = cfg.validate_for_serve()
if problems:
    sys.exit("Refusing to start:\n  - " + "\n  - ".join(problems))
db = Database(cfg.db_path_expanded())
sender = APNsSender(cfg)
app = create_app(cfg, db, sender)

import sys
from pathlib import Path
from .config import Config
from .apns import APNsSender
from .app import create_app
from .control import ControlPlane
from .registry import TenantRegistry

cfg = Config.load()
problems = cfg.validate_for_serve()
if problems:
    sys.exit("Refusing to start:\n  - " + "\n  - ".join(problems))

# Single-tenant back-compat boot (iOS 0.5.0): one control plane + one
# provisioned "default" cell rooted alongside the configured db_path, so an
# existing install's data keeps landing in the same place it always has.
db_path = Path(cfg.db_path_expanded())
tenants_root = db_path.parent / "cells"
control = ControlPlane.open(db_path.parent / "control", tenants_root)
default_dir = tenants_root / "default"
if control.epoch_of("default") is None:
    default_dir.mkdir(parents=True, exist_ok=True)
    control.create_tenant("default", str(default_dir.resolve()))

sender = APNsSender(cfg)
registry = TenantRegistry(control, cfg=cfg, sender=sender)
app = create_app(cfg, registry, control, sender=sender)

import sys
from .config import Config
from .apns import APNsSender
from .app import create_app
from .control import ControlPlane
from .provisioning import control_path_for, ensure_default_cell, tenants_root_for
from .registry import TenantRegistry
from .scheduler import ExpiryScheduler

cfg = Config.load()
problems = cfg.validate_for_serve()
if problems:
    sys.exit("Refusing to start:\n  - " + "\n  - ".join(problems))

# Single-tenant back-compat boot (iOS 0.5.0): one control plane + one
# provisioned "default" cell rooted alongside the configured db_path, so an
# existing install's data keeps landing in the same place it always has.
# control_path_for/tenants_root_for are the single source of truth for this
# layout — the tenant CLI resolves through the same helpers.
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

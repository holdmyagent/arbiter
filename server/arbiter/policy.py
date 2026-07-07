"""Create-time policy engine: deny lists, severity floors, token scopes.

Pure functions over config + identity + the incoming RequestCreate; the caller
(the create route) looks up token scopes and enforces the returned verdict.
"""
from dataclasses import dataclass

from .models import severity_rank


@dataclass
class PolicyResult:
    allowed: bool
    effective_severity: str
    reason: str | None


def evaluate_create(cfg, identity, req, scopes: dict | None = None) -> PolicyResult:
    """Evaluate a create against [policy] config and the token's scopes.

    - deny_action_types: hard deny, reason "denied by policy".
    - severity floors: effective severity = max(agent-claimed, floor) by rank
      low < medium < high < critical; the caller stores the effective value.
    - scopes (from the tokens table, None for legacy config tokens):
      "action_types" allowlist and "max_severity" cap; violations deny.
    """
    pol = cfg.policy
    if req.action_type in pol.deny_action_types:
        return PolicyResult(False, req.severity, "denied by policy")
    effective = req.severity
    floor = pol.severity_floors.get(req.action_type)
    if floor is not None and severity_rank(floor) > severity_rank(effective):
        effective = floor
    if scopes:
        allowed_types = scopes.get("action_types")
        if allowed_types is not None and req.action_type not in allowed_types:
            return PolicyResult(
                False, effective,
                f"action_type '{req.action_type}' not allowed for this token")
        cap = scopes.get("max_severity")
        if cap is not None and severity_rank(effective) > severity_rank(cap):
            return PolicyResult(
                False, effective,
                f"severity '{effective}' exceeds token max_severity '{cap}'")
    return PolicyResult(True, effective, None)

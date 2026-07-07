from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["pending", "approved", "denied", "expired"]

_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def severity_rank(s: str) -> int:
    """Return numeric rank for severity; unknown values default to 0 (fail-open to low)."""
    return _SEVERITY_RANK.get(s, 0)

class RequestCreate(BaseModel):
    title: str
    description: str = ""
    action_type: str = "generic"
    payload: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = "medium"
    ttl_seconds: int = 300
    target: str | None = None
    callback_url: str | None = None
    canonical_action: str | None = None
    action_hash: str | None = None

class ApprovalRequest(BaseModel):
    id: str
    created_at: str
    title: str
    description: str
    action_type: str
    payload: dict[str, Any]
    severity: Severity
    status: Status
    ttl_seconds: int
    expires_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    target: str | None = None
    callback_url: str | None = None
    action_hash: str | None = None
    requested_by: str | None = None

class Decision(BaseModel):
    decision: Literal["approve", "deny"]

class DeviceRegister(BaseModel):
    apns_token: str
    name: str = "iPhone"
    min_severity: Severity = "low"
    notifications_enabled: bool = True
    sound: bool = True
    severities: dict[str, bool] | None = None
    badge: bool = False

from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator

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
    idempotency_key: str | None = Field(default=None, max_length=128)

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
    consumed_at: str | None = None
    exec_exit_code: int | None = None
    exec_ran: str | None = None
    exec_output: str | None = None
    exec_kind: str | None = None
    decided_via: str | None = None
    attestation: str | None = None
    attest_key_id: str | None = None

class Decision(BaseModel):
    decision: Literal["approve", "deny"]
    # Optional and deliberately UNVALIDATED (Any, not a nested model): a
    # malformed attestation object must never 422 and block an otherwise-valid
    # decision -- attestation is RECORDED, never REQUIRED (§F.1). Expected
    # shape is {"key_id": str, "signature": str (base64), "signed_at": str
    # (ISO8601)}; any other shape is classified 'attestation_failed' by
    # app._classify_attestation, never rejected at the wire.
    attestation: Any = None

class ExecResult(BaseModel):
    mode: Literal["exec_result"]                              # REQUIRED discriminator
    exit_code: int | None = None
    ran: str | None = Field(default=None, max_length=4096)
    output: str | None = Field(default=None, max_length=32768)
    kind: Literal["command", "http"] | None = None

    @field_validator("output")
    @classmethod
    def _output_bytes_bounded(cls, v: str | None) -> str | None:
        # max_length above counts CHARACTERS, not bytes -- a multi-byte string
        # (e.g. "😀" * 32768) passes that check while landing on disk at 4x
        # the intended ~32 KB cap. This is now bounded by the write-once rule
        # (one report per request, ever), so it is not a growth vector -- but
        # the stated intent was a 32 KB cap, so enforce bytes too.
        if v is not None and len(v.encode("utf-8")) > 32768:
            raise ValueError("output exceeds 32768 bytes")
        return v

class DeviceRegister(BaseModel):
    apns_token: str
    name: str = "iPhone"
    min_severity: Severity = "low"
    notifications_enabled: bool = True
    sound: bool = True
    severities: dict[str, bool] | None = None
    badge: bool = False

class DeviceKeyEnroll(BaseModel):
    device_id: str
    public_key: str                              # base64 X9.63 uncompressed EC point
    alg: Literal["P-256"] = "P-256"

class PresetBody(BaseModel):
    name: str
    block_patterns: list[str] = Field(default_factory=list)
    allow_patterns: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    default_decision: Literal["ask", "allow"] = "ask"

class ActiveBody(BaseModel):
    preset: str

class OverlayBody(BaseModel):
    always_ask: list[str] = Field(default_factory=list)
    always_allow: list[str] = Field(default_factory=list)

class GateStatusReport(BaseModel):
    version: int
    etag: str
    fetched_at: str
    most_restrictive: bool

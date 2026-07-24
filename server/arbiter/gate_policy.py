"""Server-mediated gate policy: the RESOLVER + the MATCHER (pure).

Two responsibilities, no I/O:
  * resolve_policy(...) folds the active preset + personal overlay + a hardcoded
    LOCAL FLOOR into the single resolved-policy dict the gate consumes. A tenant
    with no policy resolves to MOST_RESTRICTIVE (never empty) — fail-closed.
  * evaluate(resolved, tool_name, command) applies fail-safe precedence:
    categorical-ask first & non-overridable; ask wins ties; split advisory vs
    override allow. This is the SAME code GET /v1/policy/test runs, so the macOS
    preview cannot lie (conformance seam).

The server may only ADD asks/blocks: effective policy = local floor UNION server
policy. No override/advisory allow can suppress a categorical-ask tool.
"""
import hashlib

POLICY_SCHEMA_VERSION = 1

# Hardcoded non-overridable ask tools. execute_code/delegate_task per the design;
# the outward-effecting Hermes tools are enumerated so a server push can never
# make them looser. Extend here (with a test) when a new outward tool is added.
LOCAL_FLOOR_CATEGORICAL = (
    "execute_code",
    "delegate_task",
    "send_message",       # iMessage/Discord replies
    "dispatch",           # coder-bridge MCP dispatch
    "write_file",
    "edit_file",
    "run_git",            # push/commit/etc.
)

# Seed catalog. Operator owns their copies; NOT auto-activated (a fresh tenant
# resolves to MOST_RESTRICTIVE). default_decision "allow" means "only listed
# block patterns ask"; "ask" means "unmatched gateable command asks".
SEED_PRESETS = {
    "dangerous-shell": {
        "block_patterns": ["rm -rf", "git push", "curl", "kubectl", "ssh"],
        "allow_patterns": [],
        "tool_allowlist": ["run_shell"],
        "default_decision": "allow",
    },
    "everything": {
        "block_patterns": [],
        "allow_patterns": [],
        "tool_allowlist": [],
        "default_decision": "ask",
    },
    "shell-and-messages": {
        "block_patterns": ["rm -rf", "git push"],
        "allow_patterns": [],
        "tool_allowlist": ["run_shell"],
        "default_decision": "allow",
    },
    "audit-only": {
        "block_patterns": [],
        "allow_patterns": [],
        "tool_allowlist": ["run_shell"],
        "default_decision": "allow",
    },
}


def _etag(epoch: int, version: int) -> str:
    return hashlib.sha256(f"{epoch}:{version}".encode()).hexdigest()[:16]


def _base(meta: dict) -> dict:
    epoch, version = int(meta["epoch"]), int(meta["version"])
    return {
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "version": version,
        "epoch": epoch,
        "etag": _etag(epoch, version),
        "match_mode": "substring",
    }


def _most_restrictive_body() -> dict:
    """Fresh most-restrictive body, rebuilt from the PRIMITIVE constants on
    every call (mirrors the preset path's `list(...)` style). No caller may
    ever be handed a reference into a shared mutable template: each call
    returns brand-new list objects, so in-place mutation of one caller's copy
    (including the public MOST_RESTRICTIVE snapshot below) can never corrupt
    what a later resolve_policy(None, ...) call returns."""
    return {
        "default_decision": "ask",
        "categorical_ask": list(LOCAL_FLOOR_CATEGORICAL),
        "tool_allowlist": [],
        "ask_patterns": [],
        "advisory_allow_patterns": [],
        "override_allow_patterns": [],
        "active_preset": None,
    }


# Public symbol per the Produces contract (Task 3 / endpoints import this
# name). This is an INDEPENDENT snapshot, not an alias of the object graph
# resolve_policy rebuilds from below — mutating it in place cannot affect
# the resolver's fail-closed default.
MOST_RESTRICTIVE = _most_restrictive_body()


def resolve_policy(active_preset: dict | None, overlay: dict, meta: dict) -> dict:
    """Fold active preset + overlay + local floor into the resolved wire doc.
    active_preset None -> MOST_RESTRICTIVE. The categorical_ask list is ALWAYS
    the local floor UNION any preset/overlay-declared categorical tools (the
    floor can only grow, never shrink).
    Partial/invalid input (missing keys, wrong types) raises (KeyError/TypeError)
    by design — callers MUST treat a resolver exception as ask/deny, never
    swallow it into allow."""
    doc = _base(meta)
    if active_preset is None:
        # Rebuilt fresh from primitives each call (not deepcopied from any
        # shared module-level object) — a caller mutating the returned doc,
        # or mutating the public MOST_RESTRICTIVE snapshot, can never corrupt
        # the fail-closed default for future calls.
        doc.update(_most_restrictive_body())
        return doc

    # "everything" is detected by SHAPE (ask + no allowlist), matching the
    # design's literal definition. This is intentional, not a proxy for a
    # name check — the local floor (categorical_ask) holds regardless of how
    # this posture is detected or misdetected.
    everything = active_preset["default_decision"] == "ask" and not active_preset["tool_allowlist"]
    always_ask = list(overlay.get("always_ask", []))
    always_allow = list(overlay.get("always_allow", []))

    # ask_patterns = preset blocks UNION overlay always_ask (both are "ask").
    ask_patterns = list(active_preset["block_patterns"]) + always_ask
    # H3: under everything / most-restrictive posture, overlay always_allow holes
    # are ignored so they cannot punch through "ask on everything".
    override_allow = [] if everything else always_allow

    categorical = list(LOCAL_FLOOR_CATEGORICAL)   # floor; only grows

    doc.update({
        "default_decision": active_preset["default_decision"],
        "categorical_ask": categorical,
        "tool_allowlist": list(active_preset["tool_allowlist"]),
        "ask_patterns": ask_patterns,
        "advisory_allow_patterns": list(active_preset["allow_patterns"]),
        "override_allow_patterns": override_allow,
        "active_preset": active_preset["name"],
    })
    return doc


def _matches(pattern: str, command: str) -> bool:
    """Advisory substring match (documented as advisory, NOT a security boundary
    — evadable by quoting/whitespace; the default_decision backstop means an
    evaded block lands in ASK, never allow). Empty pattern never matches."""
    return bool(pattern) and pattern in command


def evaluate(resolved: dict, tool_name: str, command: str = "") -> str:
    """Fail-safe precedence -> "ask" | "allow":
      1. categorical_ask contains tool_name        -> ask   (non-overridable)
      2. tool_name not affirmatively safe          -> ask   (H3: a tool the
                                                       active preset never
                                                       vetted always asks --
                                                       never follows a
                                                       permissive default_decision
                                                       set for OTHER, known tools)
      3. any ask_pattern matches command           -> ask   (ask wins ties;
                                                       override_allow cannot beat)
      4. any override_allow_pattern matches command-> allow (escape hatch;
                                                       write-time constrained)
      5. any advisory_allow_pattern matches command-> allow
      6. else                                        -> default_decision
    """
    if tool_name in resolved["categorical_ask"]:
        return "ask"
    if tool_name not in resolved["tool_allowlist"]:
        # Unknown / non-affirmatively-safe tool: never affirmatively vetted by
        # the active preset, so it asks unconditionally -- this must NOT be
        # allowed to inherit an "allow" default_decision that only applies to
        # tools the preset DID vet.
        return "ask"
    if any(_matches(p, command) for p in resolved["ask_patterns"]):
        return "ask"
    if any(_matches(p, command) for p in resolved["override_allow_patterns"]):
        return "allow"
    if any(_matches(p, command) for p in resolved["advisory_allow_patterns"]):
        return "allow"
    return resolved["default_decision"]


import re

_NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_MAX_PATTERNS = 200
_MAX_PATTERN_LEN = 512


class PolicyValidationError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _check_patterns(patterns, label):
    if len(patterns) > _MAX_PATTERNS:
        raise PolicyValidationError(f"{label}: too many patterns (max {_MAX_PATTERNS})")
    for p in patterns:
        if not isinstance(p, str) or p == "":
            raise PolicyValidationError(f"{label}: empty pattern not allowed")
        if len(p) > _MAX_PATTERN_LEN:
            raise PolicyValidationError(f"{label}: pattern too long (max {_MAX_PATTERN_LEN})")


def validate_preset(name, block_patterns, allow_patterns, tool_allowlist,
                    default_decision) -> None:
    if not _NAME_RE.match(name or ""):
        raise PolicyValidationError("preset name must match [a-z0-9-]{1,64}")
    if default_decision not in ("ask", "allow"):
        raise PolicyValidationError("default_decision must be 'ask' or 'allow'")
    _check_patterns(block_patterns, "block_patterns")
    _check_patterns(allow_patterns, "allow_patterns")
    if len(tool_allowlist) > _MAX_PATTERNS:
        raise PolicyValidationError("tool_allowlist too long")
    # H9: a preset that gates NOTHING beyond the categorical floor is fail-open.
    # default_decision "allow" with no block patterns gates nothing -> reject.
    if default_decision == "allow" and not block_patterns:
        raise PolicyValidationError(
            "this policy gates NOTHING beyond categorical-ask: add block patterns "
            "or set default_decision to 'ask'")


def validate_overlay(always_ask, always_allow) -> None:
    _check_patterns(always_ask, "always_ask")
    _check_patterns(always_allow, "always_allow")
    for p in always_allow:
        # minimum specificity: no bare dangerous verb (rm/curl/ssh/kubectl).
        if len(p) < 8 or " " not in p:
            raise PolicyValidationError(
                f"always_allow entry '{p}' is too broad: must be >=8 chars and "
                "specific (contain a space) to prevent a fail-open override")

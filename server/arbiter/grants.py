"""Scoped grants: (agent, tool) auto-approval with a TTL.

Pure rules only. Every SQL statement for the `grants` table lives in db.py and
every route/audit/event decision lives in app.py, so this module imports
nothing from the package and can be unit-tested with no database, no app and
no bearer token. That matters because these are the rules that decide when a
human is NOT asked, and they should be readable in one screen.

Everything here only ever NARROWS the operator's effort, never the system's
safety: exact string equality on both keys, no wildcards, no case folding, no
cross-agent match, a server-side TTL ceiling, and `critical` never eligible.
"""

GRANT_TTL_MAX_SECONDS = 28800      # 8 h — the server-side ceiling on any grant
GRANT_RECENT_SECONDS = 86400       # 24 h — how long an inert grant stays listed

# Severities a grant can never answer for, whatever grants exist. A separate
# frozenset rather than an inline `== "critical"` so the floor is one grep away.
NEVER_AUTO_APPROVE = frozenset({"critical"})


def grant_keys(payload) -> tuple[str, str] | None:
    """The (agent, tool) pair a request payload carries, or None.

    Both keys must be present, `str`, and non-empty. A payload that is not a
    dict, or is missing either key, is simply not grant-eligible — never an
    error: the gate forwards whatever it can, and a request the gate could not
    describe structurally must degrade to "ask a human", not to a 500.
    """
    if not isinstance(payload, dict):
        return None
    agent, tool = payload.get("agent"), payload.get("tool")
    if not isinstance(agent, str) or not agent:
        return None
    if not isinstance(tool, str) or not tool:
        return None
    return agent, tool


def auto_approve_eligible(severity: str, payload) -> tuple[str, str] | None:
    """The (agent, tool) pair to look a grant up by, or None if this request
    may not be auto-approved at all.

    SEVERITY is the EFFECTIVE severity already stored on the row by
    evaluate_create — not the one the caller asked for — so a severity floor
    that promoted a request to `critical` also removes it from grant cover.
    """
    if severity in NEVER_AUTO_APPROVE:
        return None
    return grant_keys(payload)


def grant_state(row, now: str) -> str:
    """'revoked' | 'expired' | 'active' for a grant row at NOW (ISO-8601 UTC).

    Revocation wins over expiry: a grant the operator revoked reads 'revoked'
    even once its TTL would have run out anyway, because that is what
    happened. Timestamps compare as strings — every one is written by
    db._iso(), so they are fixed-shape UTC and sort chronologically.
    """
    if row["revoked_at"] is not None:
        return "revoked"
    if row["expires_at"] <= now:
        return "expired"
    return "active"

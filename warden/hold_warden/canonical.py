"""Canonical action documents — the exact bytes a human approval is bound to.

Only the warden canonicalizes; the arbiter treats the canonical document as
opaque bytes and re-hashes them server-side. Any byte difference here breaks
the trust chain, so this module is golden-vectored (tests/vectors/*.json).
"""
from __future__ import annotations

import hashlib
import json


def canonicalize(action: str, adapter: str, params: dict[str, str],
                 resolved: dict, warden: str) -> tuple[str, str]:
    """Return (canonical_str, action_hash).

    canonical_str is json.dumps of {"action", "adapter", "params", "resolved",
    "v": 1, "warden"} with sort_keys=True, separators=(",", ":"),
    ensure_ascii=False. action_hash is sha256 of the UTF-8 bytes, hexdigest.
    `params` is ALWAYS present in the document, even when {}.
    """
    doc = {
        "action": action,
        "adapter": adapter,
        "params": params,
        "resolved": resolved,
        "v": 1,
        "warden": warden,
    }
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    action_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return canonical, action_hash

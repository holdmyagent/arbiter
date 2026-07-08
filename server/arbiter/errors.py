"""Client-visible error hygiene for the multi-tenant arbiter (§11).

The process serves every tenant, so a client-visible error body and the wall-
clock time to produce it are both cross-tenant side channels. All resolution
failures — a token that routes to no tenant, a token that routes but is invalid
in its cell, a disabled tenant — return the SAME constant body with the SAME
timing floor, so a caller cannot tell which case it hit (route-existence /
tenant-existence oracle) or read any tenant PII out of the error.

/metrics forward-constraint: /metrics is intentionally NOT exposed. If added it
MUST be authenticated and expose only fleet-aggregate counters (or enforce
per-tenant authz on label reads) — per-tenant rids/queue-depth/429/hot-gauge
labels on a public scrape are a live cross-tenant topology map.
"""
import asyncio
import time

from fastapi import HTTPException

GENERIC_403_DETAIL = "forbidden"


def generic_403() -> HTTPException:
    """The one and only client-visible auth/resolution failure — a constant,
    PII-free 403 used identically for route-miss, in-cell-invalid, and disabled."""
    return HTTPException(status_code=403, detail=GENERIC_403_DETAIL)


class EqualizedFloor:
    """Pad an operation up to a fixed floor so success and every failure mode
    take indistinguishable wall-clock time. Clock and sleep are injectable for
    deterministic tests."""

    def __init__(self, floor_s: float, clock=time.monotonic, sleep=asyncio.sleep):
        self.floor_s, self.clock, self.sleep = floor_s, clock, sleep

    async def wait(self, started_at: float) -> None:
        remaining = self.floor_s - (self.clock() - started_at)
        if remaining > 0:
            await self.sleep(remaining)

"""Tests for send_with_retry — bounded APNs retry helper."""

import pytest

from arbiter.apns import send_with_retry


class CountingSender:
    """Fake sender that fails the first *fail_count* calls, then returns *ok_result*."""

    def __init__(self, fail_count: int = 0,
                 fail_result: str = "error:503:Service Unavailable",
                 ok_result: str = "sent"):
        self.calls = 0
        self.fail_count = fail_count
        self.fail_result = fail_result
        self.ok_result = ok_result

    async def send(self, token: str, payload: dict) -> str:
        self.calls += 1
        if self.calls <= self.fail_count:
            return self.fail_result
        return self.ok_result


class RaisingSender:
    """Fake sender that raises an exception on the first *raise_count* calls."""

    def __init__(self, raise_count: int = 1, ok_result: str = "sent"):
        self.calls = 0
        self.raise_count = raise_count
        self.ok_result = ok_result

    async def send(self, token: str, payload: dict) -> str:
        self.calls += 1
        if self.calls <= self.raise_count:
            raise TimeoutError("simulated network timeout")
        return self.ok_result


# ── transient (5xx) retries ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_transient_5xx_retried_until_success():
    """Fail twice with 503, succeed on attempt 3 → final result 'sent', 3 calls."""
    sender = CountingSender(fail_count=2, fail_result="error:503:Service Unavailable")
    result = await send_with_retry(sender, "tok", {"request_id": "r1"}, backoff_base=0.001)
    assert result == "sent"
    assert sender.calls == 3


@pytest.mark.asyncio
async def test_immediate_success_no_retry():
    """No failure → only 1 call."""
    sender = CountingSender(fail_count=0)
    result = await send_with_retry(sender, "tok", {}, backoff_base=0.001)
    assert result == "sent"
    assert sender.calls == 1


@pytest.mark.asyncio
async def test_all_retries_exhausted_returns_last_error():
    """Fail every time (5xx): after max_retries+1 attempts return the error string."""
    sender = CountingSender(fail_count=99, fail_result="error:503:Service Unavailable")
    result = await send_with_retry(sender, "tok", {}, max_retries=2, backoff_base=0.001)
    assert result.startswith("error:503")
    assert sender.calls == 3  # 1 original + 2 retries


@pytest.mark.asyncio
async def test_exception_transient_retried():
    """Raised exceptions count as transient — should retry up to max_retries."""
    sender = RaisingSender(raise_count=1, ok_result="sent")
    result = await send_with_retry(sender, "tok", {}, backoff_base=0.001)
    assert result == "sent"
    assert sender.calls == 2


@pytest.mark.asyncio
async def test_429_too_many_requests_retried():
    """429 is a back-off-and-retry signal — transient, should retry then succeed."""
    sender = CountingSender(fail_count=2, fail_result="error:429:Too Many Requests")
    result = await send_with_retry(sender, "tok", {}, backoff_base=0.001)
    assert result == "sent"
    assert sender.calls == 3


# ── hard failures NOT retried ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_410_unregistered_not_retried():
    """410 Unregistered is a hard failure — exactly 1 call, no retry."""
    sender = CountingSender(fail_count=99, fail_result="error:410:Unregistered")
    result = await send_with_retry(sender, "tok", {"request_id": "r2"}, backoff_base=0.001)
    assert result == "error:410:Unregistered"
    assert sender.calls == 1


@pytest.mark.asyncio
async def test_400_bad_request_not_retried():
    """4xx client errors are hard failures — not retried."""
    sender = CountingSender(fail_count=99, fail_result="error:400:Bad Request")
    result = await send_with_retry(sender, "tok", {}, backoff_base=0.001)
    assert result == "error:400:Bad Request"
    assert sender.calls == 1


@pytest.mark.asyncio
async def test_skipped_not_retried():
    """'skipped' (APNs not configured) is not an error — returned immediately."""
    sender = CountingSender(fail_count=0, ok_result="skipped")
    result = await send_with_retry(sender, "tok", {}, backoff_base=0.001)
    assert result == "skipped"
    assert sender.calls == 1

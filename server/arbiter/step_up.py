"""Stdlib RFC-6238 TOTP verify for policy:write step-up. No new dependency.

The macOS app performs the local biometric/passkey unlock and submits a 6-digit
TOTP (shared secret provisioned in [auth].step_up_totp_secret) with each
policy:write. The server verifies it here — a device that lost the operator's
approval cannot author policy even with a valid app token."""
import base64
import hashlib
import hmac
import struct
import time as _time


def _code_at(key: bytes, counter: int) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    val = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{val:06d}"


def verify_totp(secret_b32: str, code: str, now: float | None = None,
                *, step: int = 30, window: int = 1) -> bool:
    if not secret_b32 or not code:
        return False
    try:
        key = base64.b32decode(secret_b32, casefold=True)
    except Exception:
        return False
    now = _time.time() if now is None else now
    counter = int(now // step)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_code_at(key, counter + delta), code):
            return True
    return False

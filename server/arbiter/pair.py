"""Pairing payload builder and LAN-IP helper for Hold My Agent.

`hma pair` (see arbiter.cli) is the supported CLI for printing the pairing
QR code; the functions below are the library pieces it's built on.
"""
import socket
from urllib.parse import urlencode


def build_pairing_payload(base_url: str, token: str) -> str:
    """Return the deep-link used to pair the iOS app with this server.

    Format: holdmyagent://pair?host=<url-encoded base_url>&token=<url-encoded token>
    """
    params = urlencode({"host": base_url, "token": token})
    return f"holdmyagent://pair?{params}"


def local_ip() -> str:
    """Best-effort LAN IP address.  Opens a UDP socket toward 8.8.8.8 to
    discover the kernel's preferred source address; no packets are actually sent.
    Falls back to "127.0.0.1" on any error."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip: str = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

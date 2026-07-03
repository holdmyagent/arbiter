"""
Pairing payload builder, LAN-IP helper, and CLI for Hold My Agent.

Usage:
    python -m arbiter.pair [--host HOST] [--token TOKEN]

Prints the pairing QR as Unicode blocks, the resolved server URL, the app
token, and the `holdmyagent://pair?...` payload.  Token is read from
--token flag or the ARBITER_APP_TOKEN environment variable.
"""
import argparse
import os
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


if __name__ == "__main__":
    import segno  # only needed at CLI runtime, not at import time

    parser = argparse.ArgumentParser(
        description="Print the Hold My Agent pairing QR code to the terminal."
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Server base URL (default: http://<LAN-IP>:8000)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="App token (default: $ARBITER_APP_TOKEN)",
    )
    args = parser.parse_args()

    host = args.host or f"http://{local_ip()}:8000"
    token = args.token or os.environ.get("ARBITER_APP_TOKEN", "")
    if not token:
        parser.error("Provide --token or set ARBITER_APP_TOKEN")

    payload = build_pairing_payload(host, token)

    print(segno.make(payload).terminal(compact=True))
    print()
    print(f"URL:     {host}")
    print(f"Token:   {token}")
    print(f"Payload: {payload}")
    print()
    print("Tip: run this command on the same machine as the server so the")
    print("     terminal already has network access — the QR only works on")
    print("     a trusted LAN.")

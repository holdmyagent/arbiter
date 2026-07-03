"""Tests for arbiter.pair — pairing payload builder."""
from urllib.parse import urlparse, parse_qs

import pytest


def test_payload_starts_with_scheme():
    from arbiter.pair import build_pairing_payload
    p = build_pairing_payload("http://192.168.1.1:8000", "mytoken")
    assert p.startswith("holdmyagent://pair?")


def test_payload_contains_host_and_token_keys():
    from arbiter.pair import build_pairing_payload
    p = build_pairing_payload("http://192.168.1.1:8000", "abc")
    parsed = urlparse(p)
    qs = parse_qs(parsed.query)
    assert "host" in qs
    assert "token" in qs


def test_payload_roundtrip_plain():
    """Exact host + token survive url-encode/decode."""
    from arbiter.pair import build_pairing_payload
    host = "http://10.0.0.5:8080"
    token = "abc123def"
    p = build_pairing_payload(host, token)
    parsed = urlparse(p)
    qs = parse_qs(parsed.query)
    assert qs["host"][0] == host
    assert qs["token"][0] == token


def test_payload_url_encodes_special_chars():
    """Special characters in host and token are correctly encoded and round-trip."""
    from arbiter.pair import build_pairing_payload
    host = "http://192.168.1.1:8000"
    token = "tok+en=val&x"
    p = build_pairing_payload(host, token)
    parsed = urlparse(p)
    qs = parse_qs(parsed.query)
    assert qs["host"][0] == host
    assert qs["token"][0] == token


def test_qr_buildable_from_payload():
    """segno.make() can build a QR code from the payload without error."""
    import segno
    from arbiter.pair import build_pairing_payload
    p = build_pairing_payload("http://example.com:8000", "testtoken")
    qr = segno.make(p)
    assert qr is not None


def test_local_ip_returns_nonempty_string():
    from arbiter.pair import local_ip
    ip = local_ip()
    assert isinstance(ip, str)
    assert len(ip) > 0


def test_local_ip_fallback_format():
    """local_ip returns a dotted string (not raising on network absence)."""
    from arbiter.pair import local_ip
    ip = local_ip()
    assert "." in ip  # x.x.x.x dotted-decimal

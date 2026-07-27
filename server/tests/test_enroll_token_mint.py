"""iOS 0.6 A1 — per-device token minted at enrolment. Unit half: sanitise + mint."""
import re

from arbiter.enroll import _sanitise_token_name

TOKEN_RE = re.compile(r"hma_app_[0-9a-f]{48}")


def test_sanitise_basic():
    assert _sanitise_token_name("Kevin's iPhone 17") == "kevin-s-iphone-17"

def test_sanitise_collapses_runs_and_trims():
    assert _sanitise_token_name("  --Wild  ***  Name--  ") == "wild-name"

def test_sanitise_caps_at_64():
    assert len(_sanitise_token_name("x" * 200)) <= 64

def test_sanitise_empty_falls_back():
    assert _sanitise_token_name("!!!") == "device"

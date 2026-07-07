"""Golden-vector tests for canonicalize(). The vectors pin the exact bytes the
arbiter stores and the human approval is bound to — never regenerate them to
make a failing test pass; a mismatch means canonicalize() broke."""
import json
from pathlib import Path

import pytest

from hold_warden.canonical import canonicalize

VECTOR_DIR = Path(__file__).parent / "vectors"
VECTOR_FILES = sorted(VECTOR_DIR.glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run(inp: dict) -> tuple[str, str]:
    return canonicalize(inp["action"], inp["adapter"], inp["params"],
                        inp["resolved"], inp["warden"])


def test_vector_set_is_complete() -> None:
    assert {p.stem for p in VECTOR_FILES} >= {
        "command_simple", "command_unicode", "http_post", "http_nested",
        "secret_release", "empty_params", "param_order"}


@pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda p: p.stem)
def test_golden_vector(path: Path) -> None:
    vec = _load(path)
    canonical, action_hash = _run(vec["input"])
    assert canonical == vec["canonical"]
    assert action_hash == vec["hash"]
    assert len(action_hash) == 64


def test_empty_params_never_key_dropped() -> None:
    vec = _load(VECTOR_DIR / "empty_params.json")
    canonical, _ = _run(vec["input"])
    assert '"params":{}' in canonical


def test_param_ordering_invariance() -> None:
    vec = _load(VECTOR_DIR / "param_order.json")
    # json.loads preserves the file's key order in dicts, so the two inputs
    # really do carry different insertion orders into canonicalize().
    assert list(vec["input"]["params"]) != list(vec["input_reordered"]["params"])
    assert _run(vec["input"]) == _run(vec["input_reordered"]) == (vec["canonical"], vec["hash"])


def test_unicode_is_not_ascii_escaped() -> None:
    vec = _load(VECTOR_DIR / "command_unicode.json")
    canonical, _ = _run(vec["input"])
    assert "café ☕ déjà" in canonical
    assert "\\u" not in canonical

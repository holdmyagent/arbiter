"""Docs gates: the two warden docs exist, cover the contract, no placeholders."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

WARDEN_DOC = REPO / "docs" / "warden.md"
SECRETS_DOC = REPO / "docs" / "secret-managers.md"


def test_warden_doc_covers_the_contract():
    text = WARDEN_DOC.read_text()
    for marker in [
        "the warden decides whether the agent walks through it",  # pitch line
        "pip install hold-warden",
        "hma token create",
        "hma-warden init",
        "hma-warden doctor",
        "hma-warden hash",
        "hma-warden serve",
        "arbiter_pubkey",
        "retention_days",
        "/v1/propose",
        "/v1/proposals/",
        "/v1/execute",
        "enable-linger",
        "SIGHUP",
        "idempotency_key",
        "HOLD_WARDEN_DATA_DIR",
    ]:
        assert marker in text, f"docs/warden.md missing: {marker}"
    for banned in ["TBD", "TODO", "FIXME"]:
        assert banned not in text, f"docs/warden.md contains placeholder: {banned}"


def test_secret_managers_doc_covers_the_recipes():
    text = SECRETS_DOC.read_text()
    for marker in [
        "env:", "file:", "cmd:",
        "rbw get",            # Bitwarden/Vaultwarden recommended path
        "BW_SESSION",         # official bw caveat
        "op read",            # 1Password
        "pass show",          # pass
        "vault kv get",       # HashiCorp Vault
        "ok (non-empty)",
        "FAILED (exit",
        "never prints",
    ]:
        assert marker in text, f"docs/secret-managers.md missing: {marker}"
    for banned in ["TBD", "TODO", "FIXME"]:
        assert banned not in text, f"docs/secret-managers.md placeholder: {banned}"

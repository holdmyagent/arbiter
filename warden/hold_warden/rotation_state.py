"""Persisted rotation trust state: adopted extra pins + the last-adopted seq.

Lives beside warden.sqlite3 in the data dir. Bytes are stored base64url so the
JSON is portable; load returns raw bytes ready for VerdictVerifier.

State stores PUBLIC pins + a monotonic seq only, so it is not itself a secret.
Both directions fail closed: a save is atomic (tmp file + os.replace, so a
crash mid-write never leaves a truncated file), and a load treats ANY
problem - missing file, invalid JSON, bad base64, or a pin whose bytes are
not a shape-valid Ed25519 public key (eager validation, not deferred to the
first `verify()`) - as "no rotation state yet" rather than raising or
smuggling in bad material. The file is written 0600 as an integrity signal
(a same-privilege FS writer could still tamper, but that privilege can also
rewrite warden.toml). Worst case on a tampered file: the adopted pins and seq
are forgotten and the warden falls back to its initial config pin, which always
wins on kid collision.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_FILENAME = "rotation_state.json"


def load_rotation_state(data_dir: Path) -> tuple[dict[str, bytes], int]:
    p = Path(data_dir) / _FILENAME
    if not p.is_file():
        return {}, 0
    try:
        doc = json.loads(p.read_text())
        adopted: dict[str, bytes] = {}
        for kid, x in doc.get("adopted", {}).items():
            raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
            Ed25519PublicKey.from_public_bytes(raw)  # eager shape check
            adopted[kid] = raw
        last_seq = int(doc.get("last_seq", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        return {}, 0
    return adopted, last_seq


def save_rotation_state(data_dir: Path, pinned: dict[str, bytes], last_seq: int) -> None:
    p = Path(data_dir) / _FILENAME
    doc = {"adopted": {kid: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
                       for kid, raw in pinned.items()},
           "last_seq": last_seq}
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, p)
    os.chmod(p, 0o600)

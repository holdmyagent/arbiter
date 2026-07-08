"""Ed25519 verdict signing — one signer per tenant cell.

Each cell owns its own Ed25519 key (private PEM at cell_dir/verdict_signing_key.pem,
0600). The kid is tenant-namespaced: f"{tenant_id}:{hash8}" where hash8 is the first
8 hex chars of sha256(raw public bytes) — widening the old 32-bit kid against grind
collisions and turning cross-tenant key confusion into a loud kid mismatch. Verdicts
are EdDSA JWS tokens bound to the tenant via aud=f"hma-verdict:{tenant_id}" plus an
hma.tenant_id claim (§7). Key rotation stages a record signed by the OLD key.
"""
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_FILENAME = "verdict_signing_key.pem"
RETIRED_FILENAME = "verdict_signing_key.retired.pem"
ROTATION_FILENAME = "verdict_rotation.json"


def _raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _hash8(key: Ed25519PrivateKey) -> str:
    return hashlib.sha256(_raw_public_bytes(key)).hexdigest()[:8]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwk(kid: str, key: Ed25519PrivateKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64u(_raw_public_bytes(key))}


def _load_key(pem_path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{pem_path} is not an Ed25519 private key")
    return key


def _mint_key(pem_path: Path) -> Ed25519PrivateKey:
    """Create a new PEM 0600 via O_EXCL; the loser of a first-run race loads the
    winner's key rather than crashing on FileExistsError."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    try:
        fd = os.open(pem_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _load_key(pem_path)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


@dataclass
class Signer:
    """A cell's per-tenant Ed25519 signer. kid is tenant-namespaced
    (f"{tenant_id}:{hash8}", §7) so an accidental key coincidence across tenants
    still yields distinct kids. sign_verdict(signer, ...) consumes this."""
    tenant_id: str
    kid: str
    signing_key: Ed25519PrivateKey
    dir: Path

    def public_jwks(self) -> dict:
        """JWKS served at GET /v1/keys for THIS tenant. During a rotation grace
        window the retired (previous) key is served alongside the current one and
        the OLD-key-signed rotation record is attached under "rotation"."""
        keys = [_jwk(self.kid, self.signing_key)]
        rec = _load_rotation(self.dir)
        if rec is not None:
            keys.append({"kty": "OKP", "crv": "Ed25519",
                         "kid": rec["prev_kid"], "x": rec["prev_x"]})
            return {"keys": keys, "rotation": rec["record"]}
        return {"keys": keys}


def load_or_create_signer(tenant_id: str, cell_dir) -> Signer:
    """Load (or mint on first run) this cell's Ed25519 signer.
    kid = f"{tenant_id}:{first-8-hex-of-sha256(raw pub)}"."""
    cell_dir = Path(cell_dir).expanduser()
    cell_dir.mkdir(parents=True, exist_ok=True)
    pem_path = cell_dir / KEY_FILENAME
    key = _load_key(pem_path) if pem_path.is_file() else _mint_key(pem_path)
    return Signer(tenant_id=tenant_id, kid=f"{tenant_id}:{_hash8(key)}",
                  signing_key=key, dir=cell_dir)


def _write_rotation(cell_dir: Path, rec: dict) -> None:
    (Path(cell_dir) / ROTATION_FILENAME).write_text(json.dumps(rec))


def _load_rotation(cell_dir: Path):
    """Return the staged rotation dict, or None if absent, unreadable, or expired."""
    p = Path(cell_dir) / ROTATION_FILENAME
    if not p.is_file():
        return None
    try:
        rec = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    if int(rec.get("expires_at", 0)) < int(time.time()):
        return None
    return rec


def sign_verdict(signer: "Signer", *, request_id: str, action_hash: str | None,
                 decision: str, decided_at: str, approval_ttl: int,
                 tenant_id: str) -> str:
    """Sign a verdict as an EdDSA JWS with SIGNER's (cell-scoped) key, bound to
    TENANT_ID: aud=f"hma-verdict:{tenant_id}" and an hma.tenant_id claim (§7/
    §15.8), so a verdict minted by one tenant's cell can never verify as
    belonging to another. action_hash=None means the request was created
    without a canonical action (cooperative tier) — verifiably unbound."""
    payload = {
        "iss": "hma",
        "aud": f"hma-verdict:{tenant_id}",
        "jti": request_id,
        "iat": int(time.time()),
        "hma": {
            "request_id": request_id,
            "action_hash": action_hash,
            "decision": decision,
            "decided_at": decided_at,
            "approval_ttl_seconds": approval_ttl,
            "tenant_id": tenant_id,
        },
    }
    return jwt.encode(payload, signer.signing_key, algorithm="EdDSA",
                      headers={"kid": signer.kid})


ROTATION_AUD_PREFIX = "hma-rotation:"


def sign_rotation_record(old_signer: Signer, *, new_kid: str, new_x: str, seq: int,
                         expires_at: int, tenant_id: str) -> str:
    """Sign a key-rotation record with the OLD key. The warden adopts new_kid ONLY
    if this record verifies under a LOCAL pin, carries tenant_id==paired, has
    seq strictly greater than the last adopted, and is not past expires_at (§7)."""
    payload = {
        "iss": "hma",
        "aud": f"{ROTATION_AUD_PREFIX}{tenant_id}",
        "iat": int(time.time()),
        "hma": {
            "tenant_id": tenant_id,
            "new_kid": new_kid,
            "new_x": new_x,
            "seq": seq,
            "expires_at": expires_at,
        },
    }
    return jwt.encode(payload, old_signer.signing_key, algorithm="EdDSA",
                      headers={"kid": old_signer.kid})

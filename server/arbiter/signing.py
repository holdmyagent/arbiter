"""Ed25519 verdict signing for the arbiter.

The private key lives beside the config as verdict_signing_key.pem (0600).
Verdicts are EdDSA JWS tokens an external verifier (the warden) checks
against the pinned public key from GET /v1/keys.
"""
import base64
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_FILENAME = "verdict_signing_key.pem"


def _raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _load_key(pem_path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{pem_path} is not an Ed25519 private key")
    return key


def load_or_create_keypair(config_dir: Path) -> tuple[str, Ed25519PrivateKey]:
    """Load (or mint on first run) the verdict signing key.

    Returns (kid, key) where kid = first 8 hex chars of sha256(raw public bytes).
    The PEM is written 0600 via O_EXCL so a concurrent first-run can't clobber it;
    the loser of that race recovers by loading the winner's key.
    """
    config_dir = Path(config_dir).expanduser()
    config_dir.mkdir(parents=True, exist_ok=True)
    pem_path = config_dir / KEY_FILENAME
    if pem_path.is_file():
        key = _load_key(pem_path)
    else:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        try:
            fd = os.open(pem_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            # Lost a concurrent first-run race: another process minted the key
            # between our is_file() check and the O_EXCL create. Use theirs.
            key = _load_key(pem_path)
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
    kid = hashlib.sha256(_raw_public_bytes(key)).hexdigest()[:8]
    return kid, key


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


def public_jwks(kid: str, key: Ed25519PrivateKey) -> dict:
    """Public key set for GET /v1/keys (RFC 7517 OKP entry, unpadded base64url x)."""
    x = base64.urlsafe_b64encode(_raw_public_bytes(key)).rstrip(b"=").decode()
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x}]}


@dataclass
class Signer:
    """A cell's per-tenant Ed25519 signer. kid is tenant-namespaced
    (f"{tenant_id}:{hash8}", §7) so an accidental key coincidence across tenants
    still yields distinct kids. The crypto group's sign_verdict(signer, ...)
    consumes this."""
    tenant_id: str
    kid: str
    signing_key: Ed25519PrivateKey

    def public_jwks(self) -> dict:
        return public_jwks(self.kid, self.signing_key)


def load_or_create_signer(tenant_id: str, cell_dir: Path) -> Signer:
    """Load (or mint on first open) this cell's verdict signing key from its own
    dir, returning a Signer whose kid is namespaced under the tenant. Reuses the
    shipped O_EXCL race-safe keypair loader; the 8-hex content hash becomes the
    suffix of a "{tenant_id}:{hash8}" kid."""
    hash8_kid, key = load_or_create_keypair(Path(cell_dir))
    return Signer(tenant_id=tenant_id, kid=f"{tenant_id}:{hash8_kid}", signing_key=key)

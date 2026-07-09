#!/usr/bin/env bash
# smoke-multitenant.sh — one arbiter, two tenants, curl-proven structural isolation.
#   provision : hma tenant create alice + bob; per-tenant app+agent tokens
#   happy     : alice creates -> alice app reads + approves -> verdict verifies under ALICE key
#   read-iso  : alice's app bearer 404s on bob's rid AND on bob's audit export
#   approve-iso: alice's app bearer 403/404s trying to DECIDE bob's rid (no cross-tenant approve)
#   device-iso: a device paired to alice is invisible to bob's /v1/devices
#   forged    : a router route to alice for a bearer never minted into the cell -> 403
#   verdict-iso: bob's verdict fails to verify under alice's JWKS (tenant-namespaced kid + aud)
# Port: arbiter 8905 (no clash with 8901/8902/8903/8904).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

# Use the repo-root venv when present (dev); else build a throwaway one (CI).
if [ -x "$ROOT/.venv/bin/hma" ]; then
  BIN="$ROOT/.venv/bin"
else
  python3 -m venv "$TMP/venv"
  "$TMP/venv/bin/pip" -q install "$ROOT/server"
  BIN="$TMP/venv/bin"
fi
PY="$BIN/python"

json_get() {  # json_get <json-string> <key> [<key>...] — walk keys, print the value
  "$PY" - "$@" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
for k in sys.argv[2:]:
    d = d[k]
print("" if d is None else d)
PYEOF
}

# All state (config, control.db, per-tenant cells) lives under $TMP — nothing
# touches the real ~/.config/holdmyagent or ~/.local/share/holdmyagent.
export HMA_CONFIG="$TMP/arbiter-config.toml" HMA_DB_PATH="$TMP/arbiter.sqlite3" HMA_PORT=8905
"$BIN/hma" init >/dev/null

# ── provision two tenants, mint per-tenant tokens ─────────────────────────
ALICE_OUT=$("$BIN/hma" tenant create alice)
BOB_OUT=$("$BIN/hma" tenant create bob)
A_APP=$(echo "$ALICE_OUT" | grep -oE 'hma_app_[0-9a-f]{48}')
B_APP=$(echo "$BOB_OUT" | grep -oE 'hma_app_[0-9a-f]{48}')
A_AGENT=$("$BIN/hma" token create alice-agent --role agent --tenant alice | grep -oE 'hma_agent_[0-9a-f]{48}')
B_AGENT=$("$BIN/hma" token create bob-agent --role agent --tenant bob | grep -oE 'hma_agent_[0-9a-f]{48}')
export A_APP B_APP
echo "ok: provision — alice + bob tenants created, app+agent tokens minted"

# ── forged: register a router hint for alice with NO matching cell token ──
# Done before `hma serve` boots (no server needed — control.db is plain
# filesystem state), mirroring how `hma tenant create`/`hma token create`
# operate directly on disk. This proves the router is a hint, not authority:
# a token that resolves to alice's tenant_id in control.db but was never
# minted into alice's cell db must still be rejected.
FORGED=$("$PY" - "$HMA_DB_PATH" <<'PYEOF'
import hashlib, secrets, sys
from pathlib import Path
from arbiter.control import ControlPlane
db_path = Path(sys.argv[1])
control = ControlPlane.open(db_path.parent / "control", db_path.parent / "cells")
forged = "hma_agent_" + secrets.token_hex(24)
control.add_route(hashlib.sha256(forged.encode()).hexdigest(), "alice")
print(forged)
PYEOF
)

"$BIN/hma" serve &
SERVER_PID=$!
for _ in $(seq 1 60); do
  curl -fsS localhost:8905/health >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS localhost:8905/health | grep -q '"ok":true'

auth() { echo "Authorization: Bearer $1"; }

# ── happy: alice creates, alice approves, verdict verifies under ALICE key ─
RID_A=$(curl -fsS -X POST localhost:8905/v1/requests -H "$(auth "$A_AGENT")" \
  -H 'content-type: application/json' -d '{"title":"alice-pay"}' \
  | { read j; json_get "$j" id; })
curl -fsS -X POST "localhost:8905/v1/requests/$RID_A/decision" -H "$(auth "$A_APP")" \
  -H 'content-type: application/json' -d '{"decision":"approve"}' >/dev/null
VJWS=$(curl -fsS "localhost:8905/v1/requests/$RID_A/verdict" -H "$(auth "$A_APP")" \
  | { read j; json_get "$j" verdict; })
"$PY" - "$VJWS" <<'PYEOF'
import base64, json, os, sys, urllib.request
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
jws = sys.argv[1]
req = urllib.request.Request("http://127.0.0.1:8905/v1/keys",
    headers={"Authorization": "Bearer " + os.environ["A_APP"]})
keys = json.load(urllib.request.urlopen(req))["keys"]
kid = jwt.get_unverified_header(jws)["kid"]
assert kid.startswith("alice:"), f"kid not tenant-namespaced: {kid}"
jwk = next(k for k in keys if k["kid"] == kid)
pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)))
claims = jwt.decode(jws, key=pub, algorithms=["EdDSA"], audience="hma-verdict:alice")
assert claims["hma"]["tenant_id"] == "alice", claims
PYEOF
echo "ok: happy path — alice created, approved, verdict tenant-bound"

# ── read-iso: alice cannot READ bob's rid or audit ────────────────────────
RID_B=$(curl -fsS -X POST localhost:8905/v1/requests -H "$(auth "$B_AGENT")" \
  -H 'content-type: application/json' -d '{"title":"bob-secret"}' \
  | { read j; json_get "$j" id; })
CODE=$(curl -s -o /dev/null -w '%{http_code}' "localhost:8905/v1/requests/$RID_B" -H "$(auth "$A_APP")")
[ "$CODE" = "404" ] || { echo "FAIL: alice read bob's rid (got $CODE)" >&2; exit 1; }
curl -fsS "localhost:8905/v1/audit/export" -H "$(auth "$A_APP")" | grep -q "$RID_B" \
  && { echo "FAIL: bob's rid leaked into alice's audit export" >&2; exit 1; } || true
echo "ok: read isolation — alice blind to bob's request + audit"

# ── approve-iso: alice cannot DECIDE bob's rid ────────────────────────────
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8905/v1/requests/$RID_B/decision" \
  -H "$(auth "$A_APP")" -H 'content-type: application/json' -d '{"decision":"approve"}')
[ "$CODE" = "404" ] || [ "$CODE" = "403" ] \
  || { echo "FAIL: alice approved bob's request (got $CODE)" >&2; exit 1; }
ST=$(curl -fsS "localhost:8905/v1/requests/$RID_B" -H "$(auth "$B_APP")" | { read j; json_get "$j" status; })
[ "$ST" = "pending" ] || { echo "FAIL: bob's request status is '$ST', expected pending" >&2; exit 1; }
echo "ok: approve isolation — alice cannot decide bob's request"

# ── device-iso: a device paired to alice is invisible to bob ──────────────
curl -fsS -X POST localhost:8905/v1/devices -H "$(auth "$A_APP")" \
  -H 'content-type: application/json' -d '{"apns_token":"alice-phone","name":"Alice iPhone"}' >/dev/null
curl -fsS localhost:8905/v1/devices -H "$(auth "$B_APP")" | grep -q "alice-phone" \
  && { echo "FAIL: alice's device visible to bob" >&2; exit 1; } || true
echo "ok: device isolation — alice's phone invisible to bob"

# ── forged: a router route to alice for an unminted bearer -> 403 ─────────
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8905/v1/requests \
  -H "$(auth "$FORGED")" -H 'content-type: application/json' -d '{"title":"x"}')
[ "$CODE" = "403" ] || { echo "FAIL: forged route not rejected (got $CODE)" >&2; exit 1; }
echo "ok: forged route — router hint without a cell token → 403"

# ── verdict-iso: bob's verdict must NOT verify under alice's key ──────────
curl -fsS -X POST "localhost:8905/v1/requests/$RID_B/decision" -H "$(auth "$B_APP")" \
  -H 'content-type: application/json' -d '{"decision":"approve"}' >/dev/null
VJWS_B=$(curl -fsS "localhost:8905/v1/requests/$RID_B/verdict" -H "$(auth "$B_APP")" \
  | { read j; json_get "$j" verdict; })
"$PY" - "$VJWS_B" <<'PYEOF'
import base64, json, os, sys, urllib.request
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
jws = sys.argv[1]
req = urllib.request.Request("http://127.0.0.1:8905/v1/keys",
    headers={"Authorization": "Bearer " + os.environ["A_APP"]})
akeys = json.load(urllib.request.urlopen(req))["keys"]
apub = Ed25519PublicKey.from_public_bytes(
    base64.urlsafe_b64decode(akeys[0]["x"] + "=" * (-len(akeys[0]["x"]) % 4)))
try:
    jwt.decode(jws, key=apub, algorithms=["EdDSA"], audience="hma-verdict:alice")
except jwt.InvalidTokenError:
    pass
else:
    sys.exit("FAIL: bob's verdict verified under alice's key — tenant binding broken")
PYEOF
echo "ok: verdict isolation — bob's verdict rejected under alice's key/audience"

echo "SMOKE-MULTITENANT OK"

#!/usr/bin/env bash
# smoke-warden.sh — end-to-end warden enforcement smoke.
#   happy path : propose -> approve on the arbiter -> warden executes -> marker in stdout_tail
#   receipt    : verdict JWS verifies against /v1/keys; hash bound to the stored canonical
#   replay     : second consume of the same approval -> 409
#   deny path  : propose -> deny -> proposal denied and NO side effect (marker file absent)
#   expiry     : propose at the 30s policy-floor TTL, never answer -> expired, NO side effect
#   wrong key  : second warden pinned to a WRONG Ed25519 key -> proposal failed, NO side effect
# Ports: arbiter 8902, wardens 8903 + 8904 (scripts/smoke.sh uses 8901 — no clash).
# Overall timeout budget: ~3 minutes — the expiry leg alone waits out a 30s TTL (90s deadline).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""
WARDEN_PID=""
WARDEN2_PID=""
cleanup() {
  [ -n "$WARDEN2_PID" ] && kill "$WARDEN2_PID" 2>/dev/null || true
  [ -n "$WARDEN_PID" ] && kill "$WARDEN_PID" 2>/dev/null || true
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

# Use the repo-root venv when present (dev); else build a throwaway one (CI).
if [ -x "$ROOT/.venv/bin/hma" ] && [ -x "$ROOT/.venv/bin/hma-warden" ]; then
  BIN="$ROOT/.venv/bin"
else
  python3 -m venv "$TMP/venv"
  "$TMP/venv/bin/pip" -q install "$ROOT/server" "$ROOT/warden"
  BIN="$TMP/venv/bin"
fi
PY="$BIN/python"

json_get() {  # json_get <json-string> <key> [<key>...] — walk keys, print the value
  "$PY" - "$@" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
for k in sys.argv[2:]:
    d = d[k]
print(d)
PYEOF
}

# ── arbiter up ────────────────────────────────────────────────────────────
export HMA_CONFIG="$TMP/arbiter-config.toml" HMA_DB_PATH="$TMP/arbiter.sqlite3" HMA_PORT=8902
"$BIN/hma" init
WARDEN_TOKEN=$("$BIN/hma" token create warden-smoke --role warden \
               | grep -oE 'hma_warden_[0-9a-f]{48}')
"$BIN/hma" serve &
SERVER_PID=$!
for _ in $(seq 1 60); do
  curl -fsS localhost:8902/health >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS localhost:8902/health | grep -q '"ok":true'
APP_TOKEN=$(grep app_token "$HMA_CONFIG" | cut -d'"' -f2)

# ── warden config + up ────────────────────────────────────────────────────
ARBITER_PUBKEY=$(curl -fsS localhost:8902/v1/keys | "$PY" -c \
  'import json,sys; k=json.load(sys.stdin)["keys"][0]; print(k["kid"]+":"+k["x"])')
SMOKE_AGENT_TOKEN=$("$PY" -c 'import secrets; print(secrets.token_hex(24))')
export SMOKE_AGENT_TOKEN SMOKE_WARDEN_TOKEN="$WARDEN_TOKEN"
export HOLD_WARDEN_DATA_DIR="$TMP/warden-data"   # keep the warden's SQLite inside $TMP
mkdir -p "$HOLD_WARDEN_DATA_DIR"

cat > "$TMP/warden.toml" <<EOF
[warden]
arbiter_url = "http://127.0.0.1:8902"
arbiter_token = "env:SMOKE_WARDEN_TOKEN"
arbiter_pubkey = "$ARBITER_PUBKEY"
name = "smoke-warden"
bind = "127.0.0.1"
port = 8903
retention_days = 7

[agents.smoke]
token = "env:SMOKE_AGENT_TOKEN"

[actions.echo_marker]
adapter = "command"
severity = "low"
ttl_seconds = 60
description = "Echo a marker string (smoke test)"
argv = ["echo", "{marker}"]

  [actions.echo_marker.params.marker]
  type = "string"
  max_len = 64
  pattern = "^[a-z0-9-]+\$"

[actions.touch_marker]
adapter = "command"
severity = "low"
ttl_seconds = 60
description = "Create a marker file — must NEVER run on the deny path"
argv = ["touch", "$TMP/deny-marker"]

[actions.touch_expiry_marker]
adapter = "command"
severity = "low"
ttl_seconds = 30
description = "Create a marker file — must NEVER run on the expiry path (TTL = policy floor)"
argv = ["touch", "$TMP/expiry-marker"]

[actions.touch_wrongkey_marker]
adapter = "command"
severity = "low"
ttl_seconds = 60
description = "Create a marker file — must NEVER run when the pinned key is wrong"
argv = ["touch", "$TMP/wrongkey-marker"]
EOF

"$BIN/hma-warden" serve --config "$TMP/warden.toml" &
WARDEN_PID=$!
for _ in $(seq 1 60); do
  curl -fsS localhost:8903/health >/dev/null 2>&1 && break
  sleep 0.5
done

wait_proposal() {  # wait_proposal <proposal_id> <want_status> [<port>] — echoes final proposal JSON
  local pid="$1" want="$2" port="${3:-8903}" body status
  for _ in $(seq 1 60); do
    body=$(curl -fsS "localhost:$port/v1/proposals/$pid" \
           -H "Authorization: Bearer $SMOKE_AGENT_TOKEN")
    status=$(json_get "$body" status)
    if [ "$status" = "$want" ]; then echo "$body"; return 0; fi
    case "$status" in
      pending|executing) sleep 0.5 ;;
      *) echo "FAIL: proposal $pid reached '$status', wanted '$want'" >&2; return 1 ;;
    esac
  done
  echo "FAIL: proposal $pid never reached '$want'" >&2
  return 1
}

# ── happy path: propose -> approve -> executed, marker in stdout_tail ─────
MARKER="hma-smoke-$("$PY" -c 'import secrets; print(secrets.token_hex(4))')"
P1=$(curl -fsS -X POST localhost:8903/v1/propose \
  -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" -H 'content-type: application/json' \
  -d "{\"action\":\"echo_marker\",\"params\":{\"marker\":\"$MARKER\"}}")
PID1=$(json_get "$P1" proposal_id)
RID1=$(json_get "$P1" request_id)
curl -fsS -X POST "localhost:8902/v1/requests/$RID1/decision" \
  -H "Authorization: Bearer $APP_TOKEN" -H 'content-type: application/json' \
  -d '{"decision":"approve"}' >/dev/null
BODY1=$(wait_proposal "$PID1" executed)
json_get "$BODY1" result stdout_tail | grep -q "$MARKER" \
  || { echo "FAIL: marker '$MARKER' missing from stdout_tail" >&2; exit 1; }
echo "ok: happy path executed with marker in stdout_tail"

# ── receipt: verify the verdict JWS signature + action-hash binding ───────
RECEIPT_JWS=$(json_get "$BODY1" receipt verdict_jws)
RECEIPT_HASH=$(json_get "$BODY1" receipt action_hash)
"$PY" - "$RECEIPT_JWS" "$RECEIPT_HASH" "$HOLD_WARDEN_DATA_DIR/warden.sqlite3" "$PID1" <<'PYEOF'
import base64, hashlib, json, sqlite3, sys, urllib.request
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

jws, receipt_hash, db_path, proposal_id = sys.argv[1:5]

# 1. the verification key, fresh from the arbiter's JWKS endpoint
keys = json.load(urllib.request.urlopen("http://127.0.0.1:8902/v1/keys"))["keys"]
kid = jwt.get_unverified_header(jws)["kid"]
jwk = next(k for k in keys if k["kid"] == kid)
pub = Ed25519PublicKey.from_public_bytes(
    base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)))

# 2. signature + audience (raises -> non-zero exit -> smoke fails)
claims = jwt.decode(jws, key=pub, algorithms=["EdDSA"], audience="hma-verdict")

# 3. the hash the verdict is bound to == the receipt's hash…
bound = claims["hma"]["action_hash"]
if bound != receipt_hash:
    sys.exit(f"FAIL: verdict action_hash {bound} != receipt action_hash {receipt_hash}")

# 4. …and == sha256 of the canonical the warden stored for this proposal
canonical = sqlite3.connect(db_path).execute(
    "SELECT canonical FROM proposals WHERE id=?", (proposal_id,)).fetchone()[0]
recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
if bound != recomputed:
    sys.exit(f"FAIL: verdict action_hash {bound} != sha256(stored canonical) {recomputed}")
PYEOF
echo "ok: receipt verified — signature, audience, and action-hash binding"

# ── replay: second consume of the same approval -> 409 ────────────────────
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "localhost:8902/v1/requests/$RID1/consume" \
  -H "Authorization: Bearer $WARDEN_TOKEN")
[ "$CODE" = "409" ] || { echo "FAIL: second consume returned $CODE, wanted 409" >&2; exit 1; }
echo "ok: double consume refused (409)"

# ── deny path: propose -> deny -> denied, NO side effect ──────────────────
P2=$(curl -fsS -X POST localhost:8903/v1/propose \
  -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"action":"touch_marker","params":{}}')
PID2=$(json_get "$P2" proposal_id)
RID2=$(json_get "$P2" request_id)
curl -fsS -X POST "localhost:8902/v1/requests/$RID2/decision" \
  -H "Authorization: Bearer $APP_TOKEN" -H 'content-type: application/json' \
  -d '{"decision":"deny"}' >/dev/null
wait_proposal "$PID2" denied >/dev/null
[ ! -e "$TMP/deny-marker" ] \
  || { echo "FAIL: deny path executed the action (marker file exists)" >&2; exit 1; }
echo "ok: deny path held — no side effect"

# ── expiry: propose at the policy-floor TTL, never answer -> expired ──────
P3=$(curl -fsS -X POST localhost:8903/v1/propose \
  -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"action":"touch_expiry_marker","params":{}}')
PID3=$(json_get "$P3" proposal_id)
STATUS3=""
for _ in $(seq 1 180); do   # 90s deadline: 30s TTL + sweeper lag + polling slack
  BODY3=$(curl -fsS "localhost:8903/v1/proposals/$PID3" \
          -H "Authorization: Bearer $SMOKE_AGENT_TOKEN")
  STATUS3=$(json_get "$BODY3" status)
  [ "$STATUS3" = "expired" ] && break
  case "$STATUS3" in
    pending|executing) sleep 0.5 ;;
    *) echo "FAIL: expiry proposal reached '$STATUS3', wanted 'expired'" >&2; exit 1 ;;
  esac
done
[ "$STATUS3" = "expired" ] \
  || { echo "FAIL: proposal $PID3 never expired within the 90s deadline" >&2; exit 1; }
[ ! -e "$TMP/expiry-marker" ] \
  || { echo "FAIL: expiry path executed the action (marker file exists)" >&2; exit 1; }
echo "ok: expiry path held — no side effect"

# ── wrong key: a warden pinned to the WRONG Ed25519 key must fail closed ──
WRONG_X=$("$PY" - <<'PYEOF'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
PYEOF
)
WRONG_PUBKEY="${ARBITER_PUBKEY%%:*}:$WRONG_X"   # real kid, wrong key bytes -> signature must fail
sed -e "s|^arbiter_pubkey = .*|arbiter_pubkey = \"$WRONG_PUBKEY\"|" \
    -e "s|^port = 8903|port = 8904|" \
    "$TMP/warden.toml" > "$TMP/warden2.toml"
mkdir -p "$TMP/warden2-data"
HOLD_WARDEN_DATA_DIR="$TMP/warden2-data" \
  "$BIN/hma-warden" serve --config "$TMP/warden2.toml" &
WARDEN2_PID=$!
for _ in $(seq 1 60); do
  curl -fsS localhost:8904/health >/dev/null 2>&1 && break
  sleep 0.5
done

P4=$(curl -fsS -X POST localhost:8904/v1/propose \
  -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"action":"touch_wrongkey_marker","params":{}}')
PID4=$(json_get "$P4" proposal_id)
RID4=$(json_get "$P4" request_id)
curl -fsS -X POST "localhost:8902/v1/requests/$RID4/decision" \
  -H "Authorization: Bearer $APP_TOKEN" -H 'content-type: application/json' \
  -d '{"decision":"approve"}' >/dev/null
wait_proposal "$PID4" failed 8904 >/dev/null
[ ! -e "$TMP/wrongkey-marker" ] \
  || { echo "FAIL: wrong-key warden executed the action (marker file exists)" >&2; exit 1; }
echo "ok: wrong pinned key refused — proposal failed with no side effect"

echo "SMOKE-WARDEN OK"

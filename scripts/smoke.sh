#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'kill %1 2>/dev/null; rm -rf "$TMP"' EXIT
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/pip" -q install "$ROOT/server" "$ROOT/sdk"
export HMA_CONFIG="$TMP/config.toml" HMA_DB_PATH="$TMP/db.sqlite3" HMA_PORT=8901
"$TMP/venv/bin/hma" init
"$TMP/venv/bin/hma" serve &
for i in $(seq 1 30); do curl -fsS localhost:8901/health >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS localhost:8901/health | grep -q '"ok":true'
APP_TOKEN=$(grep app_token "$HMA_CONFIG" | cut -d'"' -f2)
( sleep 2
  RID=$("$TMP/venv/bin/python" -c "
import httpx,os
h={'Authorization':'Bearer $APP_TOKEN'}
print(httpx.get('http://localhost:8901/v1/requests',headers=h,params={'status':'pending'}).json()[0]['id'])")
  curl -fsS -X POST "localhost:8901/v1/requests/$RID/decision" \
    -H "Authorization: Bearer $APP_TOKEN" -H 'content-type: application/json' \
    -d '{"decision":"approve"}' >/dev/null ) &
"$TMP/venv/bin/hma" ask "Smoke test?" --severity low --ttl 30
echo "SMOKE OK (hma ask exited 0 = approved)"

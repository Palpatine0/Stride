#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
source .env
set +a
export LOCAL_UID="$(id -u)"
export XRAY_CONFIG_DIR="$(dirname "$XRAY_CONFIG")"
endpoint="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"
case "$endpoint" in
  unix://*) export DOCKER_SOCKET="${endpoint#unix://}" ;;
  *) echo 'A local Docker Unix socket is required.' >&2; exit 1 ;;
esac
test -S "$DOCKER_SOCKET"
test -f "$XRAY_CONFIG"
test "$(basename "$XRAY_CONFIG")" = xray.json
test -n "$VPN_HOST"
test -n "$VPN_WS_PATH"
docker inspect "$XRAY_CONTAINER" >/dev/null
compose=(docker compose -f compose.yaml -f compose.tunnel.yaml -f compose.controller.yaml)
"${compose[@]}" config --quiet
"${compose[@]}" build
# Stop SQLite writers before aligning volume ownership with the host config owner.
# The named volume and all existing users, tokens and sessions are retained.
"${compose[@]}" stop controller web
"${compose[@]}" run --rm --no-deps --user 0 --cap-add CHOWN --cap-add DAC_READ_SEARCH --entrypoint python web -c \
  'import os,sys; from pathlib import Path; uid=int(sys.argv[1]); p=Path("/data"); os.chown(p,uid,0); [(os.chown(f,uid,0)) for f in p.iterdir() if f.is_file()]' "$LOCAL_UID"
"${compose[@]}" up -d
echo 'Checking controller sync and subscriptions (up to 90 seconds)...'
# Verify the exact database used by the public API; never print subscription tokens.
"${compose[@]}" exec -T web python - <<'PY'
import base64, json, sqlite3, time, urllib.request
for attempt in range(45):
    with sqlite3.connect('/data/vpn.sqlite3') as db:
        meta = dict(db.execute('SELECT key,value FROM meta'))
        tokens = [r[0] for r in db.execute('SELECT token FROM users WHERE enabled=1')]
    if (meta.get('revision') == meta.get('applied')
            and time.time() - int(meta.get('controller_at', 0)) < 60
            and not meta.get('error')):
        for token in tokens:
            with urllib.request.urlopen('http://127.0.0.1:8092/sub/'+token, timeout=5) as response:
                assert base64.b64decode(response.read()).startswith(b'vless://')
        print('Controller synced; all enabled subscription responses are valid.')
        break
    time.sleep(2)
else:
    raise SystemExit('Controller did not sync: '+meta.get('error', 'check controller logs'))
PY
echo 'Checking the public VPN TLS/WebSocket route...'
"${compose[@]}" exec -T web python - < deploy/check-vpn-route.py
"${compose[@]}" ps

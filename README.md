# VPN Console

Private Shadowrocket user and subscription management for the local Xray server.

```
ui/       React dashboard
api/      HTTP API, SQLite storage, host Docker controller, tests
docs/     Design and deployment decisions
deploy/   Reverse-proxy configuration example
```

## Local setup

Requirements: Python 3.9+, Node.js 22+, npm, and Docker CLI for the controller. The Python API has no third-party dependencies. Run all Python commands from this repository root.

```sh
cp .env.example .env
# Edit .env with your actual admin, Google OAuth and existing VPN settings.
set -a
source .env
set +a
cd ui
npm install
npm run build
cd ..
python3 -m api.server
```

The initial dependency install generates `ui/package-lock.json`; review and commit it, then use `npm ci` for repeatable builds. Dependencies have not been installed in the restricted authoring environment.

For Vite development, use `PUBLIC_URL=http://localhost:5173` for the API, register that callback with Google, and run `npm run dev` in `ui` in another shell. Vite proxies `/api` and `/sub` to port 8092. Production serves the built UI from the API on the same origin.

## Admin sign-in

1. In Google Cloud, create a Web application OAuth client. Configure the consent screen and add your Google account as a test user if the app is in testing.
2. Register the exact redirect URI `https://stride.sethmccarthy.in/api/auth/callback` (and `http://localhost:5173/api/auth/callback` for development).
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `ADMIN_EMAIL` in `.env`. Only that exact verified email is allowed.
4. Enable a passkey or MFA on the Google account. The dashboard has no separate password database.

No default administrator, public sign-up, or development authentication bypass exists. Keep `.env`, the database, and config backups private.

## Enable the local controller

The web API does not get a Docker socket. Run the controller as the host user who already operates Docker. Load the same environment and database path in both processes. Use absolute DATABASE_PATH values for services with different working directories.

Before starting, confirm `docker ps` works in your terminal, verify `XRAY_CONFIG`, `VPN_HOST`, `VPN_PORT`, and `VPN_WS_PATH`, and back up the existing service. Do not change the existing WebSocket route. The controller supports one VLESS WebSocket inbound; other protocols need separate adapters.

```sh
# First integration: import existing UUIDs, validate, apply, and verify one cycle.
python3 -m api.controller --apply --import-existing --once
# After checking existing clients still connect, run continuously:
python3 -m api.controller --apply
```

Both commands modify the VPN configuration and restart the container. The app displays pending changes until a successful apply. Use a service manager for the API and controller after integration tests pass. Do not run a second controller, and do not serve the database directory.

The controller backs up the config before writing, validates with the installed Xray binary, and attempts rollback on failure. It writes the existing file in place because the Docker Compose file mounts a single file; atomic replacement would leave that container bound to the old inode. The original config is never copied into this repository.

If someone edits Xray config manually after the controller first applies it, it refuses to overwrite the change. Stop the controller, inspect and back up both versions, then clear only `meta.config_hash` after deciding the new config is authoritative. Restart the controller and verify all clients.

## Docker access in Codex

The observed socket is `/Users/sethmccarthy/.docker/run/docker.sock`, owned by the logged-in macOS user. The authoring session denied access through its sandbox. Changing Unix socket modes does not grant a sandbox capability. Do not make the socket world-writable or expose an unauthenticated Docker TCP port.

Use a Codex session permitted to access the local Docker socket, if your app/policy offers that permission, or run the commands yourself in Terminal. Exact permission controls depend on the installed Codex application and managed policy; this project cannot change them. The current authoring session does not support shell escalation.

## Domain and HTTPS

`deploy/Caddyfile` is an integration example for a host-based Caddy instance. First inspect the existing ingress and DNS. Do not start a second service on port 443 or replace the current VPN proxy. If the proxy is containerized, its loopback is not the host: use its existing host routing or an appropriately restricted shared network instead.

Point `stride.sethmccarthy.in` to the actual ingress, provision TLS, and proxy to the local API. A tunnel is also possible when the Mac has no reachable public address, but configure it against the existing network topology. Keep `/sub/*` reachable by Shadowrocket without browser login. Disable access-log capture of subscription URLs and query strings. Add request rate limits at the existing edge before public exposure. DNS/TLS are not configured by the source files alone.

## Verify

```sh
python3 -m unittest discover -s api -p 'test_*.py' -v
cd ui
npm run build
```

Live checklist: administrator-only login; mobile layout; import generated URL into Shadowrocket; verify two users have separate counters; rotate credentials and verify the old UUID no longer connects; disable a user; restart Xray and verify totals persist; stop the controller and confirm stale/pending UI states. The current implementation has not passed these live checks because Docker and package download access were unavailable.

See [the design document](docs/design.md) for scope, tradeoffs, and limitations.

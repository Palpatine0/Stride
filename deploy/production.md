# Production Stride deployment

## Start the complete stack

Run from this repository on the Mac:

```sh
bash deploy/start-production.sh
```

This builds and starts the dashboard, dedicated Stride tunnel, and VPN controller
together using `compose.yaml`, `compose.tunnel.yaml`, and `compose.controller.yaml`.
It retains the production `console_data` volume, briefly stops SQLite writers to
align ownership with the host user, and applies pending VPN changes through the
controller. Applying an Xray configuration change restarts the VPN server.

The startup script checks controller sync and verifies that every enabled local
subscription returns a VLESS payload. It also requires a verified public
TLS/WebSocket upgrade (HTTP 101) at `VPN_HOST`, `VPN_PORT`, and `VPN_WS_PATH`; a 502
or dashboard HTML response fails deployment verification.

A successful WebSocket handshake proves the public route reaches a WebSocket
server. It does not authenticate a VLESS user or prove internet access. After
route verification, test an existing client against Google through the VPN,
check Xray traffic counters, and confirm the affected phone works.

## Production data and permissions

The controller and dashboard share the existing production `console_data` volume
and `/data/vpn.sqlite3` database. Production does not import development users or
sessions automatically. Do not run a host controller against a different database
and assume it manages production users, or run it alongside this controller.

Only the controller receives the Docker socket and the existing Xray configuration
directory. Its UID matches the host owner of that configuration; both application
processes use the same UID to keep SQLite WAL files accessible. Xray configuration
is backed up before changes, and unmanaged VPN clients remain. Docker socket
access grants control over Docker; it is never mounted into the web service.
Use the complete startup script for subsequent deployments so the controller
overlay and database ownership remain consistent.

The root Dockerfile builds React and runs the Python API as an unprivileged user.
Compose reads Google credentials from the ignored `.env` and fixes the production
origin at `https://stride.sethmccarthy.in`.

## Dashboard routing and Google sign-in

The dashboard is published only on the Mac's loopback port **8093**, avoiding the
development server on port 8092. Check `/api/health` and `/api/session` on port 8093;
the session response must show `loginConfigured: true`.

The separate Cloudflare tunnel **prd_carrion-spike_stride** publishes
`stride.sethmccarthy.in` to `http://web:8092`. Its `stride_tunnel` connector runs on
the Stride project's own network. Keep this dashboard route separate from the
existing VPN route and do not change Voca's connector or configuration.

Save the Stride tunnel token in `data/cloudflare-token` (ignored by Git). The token
is mounted only into the connector, not the web application. Do not paste the
token into chat or commit it. `python3 deploy/connect-tunnel.py` saves the token
from the copied Cloudflare command and invokes the same complete startup script.

Google OAuth must allow this exact production callback:

`https://stride.sethmccarthy.in/api/auth/callback`

Verify public DNS, HTTPS, dashboard health, and Google sign-in after changing
routing or OAuth settings. Docker files alone do not register the hostname.

## Current VPN route and network requirement

`VPN_HOST` must identify the actual VPN ingress; `PUBLIC_URL` remains
`https://stride.sethmccarthy.in`. The existing `vpn.sethmccarthy.in` route still
uses the older connector with origin `http://shadowrocket_vless:8080`; it has not
migrated to the dedicated Stride tunnel.

Xray must share a Docker network with the connector serving the VPN hostname.
The VPN server's Compose configuration in
`/Users/sethmccarthy/Services/shadowrocket/compose.yaml` retains
`shadowrocket_network` and also attaches the VPN server to the existing
connector's `voca_network`. Voca's files and containers do not need to change or
restart.

A tunnel log reporting `lookup shadowrocket_vless ... no such host` means the
connector cannot resolve Xray on its Docker network. This causes public HTTP 502
before VLESS authentication; valid subscriptions and healthy containers do not
resolve it. Keep the shared network attachment in the VPN server configuration
so recreating that server preserves reachability. Do not change the VPN hostname
to the dashboard hostname without configuring and verifying its VPN ingress
first.

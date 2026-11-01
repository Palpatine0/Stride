# VPN Console design and implementation

Status: initial implementation; live integration and frontend build are awaiting local environment access.

The supplied design reference is saved verbatim in DESIGN-jobright.md. Its mint (#00f0a0), warm mint canvas (#ecffe0), black pill actions, Titillium Web headings, Inter UI, and rounded cards are applied by ui/src/theme.css. This document records application behavior and deployment decisions.

## Goal

An administrator at `vpn.sethmccarthy.in` creates and manages individual Shadowrocket subscriptions, assigns names and tags, and monitors recorded upload/download traffic. Source layout is `/ui` (React) and `/api` (Python API and local Docker controller).

## Verified local configuration

Read-only inspection on November 1, 2026 found an Xray VLESS WebSocket configuration, listening on port 8080 inside Docker, with two clients. Its Docker Compose service is named `server`, container `shadowrocket_vless`. Neither the stats service nor the management API is enabled. A separate Shadowsocks Compose file also exists. Docker socket access was denied, so which services are running, the public proxy, TLS endpoint, and DNS are unverified. No original VPN configuration has been modified.

## Experience

Use the supplied Jobright design language: white sidebar, warm mint heading band, black pill primary actions, mint highlights, rounded summary cards, and a user table. Mobile navigation collapses into an icon bar. The main navigation contains Overview, Users & links, Activity, and Settings. No placeholder users, fake usage, or invented live status.

The overview shows user count, lifetime recorded upload/download totals, enabled subscriptions, and 14 daily traffic bars. Empty, pending, disconnected, failed, and stale states must remain visible. Daily buckets use UTC. Labels reflect collection time; outages may shift recovered counter deltas into the recovery day's bucket.

User creation takes a name and optional comma-separated tags. Access management reveals a private subscription URL and QR code. Disabling or rotating credentials requires a confirmation that explains the connection interruption. Rotation replaces both the URL token and the VLESS UUID. The old subscription URL stops resolving immediately; existing VPN access is revoked when the controller successfully applies the configuration. Name and tag edits never restart Xray.

## Authentication

Default: Google OAuth authorization-code flow with PKCE, a one-time state bound to an HttpOnly cookie, and server-side token exchange. Identity is fetched directly from Google's HTTPS UserInfo endpoint. Only the configured exact, verified `ADMIN_EMAIL` is accepted. There is no public registration or password fallback. Google MFA/passkeys can protect that Google account, but the app does not independently enforce provider MFA.

Opaque admin sessions are hashed in SQLite, expire after 12 hours, and use HttpOnly, SameSite=Lax, Secure cookies in production. All mutations require an exact same-origin Origin header and an authenticated session. OAuth state expires after 10 minutes. No browser-facing endpoint can execute Docker commands or accept a filesystem path.

## Components

- React + Vite UI, with Lucide icons and locally rendered subscription QR codes.
- Python 3.9+ standard-library HTTP API, deployed only behind a TLS reverse proxy. For a larger or multi-admin deployment, replace the lightweight HTTP server with a hardened application server and add edge rate limits. The current scope is one private administrator and a small personal VPN.
- SQLite in WAL mode, with restrictive filesystem permissions, user metadata, bearer subscriptions, hashed sessions, audit events, cumulative counters, and UTC daily aggregates.
- A separate host controller holds Docker access. It has no HTTP listener. It watches the shared database, validates generated Xray configuration, saves a protected backup, applies changes, and restarts Xray. Only one controller can run, enforced by a filesystem lock.
- Existing reverse proxy handles HTTPS for `vpn.sethmccarthy.in`. The API binds to loopback. The VPN's existing WebSocket ingress remains separate from dashboard routing.

## Traffic accounting and persistence

Managed Xray clients have stable email identifiers and level 100 policies enabling upload/download statistics. The stats API binds to 127.0.0.1 inside the VPN container and is queried through `docker exec`; it is never published to the network. The controller samples every 15 seconds, stores cumulative deltas, and identifies restart generations from Docker's StartedAt value. An ordinary restart does not double-count counters. Unsampled traffic before a crash or restart cannot be recovered; this is operational monitoring, not billing-grade metering.

The controller preserves unrelated clients and routes. `--import-existing` explicitly adopts existing VLESS clients without changing their UUIDs, assigning generic names until the administrator labels them. Existing traffic history is unavailable. Changes apply from a consistent database snapshot; newer concurrent changes remain pending. External config changes cause the controller to stop applying changes until reviewed. Initial integration validates a new config before touching the original, then rolls back if restart or stats verification fails.

The first release uses safe config validation and process restarts instead of hot user mutations. This is compatible with a wider range of Xray versions, but briefly drops active connections. Test against the installed container before unattended use. Configuration rollback failure, power loss mid-write, and future Xray behavior changes still require operator intervention; keep the backups.

## Subscription contract

`GET /sub/<random 256-bit token>` returns a base64-encoded VLESS URI using TLS and WebSocket, plus the recorded upload/download header. This adapter requires the existing public hostname, port, and WebSocket path. Subscriptions return 503 while any credential configuration is pending and 404 when disabled or unknown. Links are bearer secrets stored in SQLite so the administrator can retrieve them. Do not log URL paths at the reverse proxy, export the database publicly, or place subscription routes behind interactive Google login.

Shadowrocket import and QR scanning must be tested on the user's actual app version. No claim of successful device integration is made before this test.

## Deployment gates

1. Build and inspect the React app once Node.js and package network access are available.
2. Visually verify the implementation against the supplied DESIGN-jobright.md.
3. Select the admin email and create Google OAuth credentials.
4. Verify existing VPN hostname, TLS ingress, and WebSocket path.
5. Restore Docker access to the deployment shell; test controller import and rollback with backups.
6. Integrate the dashboard hostname into the existing DNS/reverse proxy.
7. Verify real Shadowrocket import, independent user counters, disable, and rotation on two devices.

## Sources

- Xray stats: https://xtls.github.io/en/config/stats.html
- Xray policy: https://xtls.github.io/en/config/policy.html
- Xray CLI: https://xtls.github.io/en/document/command
- Google OAuth: https://developers.google.com/identity/protocols/oauth2/web-server
- Google UserInfo: https://developers.google.com/identity/openid-connect/openid-connect

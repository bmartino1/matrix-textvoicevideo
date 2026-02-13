# Matrix-Discord — Self-Hosted Chat Server

A turnkey, Docker-based Matrix server stack providing Discord-like text, voice,
and video chat. Supports 10-50 concurrent users in voice/video rooms.

## Stack

| Service       | Purpose                          | Image                              |
|---------------|----------------------------------|------------------------------------|
| **Synapse**   | Matrix homeserver                | matrixdotorg/synapse               |
| **PostgreSQL**| Database (C locale)              | postgres:16-alpine                 |
| **Element Web**| Chat UI (like Discord)          | vectorim/element-web               |
| **Element Call**| Video/Voice UI                 | ghcr.io/element-hq/element-call    |
| **LiveKit**   | WebRTC SFU (group video/voice)   | livekit/livekit-server             |
| **Coturn**    | TURN/STUN relay (NAT traversal)  | coturn/coturn                      |
| **Nginx**     | Reverse proxy + TLS              | nginx:alpine                       |
| **Certbot**   | Auto TLS renewal                 | certbot/certbot                    |

## Quick Start

```bash
# 1. Clone and run setup
chmod +x setup.sh
sudo ./setup.sh --domain chat.yourdomain.com

# 2. Start the stack
docker compose up -d

# 3. Create your first admin user
./scripts/create-user.sh admin --admin

# 4. Create regular users
./scripts/create-user.sh alice
./scripts/create-user.sh bob
```

## LAN-Only (No TLS)

```bash
sudo ./setup.sh --domain myserver.local --no-tls
```

## Admin Scripts

| Script                  | Purpose                    |
|-------------------------|----------------------------|
| `scripts/create-user.sh`   | Register new user          |
| `scripts/reset-password.sh`| Reset user password        |
| `scripts/list-users.sh`    | List all users             |
| `scripts/deactivate-user.sh`| Disable a user account   |
| `scripts/rotate-secrets.sh`| Rotate TURN/LiveKit keys  |
| `scripts/backup.sh`        | Full server backup         |
| `scripts/status.sh`        | Check service health       |

## Architecture

```
Internet → Nginx (443/80) → Element Web (chat UI)
                           → Synapse (/_matrix, /_synapse)
                           → Element Call (/call)
                           → LiveKit (/livekit-ws)
         → Coturn (3478 UDP/TCP, 5349 TLS)
         → LiveKit (50000-50200 UDP media)
```

## Security Defaults

- Registration is **disabled** — use admin scripts to create users
- PostgreSQL initialized with **C locale** (required by Synapse)
- All secrets **auto-generated** with cryptographic randomness
- Trusted key servers **empty** — fully self-hosted, no matrix.org dependency
- TURN server denies relay to **all private IP ranges**
- Rate limiting on registration, login, and messaging
- Password policy: 10+ chars, upper + lower + digit required
- Admin API restricted (configurable IP whitelist in nginx)
- No ports exposed except nginx (80/443), coturn, and LiveKit UDP

## Firewall Requirements

| Port          | Protocol | Service    | Purpose               |
|---------------|----------|------------|-----------------------|
| 80            | TCP      | Nginx      | HTTP / ACME           |
| 443           | TCP      | Nginx      | HTTPS                 |
| 3478          | UDP+TCP  | Coturn     | TURN/STUN             |
| 5349          | TCP      | Coturn     | TURNS (TLS)           |
| 49160-49250   | UDP      | Coturn     | TURN media relay      |
| 50000-50200   | UDP      | LiveKit    | WebRTC media          |

## Scaling Notes

- LiveKit SFU handles up to **50 participants** per room by default
- For 50+ users, add Redis and scale LiveKit horizontally
- Synapse workers can be added for 100+ total users
- Coturn `total-quota=300` supports ~50 concurrent TURN relays

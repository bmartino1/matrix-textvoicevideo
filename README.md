# Matrix-TextVoiceVideo — Self-Hosted Text/Voice/Video Alternative

A turnkey, Docker-based Matrix server stack providing a Discord-like text, voice,
and video chat. Supports 10-50 concurrent users in voice/video rooms.

## Stack

| Service            | Purpose                          | Image                                | IP           |
|--------------------|----------------------------------|--------------------------------------|--------------|
| **Synapse**        | Matrix homeserver                | `matrixdotorg/synapse`               | 172.42.0.3   |
| **PostgreSQL**     | Database (C locale)              | `postgres:16-alpine`                 | 172.42.0.2   |
| **Element Web**    | Chat UI (like Discord)           | `vectorim/element-web`               | 172.42.0.4   |
| **Element Call**   | Video/Voice UI                   | `ghcr.io/element-hq/element-call`    | 172.42.0.5   |
| **LiveKit**        | WebRTC SFU (group video/voice)   | `livekit/livekit-server`             | 172.42.0.6   |
| **Valkey**         | Redis-compatible cache/queue     | `valkey/valkey`                      | 172.42.0.7   |
| **LK-JWT-Service** | MatrixRTC authorization          | `ghcr.io/element-hq/lk-jwt-service` | 172.42.0.8   |
| **Coturn**         | TURN/STUN relay (NAT traversal)  | `coturn/coturn`                      | host network |
| **Nginx**          | Reverse proxy + TLS              | `nginx:alpine`                       | 172.42.0.10  |
| **Certbot**        | Auto TLS renewal                 | `certbot/certbot`                    | —            |

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/bmartino1/matrix-textvoicevideo.git
cd matrix-textvoicevideo

# 2. Run setup
chmod +x setup.sh
sudo ./setup.sh --domain chat.yourdomain.com

# 3. Start the stack
docker compose up -d

# 4. Create your first admin user
./scripts/create-user.sh admin --admin

# 5. Create regular users
./scripts/create-user.sh alice
./scripts/create-user.sh bob
```

## LAN-Only (No TLS)

```bash
sudo ./setup.sh --domain myserver.local --no-tls
```

## Specify External IP Manually

If auto-detection fails (e.g. behind a proxy):

```bash
sudo ./setup.sh --domain chat.example.com --external-ip 203.0.113.42
```

## Admin Scripts

| Script                         | Purpose                    |
|--------------------------------|----------------------------|
| `scripts/create-user.sh`      | Register new user          |
| `scripts/reset-password.sh`   | Reset user password        |
| `scripts/list-users.sh`       | List all users             |
| `scripts/deactivate-user.sh`  | Disable a user account     |
| `scripts/rotate-secrets.sh`   | Rotate TURN/LiveKit keys   |
| `scripts/backup.sh`           | Full server backup         |
| `scripts/status.sh`           | Check service health       |

All admin scripts use `scripts/load-env.sh` to safely parse the `.env` file
(handles spaces, quotes, and special characters in values).

## Architecture

```
Internet → Nginx (60443/60080) → Element Web (chat UI)
                                → Synapse (/_matrix, /_synapse)
                                → Element Call (/call)
                                → LK-JWT-Service (/livekit/jwt) → LiveKit JWT auth
                                → LiveKit SFU (/livekit/sfu)    → WebRTC signaling
         → Coturn (3478 UDP/TCP, 5349 TLS)                     → TURN relay
         → LiveKit (7881 TCP, 50000-50200 UDP)                  → WebRTC media
```

### Voice/Video Call Flow

1. User clicks "Call" in Element Web → requests OpenID token from Synapse
2. Element Call sends token to LK-JWT-Service via `/livekit/jwt/`
3. LK-JWT-Service validates against Synapse, returns LiveKit JWT
4. Client connects to LiveKit SFU with the JWT
5. LiveKit routes audio/video between participants
6. Coturn provides TURN relay for users behind strict NATs

## Security Defaults

- Registration is **disabled** — use admin scripts to create users
- PostgreSQL initialized with **C locale** (required by Synapse)
- All secrets **auto-generated** with cryptographic randomness
- `.env` values are **quoted** to prevent shell injection
- Trusted key servers **empty** — fully self-hosted, no matrix.org dependency
- TURN server denies relay to **all private IP ranges**
- Rate limiting on registration, login, and messaging
- Password policy: 10+ chars, upper + lower + digit required
- Internal service ports **commented out** by default (uncomment for debug)
- No ports exposed except Nginx, Coturn, and LiveKit UDP

## Firewall Requirements

| Port          | Protocol | Service    | Purpose               |
|---------------|----------|------------|-----------------------|
| 60080         | TCP      | Nginx      | HTTP / ACME           |
| 60443         | TCP      | Nginx      | HTTPS                 |
| 3478          | UDP+TCP  | Coturn     | TURN/STUN             |
| 5349          | TCP      | Coturn     | TURNS (TLS)           |
| 49160-49250   | UDP      | Coturn     | TURN media relay      |
| 7881          | TCP      | LiveKit    | WebRTC TCP fallback   |
| 50000-50200   | UDP      | LiveKit    | WebRTC media          |

## Unraid Notes

This stack uses `composeman` labels for Unraid Docker management. Each container
has a custom icon and the Nginx container has a WebUI link configured. Deploy
via the Unraid Compose Manager or manually with `docker compose up -d`.

## Troubleshooting

### Voice/Video calls connect but no audio/video
- Verify `EXTERNAL_IP` in `.env` is your actual public IP
- Ensure ports 7881/tcp and 50000-50200/udp are forwarded
- Check LiveKit JWT service: `curl https://yourdomain.com/livekit/jwt/healthz`
- Check Coturn ports 3478 and 5349 are reachable

### "Failed to load service worker" warning
- This is a known Element Web warning about authenticated media
- It does not affect core functionality (text, voice, video all work)

### Admin scripts show "command not found"
- Ensure you're running scripts from the project root
- The `.env` file must be generated by `setup.sh` (values are quoted)

## Scaling Notes

- LiveKit SFU handles up to **50 participants** per room by default
- Valkey enables Synapse worker support for higher throughput
- For 100+ users, add Synapse workers (stream_writers, federation_sender)
- Coturn `total-quota=300` supports ~50 concurrent TURN relays

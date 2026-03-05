Docker networks get in way on how to secure and setup with RP... Public Archiving. More porrf of concept...

2nds release was last known good tested that had meet and udp ports port forwarded...
https://github.com/bmartino1/matrix-textvoicevideo/releases/tag/Produxtion-v1

Wth a change to use pve lxc (got secure and working) and a rewrite of a lxc on unraid(wip) I decided to abanded this type of setup.


# Matrix-TextVoiceVideo

**A self-hosted, Discord-like alternative for secure text, voice, and video chat.**

Built on [Matrix](https://matrix.org) (Synapse) + [Element Web](https://element.io) + [Jitsi Meet](https://jitsi.org) + [Coturn](https://github.com/coturn/coturn). Supports **10–50 concurrent users** in voice and video rooms. Optimized for [Unraid](https://unraid.net) but runs on any Docker host.

One `setup.sh` command generates all secrets, writes all configs, and bootstraps the entire stack. One `docker compose up -d` starts everything.

See Documentation:

* Synapse (Matrix homeserver): https://matrix-org.github.io/synapse/latest/
* Element Web config: https://github.com/element-hq/element-web/blob/develop/docs/config.md
* Jitsi Self-Hosting: https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-docker
* Coturn: https://github.com/coturn/coturn/wiki/turnserver
* Matrix federation tester: https://federationtester.matrix.org/

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/bmartino1/matrix-textvoicevideo.git
cd matrix-textvoicevideo

# Run setup (generates .env, configs, certs, and docker-compose.yml)
sudo bash setup.sh --domain chat.yourdomain.com

# Start the stack
docker compose up -d

# Wait ~30 seconds, then create your first admin user
./scripts/create-user.sh admin --admin
```

Open `https://chat.yourdomain.com` in your browser.

### Unraid Quick Start

```bash
# Clone to the standard Unraid appdata location
git clone https://github.com/bmartino1/matrix-textvoicevideo.git /mnt/user/appdata/matrix-textvoicevideo
cd /mnt/user/appdata/matrix-textvoicevideo

# Run setup — auto-detects your WAN IP, generates secrets, writes all configs
sudo bash setup.sh --domain chat.yourdomain.com --reset

# Verify the generated .env looks correct
cat .env

# Start the stack
docker compose up -d

# Create your admin user
./scripts/create-user.sh admin --admin
```

Then register it in the Unraid Compose Manager web UI:

1. Go to **Docker → Compose Manager** in the Unraid web UI
2. Click **Add Stack** and point it to `/mnt/user/appdata/matrix-textvoicevideo`
3. Open the stack, click **Edit Stack**, then open both the `.env` and `docker-compose.yml` files and save them to register the stack
4. Click **Update Stack** to pull images and start containers

> **Unraid port note:** Unraid's web GUI occupies host ports 80 and 443. This stack uses 60080 and 60443 internally. Your router NAT bridges the gap: WAN 80 → Unraid 60080, WAN 443 → Unraid 60443.

### Other Distros (Debian, Ubuntu, etc.)

The setup is the same — just choose your own `--data-dir` if you don't want the Unraid default path:

```bash
sudo bash setup.sh --domain chat.example.com --data-dir /opt/matrix/data
docker compose up -d
./scripts/create-user.sh admin --admin
```

---

## Setup Options

```
sudo bash setup.sh --domain <FQDN> [options]

Required:
  --domain <FQDN>            Your fully qualified domain name

Optional:
  --external-ip <IP>         Public WAN IP (auto-detected if omitted)
  --data-dir <path>          Default: /mnt/user/appdata/matrix-textvoicevideo/data
  --admin-email <email>      For Let's Encrypt (default: admin@DOMAIN)
  --tz <timezone>            Default: America/Chicago
  --no-tls                   HTTP-only mode (LAN/testing)
  --behind-proxy             Behind NPM/Traefik/Caddy (TLS terminated externally)
  --enable-registration      Allow public user registration (default: off)
  --reset                    DESTRUCTIVE: wipe all data and start fresh
  -h, --help                 Show help
```

### Examples

```bash
# Standard production setup
sudo bash setup.sh --domain chat.example.com

# Specify public IP manually
sudo bash setup.sh --domain chat.example.com --external-ip 203.0.113.1

# LAN-only, no TLS
sudo bash setup.sh --domain myserver.local --no-tls

# Behind Nginx Proxy Manager or Traefik
sudo bash setup.sh --domain chat.example.com --behind-proxy

# Complete wipe and fresh reinstall
sudo bash setup.sh --domain chat.example.com --reset
```

> **Re-running without `--reset`** is safe — it rewrites all config files from templates while preserving your `.env`, database, and signing keys.

---

## DNS Records Required

Create these A records pointing to your public IP **before** running certbot:

```
chat.example.com    A    YOUR.PUBLIC.IP
meet.example.com    A    YOUR.PUBLIC.IP
turn.example.com    A    YOUR.PUBLIC.IP
```

---

## Port Forwarding

| WAN Port | Host Port | Protocol | Purpose |
|---|---|---|---|
| 80 | 60080 | TCP | HTTP / Let's Encrypt ACME |
| 443 | 60443 | TCP | HTTPS — Matrix + Element + Jitsi |
| 3478 | 3478 | UDP+TCP | STUN/TURN (works with self-signed certs) |
| 5349 | 5349 | TCP | TURNS over TLS (needs trusted cert) |
| 10000 | 10000 | UDP | **JVB media — required for video/audio** |
| 49160–49250 | 49160–49250 | UDP | Coturn relay range |

---

## TLS Certificates and HTTPS

### Default Mode — Self-Signed on First Run

`setup.sh` generates a self-signed certificate so the stack starts immediately. Replace with Let's Encrypt once DNS is ready:

```bash
./scripts/certbot-init.sh
```

On Unraid, the initial certbot attempt during setup will fail because Unraid owns port 80 — this is expected. The self-signed fallback lets the stack start. Run `certbot-init.sh` after the stack is up.

Auto-renew via cron (Unraid User Scripts plugin, or system crontab):

```
0 3 1 * * /mnt/user/appdata/matrix-textvoicevideo/scripts/certbot-renew.sh
```

### Behind-Proxy Mode (`--behind-proxy`)

Use when NPM, Traefik, or Caddy handles TLS. Nginx listens HTTP-only on port 60080.

```
Internet → External Proxy (TLS) → http://UNRAID_IP:60080 → nginx → services
```

In your proxy, create hosts for both `chat.example.com` and `meet.example.com` pointing to `http://UNRAID_IP:60080`. Your proxy **must** set `X-Forwarded-Proto: https`.

NPM Advanced tab example:

```nginx
proxy_set_header X-Forwarded-Proto  https;
proxy_set_header X-Real-IP          $remote_addr;
proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
proxy_set_header Host               $host;
client_max_body_size  100M;
proxy_read_timeout    600s;
```

> JVB (10000/udp) and Coturn ports still need direct NAT — they cannot be reverse-proxied.

### HTTP-Only Mode (`--no-tls`)

```bash
sudo bash setup.sh --domain myserver.local --no-tls
```

No certificates generated. For LAN-only or development. Federation and some WebRTC features won't work without HTTPS.

### Self-Signed Certificate Notes

With self-signed certs, you'll need to accept the browser warning for **both** `DOMAIN` and `meet.DOMAIN` separately. Before your first video call, visit `https://meet.DOMAIN` directly and accept the warning. TURNS (TLS TURN) won't work until you have a real cert, but plain TURN on UDP 3478 works fine.

---

## Architecture

```
Internet
    │
    ├── 80/443 ──► Nginx (60080/60443)
    │                  ├── /              ──► Element Web  (chat UI)
    │                  ├── /_matrix       ──► Synapse      (homeserver)
    │                  ├── /_synapse      ──► Synapse      (admin API)
    │                  ├── /.well-known   ──► static files
    │                  └── meet.DOMAIN    ──► Jitsi Web    (video UI)
    │
    ├── 3478/5349 ──► Coturn (TURN/STUN relay for NAT traversal)
    │
    └── 10000 UDP ──► JVB (WebRTC video/audio media bridge)

Internal network (172.42.0.0/24):
    Synapse      ──► PostgreSQL  (172.42.0.2)
    Synapse      ──► Valkey      (172.42.0.7)
    Jitsi Jicofo ──► Prosody     (172.42.0.20)
    Jitsi Web    ──► Prosody     (172.42.0.20)
    Jitsi JVB    ──► Prosody     (172.42.0.20)
```

### Stack

| Service | Purpose | Internal IP |
|---|---|---|
| **Synapse** | Matrix homeserver | 172.42.0.3 |
| **PostgreSQL** | Database (C locale, required by Synapse) | 172.42.0.2 |
| **Valkey** | Redis-compatible cache | 172.42.0.7 |
| **Element Web** | Chat UI (browser client) | 172.42.0.4 |
| **Jitsi Web** | Video conference UI | 172.42.0.22 |
| **Jitsi Prosody** | XMPP signaling | 172.42.0.20 |
| **Jitsi Jicofo** | Conference focus/coordinator | 172.42.0.21 |
| **Jitsi JVB** | WebRTC media bridge | 172.42.0.23 |
| **Coturn** | TURN/STUN relay for NAT traversal | 172.42.0.15 |
| **Nginx** | Reverse proxy + TLS termination | 172.42.0.10 |

Jitsi is locked to iframe-only access from Element — visiting `meet.DOMAIN` directly returns 403.

### Voice and Video Call Flow

1. User clicks **Video Call** in Element Web
2. Element opens a Jitsi widget pointing to `meet.DOMAIN`
3. Jitsi connects to Prosody via BOSH/WebSocket (XMPP signaling)
4. Jicofo coordinates the conference room
5. JVB routes audio and video between participants (WebRTC)
6. Coturn provides TURN relay for users behind strict NAT

---

## File Structure

```
matrix-textvoicevideo/
├── setup.sh                  ← Run this first. Generates everything below.
├── docker-compose.yml        ← GENERATED by setup.sh. Do not edit directly.
├── .env                      ← GENERATED. Contains all secrets. Never commit.
├── .env.example              ← Documents every variable (safe to commit).
├── reference/                ← TEMPLATES with __PLACEHOLDERS__
│   ├── docker-compose.yml    ← Compose template
│   ├── homeserver.yaml       ← Synapse config template
│   ├── element-config.json   ← Element Web config template
│   ├── custom-config.js      ← Jitsi Meet JS overrides
│   ├── custom-jvb.conf       ← JVB NAT/websocket config
│   ├── custom-sip-communicator.properties
│   ├── turnserver.conf       ← Coturn config
│   ├── nginx-https.conf      ← Nginx with TLS + SNI mux
│   ├── nginx-behind-proxy.conf
│   ├── nginx-no-tls.conf
│   ├── synapse-log.config
│   ├── well-known-client.json
│   └── well-known-server.json
├── scripts/                  ← Admin scripts
└── data/                     ← Runtime data (gitignored)
```

> **If you edit `docker-compose.yml` directly, the next `setup.sh` run will overwrite it.** Edit the template in `reference/` instead.

### Template → Generated Output Map

`setup.sh` reads templates from `reference/`, replaces all `__PLACEHOLDERS__` with real values, and writes the output to the correct location.

| Template | Generated Output |
|---|---|
| `reference/docker-compose.yml` | `./docker-compose.yml` |
| `reference/homeserver.yaml` | `${DATA_DIR}/synapse/appdata/homeserver.yaml` |
| `reference/element-config.json` | `${DATA_DIR}/element-web/config/config.json` |
| `reference/custom-config.js` | `${DATA_DIR}/jitsi/web/custom-config.js` |
| `reference/custom-jvb.conf` | `${DATA_DIR}/jitsi/jvb/custom-jvb.conf` |
| `reference/custom-sip-communicator.properties` | `${DATA_DIR}/jitsi/jvb/custom-sip-communicator.properties` |
| `reference/turnserver.conf` | `${DATA_DIR}/coturn/config/turnserver.conf` |
| `reference/nginx-*.conf` | `${DATA_DIR}/nginx/nginx.conf` |
| `reference/well-known-*.json` | `${DATA_DIR}/nginx/html/.well-known/matrix/*` |

---

## Admin Scripts

All scripts are in `scripts/` and read settings from `.env` automatically. Run from the project root.

| Script | Usage | Purpose |
|---|---|---|
| `create-user.sh` | `./scripts/create-user.sh <name>` | Create a regular user |
| `create-user.sh` | `./scripts/create-user.sh <name> --admin` | Create an admin user |
| `create-admin.sh` | `./scripts/create-admin.sh <name>` | Shortcut for admin creation |
| `reset-password.sh` | `./scripts/reset-password.sh <name> <token>` | Reset a user's password |
| `list-users.sh` | `./scripts/list-users.sh <token>` | List all users |
| `deactivate-user.sh` | `./scripts/deactivate-user.sh <name> <token>` | Disable a user account |
| `delete-user.sh` | `./scripts/delete-user.sh <name> <token>` | Permanently delete a user |
| `toggle-registration.sh` | `./scripts/toggle-registration.sh on\|off` | Open/close public registration |
| `status.sh` | `./scripts/status.sh` | Health check all services |
| `backup.sh` | `./scripts/backup.sh` | Full backup (DB + configs + media) |
| `restore.sh` | `./scripts/restore.sh <backup>` | Restore from backup |
| `certbot-init.sh` | `./scripts/certbot-init.sh` | Obtain Let's Encrypt certificate |
| `certbot-renew.sh` | `./scripts/certbot-renew.sh` | Renew existing certificate |
| `rotate-secrets.sh` | `./scripts/rotate-secrets.sh` | Rotate TURN + Jitsi secrets |
| `dockerlogs.sh` | `./scripts/dockerlogs.sh` | Dump all container logs to file |

**How to get your admin access token:**
Log into Element Web → click your username → **Settings** → **Help & About** → **Access Token**

### Makefile Shortcuts

```bash
make up              # docker compose up -d
make down            # docker compose down
make restart         # docker compose restart
make logs            # docker compose logs -f
make status          # ./scripts/status.sh
make ps              # docker compose ps
make create-user     # Interactive user creation
make create-admin    # Interactive admin creation
make backup          # ./scripts/backup.sh
```

---

## Backup and Restore

```bash
# Create a full backup
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh backups/TIMESTAMP/
```

> **Critical:** The `*.signing.key` file is your server's cryptographic identity for Matrix federation. Back it up regularly. If lost, remote servers can no longer verify your homeserver.

---

## Updating

```bash
./scripts/backup.sh                          # Always back up first
docker compose pull                          # Pull latest images
docker compose down && docker compose up -d  # Restart with new images
```

---

## Migrating from Older Versions

If you previously ran an older `setup.sh` that had placeholder bugs, Prosody may have cached config with literal `__MEET_DOMAIN__` strings. The current setup.sh detects and wipes contaminated Prosody config automatically.

If you still hit issues:

```bash
docker compose down
rm -rf data/jitsi/prosody/conf.d data/jitsi/prosody/data
rm -f  data/jitsi/prosody/prosody.cfg.lua
docker compose up -d
```

Or for a complete fresh start: `sudo bash setup.sh --domain your.domain.com --reset`

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| **nginx won't start** | Config syntax error | `docker compose logs matrix-nginx` |
| **"Cannot connect to homeserver"** | DNS or port forwarding | Check `nslookup` + WAN 443 → 60443 |
| Prosody `error loading private key ((null))` | Missing/wrong cert perms | Re-run `setup.sh` (copies certs, sets 640 on keys) |
| Prosody loops on `__MEET_DOMAIN__` | Stale config from old run | Auto-detected by setup.sh; or wipe `data/jitsi/prosody/` |
| Video calls connect but no audio/video | JVB port 10000/UDP not forwarded | Forward WAN 10000 → Host 10000 UDP |
| Video calls fail entirely (self-signed) | Browser doesn't trust `meet.DOMAIN` | Visit `https://meet.DOMAIN` directly, accept cert |
| TURN relay not working over TLS | Self-signed cert | Get real cert via `./scripts/certbot-init.sh`; UDP TURN still works |
| Element can't find homeserver | `.well-known` misconfigured | Check `data/nginx/html/.well-known/matrix/client` |
| Jitsi 403 on direct visit | By design (iframe-only) | Access via Element video calls |
| `docker compose up` fails on coturn cert | Cert files missing | Re-run `setup.sh` (generates self-signed fallback) |
| Federation not working | Self-signed cert untrusted | Get real cert; check `/.well-known/matrix/server` |
| Mixed content errors (behind-proxy) | Missing `X-Forwarded-Proto` | Set `proxy_set_header X-Forwarded-Proto https;` in proxy |
| Admin script says "Could not reach Synapse" | Stack not fully running | `docker compose ps` then `curl http://172.42.0.3:8008/_matrix/client/versions` |

---

## Security Defaults

- **Registration closed** by default — use `scripts/create-user.sh` or `toggle-registration.sh on`
- All secrets generated with `openssl rand` (cryptographically secure)
- `.env` is `chmod 600` — not readable by other system users
- Coturn blocks relay to all RFC 1918 private IP ranges (SSRF protection)
- No external Matrix key servers — fully self-contained federation
- TLS 1.2/1.3 only, strong cipher suites, HSTS preload header
- Jitsi iframe-gated — only accessible through Element
- Prosody private keys `chmod 640`
- Password policy: 10+ characters, upper + lower + digit required

---

## Unraid Notes

- Default data path: `/mnt/user/appdata/matrix-textvoicevideo/data`
- `chmod 777` applied to Jitsi data dirs for container compatibility; cert keys re-tightened to 640
- Synapse data `chown`-ed to UID 991:991 (container user) by `setup.sh`
- Uses `composeman` labels for Unraid Docker Manager integration
- All containers include Unraid icon labels and WebUI links
- `.env` format is fully compatible with Unraid Compose Manager — no need to uncomment `env_file` lines

---

## License

[MIT](LICENSE)

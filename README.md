# Matrix-TextVoiceVideo

**A self-hosted, Discord-like alternative for text, voice, and video chat.**
Built on [Matrix](https://matrix.org) + [Element Web](https://element.io) + [Jitsi](https://jitsi.org) + [Coturn](https://github.com/coturn/coturn). Optimised for [Unraid](https://unraid.net) but runs on any Docker host.

Supports **10–50 concurrent users** in voice and video rooms.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/bmartino1/matrix-textvoicevideo.git /mnt/user/appdata/matrix-textvoicevideo
chmod 777 -R /mnt/user/appdata/matrix-textvoicevideo
cd /mnt/user/appdata/matrix-textvoicevideo

# 2. Run setup — auto-detects IPs, generates all secrets, and writes all configs
sudo bash setup.sh --domain chat.yourdomain.com --reset
# When prompted, type:  YES  (all caps, no quotes)

# 3. Verify the generated environment file looks correct
cat .env

# 4. Start the stack
docker compose up -d

# 5. Wait ~30 seconds, then create your first admin user
./scripts/create-user.sh admin --admin
```

Open your browser at `https://chat.yourdomain.com`  
Video calls via Jitsi at `https://meet.yourdomain.com`

### Unraid Users

After running `setup.sh`, add the stack to the Unraid Compose Manager web UI so you get Docker controls, icons, and WebUI links:

1. Go to **Docker → Compose Manager** in the Unraid web UI
2. Click **Add Stack** and point it to `/mnt/user/appdata/matrix-textvoicevideo`
3. Open the stack, click **Edit Stack**, then open both the `.env` and `docker-compose.yml` files and save them to register the stack
4. Click **Update Stack** to pull images and start containers

![Unraid Compose Manager](https://github.com/user-attachments/assets/2b58492a-03eb-4d7a-833d-8ac0338aae8b)

### Other Distros (Debian, Ubuntu, etc.)

```bash
# Before starting, uncomment the env_file line in docker-compose.yml for each service:
#   # env_file: .env   ← remove the leading #

# Start the stack
docker compose up -d

# Wait ~30 seconds for Synapse and Postgres to initialize, then check health
./scripts/status.sh

# Create your first admin user
./scripts/create-user.sh admin --admin

# Create additional regular users
./scripts/create-user.sh alice
./scripts/create-user.sh bob
```

---

## Setup Options

```
sudo bash setup.sh --domain <FQDN> [OPTIONS]

Required:
  --domain <FQDN>          Your fully qualified domain name (e.g. chat.example.com)

Optional:
  --external-ip <IP>       Public WAN IP — auto-detected via curl if omitted
  --no-tls                 HTTP-only — skip all TLS/certbot entirely
                           Use for: LAN/testing, or when an external proxy on a
                           different machine handles TLS before reaching this host
  --behind-proxy           Configure nginx for internal reverse-proxy mode.
                           Nginx listens HTTP-only internally; your existing proxy
                           (NPM, Traefik, Caddy) terminates TLS upstream.
                           See: TLS Certificates and HTTPS — Behind-Proxy Mode
  --admin-email <email>    Let's Encrypt registration email (default: admin@DOMAIN)
  --data-dir <path>        Data directory (default: /mnt/user/appdata/matrix-textvoicevideo/data)
  --tz <timezone>          Timezone (default: America/Chicago)
  --reset                  DESTRUCTIVE: wipe all data and start fresh
  --enable-registration    Enable open user registration (default: disabled)
  -h, --help               Show help
```

### Examples

```bash
# Standard production setup
sudo bash setup.sh --domain chat.example.com

# Specify public IP manually (if auto-detect fails)
sudo bash setup.sh --domain chat.example.com --external-ip 203.0.113.1

# LAN-only / no internet / no TLS
sudo bash setup.sh --domain myserver.local --no-tls

# Already have NPM or Traefik handling TLS on this machine
sudo bash setup.sh --domain chat.example.com --behind-proxy

# Custom data directory (non-Unraid)
sudo bash setup.sh --domain chat.example.com --data-dir /opt/matrix/data

# Complete wipe and fresh reinstall
sudo bash setup.sh --domain chat.example.com --reset
```

> **Re-running without `--reset`** is safe and useful — it rewrites all config files with updated values while keeping your existing `.env`, database, and signing keys intact.

---

## TLS Certificates and HTTPS

This stack supports three TLS modes. Choose based on your setup:

| Mode | Flag | When to use |
|---|---|---|
| **Self-managed** | *(default)* | Nginx handles TLS directly. Certbot obtains a Let's Encrypt cert. Best for most setups. |
| **Behind external proxy** | `--behind-proxy` | Another proxy (NPM, Traefik, Caddy) sits in front of this stack and handles TLS. Nginx runs HTTP-only internally. |
| **HTTP only** | `--no-tls` | No TLS at all. Use for LAN-only, testing, or development. |

---

### Default Mode — Nginx Manages TLS

```
Internet → WAN:443 → Router NAT → Unraid:60443 → nginx (TLS termination) → services
Internet → WAN:80  → Router NAT → Unraid:60080 → nginx (ACME / redirect)
```

Nginx holds the TLS certificate and terminates HTTPS for all services. Certbot obtains and renews the certificate from Let's Encrypt.

**On Unraid**, the initial `setup.sh` certbot attempt will fail because Unraid's web GUI owns port 80. That is expected — `setup.sh` generates a self-signed certificate as a fallback so the stack can start. Once your stack is running, get a real certificate:

```bash
./scripts/certbot-init.sh
```

This script stops nginx (freeing host port 60080), runs certbot in standalone mode with `-p 60080:80` so Let's Encrypt can reach it via your router NAT, then restarts nginx with the real certificate.

**Certificate renewal** — run monthly via Unraid User Scripts plugin:

```
0 3 1 * *  /mnt/user/appdata/matrix-textvoicevideo/scripts/certbot-renew.sh
```

Or trigger manually at any time:

```bash
./scripts/certbot-renew.sh
```

**Required router port forwards for this mode:**

| WAN Port | Unraid Port | Purpose |
|---|---|---|
| 80 | 60080 | Let's Encrypt ACME challenge + HTTP redirect |
| 443 | 60443 | HTTPS — all Matrix and Jitsi traffic |

> **Why 60080/60443?** Unraid's own web GUI occupies host ports 80 and 443. This stack uses alternate host ports. Your router's NAT bridges the gap so external traffic still arrives on the standard ports.

---

### `--behind-proxy` Mode — External Reverse Proxy Handles TLS

Use this mode if you already have a reverse proxy running on the same Unraid machine (such as [Nginx Proxy Manager](https://nginxproxymanager.com/), [Traefik](https://traefik.io/), or [Caddy](https://caddyserver.com/)) that manages TLS certificates for all your services.

```
Internet
    │
    ▼ WAN :443 / :80
┌────────────────────────┐
│  External Proxy        │  ← NPM / Traefik / Caddy
│  TLS termination here  │    Manages Let's Encrypt cert
│  Listens :443 / :80    │    (on whatever host port you've assigned)
└──────────┬─────────────┘
           │ HTTP (no TLS)
           ▼ Unraid IP :60080
┌────────────────────────┐
│  This stack's nginx    │  ← HTTP-only internally
│  Listens on :60080     │    Routes to Synapse, Element, Jitsi
└────────────────────────┘
```

**Setup:**

```bash
sudo bash setup.sh --domain chat.example.com --behind-proxy
```

This writes an HTTP-only nginx config that trusts `X-Forwarded-Proto: https` from your upstream proxy.

**In your external proxy** (NPM / Traefik / Caddy), create a proxy host for `chat.example.com` pointing to:

```
http://UNRAID_IP:60080
```

You must pass these headers to the upstream:

| Header | Value |
|---|---|
| `X-Forwarded-Proto` | `https` |
| `X-Forwarded-For` | `$remote_addr` |
| `Host` | `$host` |

**NPM example** — in the *Advanced* tab of your Proxy Host, add:

```nginx
proxy_set_header X-Forwarded-Proto  https;
proxy_set_header X-Real-IP          $remote_addr;
proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
proxy_set_header Host               $host;

# Required for Matrix federation and large media uploads
client_max_body_size  100M;
proxy_read_timeout    600s;
```

Repeat for `meet.example.com` → `http://UNRAID_IP:60080` with the same headers.

> **Important:** In `--behind-proxy` mode, `setup.sh` does **not** generate TLS certificates. Your external proxy is responsible for certificates. The `/.well-known/acme-challenge/` path is still served by nginx internally in case your proxy uses the webroot challenge method.

**What about coturn (voice relay)?**  
Coturn uses its own TLS on ports 3478/5349 — these are port-forwarded directly, not through nginx or your external proxy. Coturn reads the cert from the nginx certs directory. In `--behind-proxy` mode you need to supply certs for coturn manually, or copy/symlink your external proxy's certs to:

```
data/nginx/certs/live/YOUR_DOMAIN/fullchain.pem
data/nginx/certs/live/YOUR_DOMAIN/privkey.pem
```

Then restart coturn: `docker compose restart matrix-coturn`

For full details on Synapse's reverse proxy requirements see the [official Synapse reverse proxy documentation](https://matrix-org.github.io/synapse/latest/reverse_proxy.html).

---

### `--no-tls` Mode — HTTP Only

```bash
sudo bash setup.sh --domain chat.lan --no-tls
```

Nginx listens on HTTP only. No certificates are generated or required. Use for:

- LAN-only internal deployments not exposed to the internet
- Development and testing
- When a proxy on a **different machine entirely** handles TLS before traffic arrives at this host

> **Note:** Without HTTPS, Matrix federation with other homeservers will not work. Browsers will also block some WebRTC features on non-secure origins.

---

### Replacing a Self-Signed Certificate

If `setup.sh` generated a self-signed certificate as a fallback, replace it once your DNS is propagated and your router port-forward is active:

```bash
# Ensure WAN:80 → Unraid:60080 is active in your router first
./scripts/certbot-init.sh
```

To check what certificate is currently in use:

```bash
openssl x509 -noout -issuer -in \
  /mnt/user/appdata/matrix-textvoicevideo/data/nginx/certs/live/YOUR_DOMAIN/fullchain.pem
```

Output will say `issuer=CN=Let's Encrypt` (real cert) or `issuer=CN=YOUR_DOMAIN` (self-signed).

---

## Stack

| Service | Purpose | Network |
|---|---|---|
| **Synapse** | Matrix homeserver | 172.42.0.3 |
| **PostgreSQL** | Database (C locale, required by Synapse) | 172.42.0.2 |
| **Valkey** | Redis-compatible cache | 172.42.0.7 |
| **Element Web** | Chat UI (browser client, like Discord) | 172.42.0.4 |
| **Jitsi Meet** | Video conference UI | 172.42.0.22 |
| **Jitsi Prosody** | XMPP signalling | 172.42.0.20 |
| **Jitsi Jicofo** | Conference focus/coordinator | 172.42.0.21 |
| **Jitsi JVB** | WebRTC media bridge | host network |
| **Coturn** | TURN/STUN relay for NAT traversal | host network |
| **Nginx** | Reverse proxy + TLS termination | 172.42.0.10 |
| **Certbot** | Automatic TLS certificate renewal | — |

---

## Architecture

```
Internet
    │
    ├── 80/443 ──► Nginx (60080/60443)
    │                  ├── /              ──► Element Web  (172.42.0.4)
    │                  ├── /_matrix       ──► Synapse       (172.42.0.3)
    │                  ├── /_synapse      ──► Synapse Admin (172.42.0.3)
    │                  ├── /.well-known   ──► nginx html dir
    │                  └── meet.DOMAIN    ──► Jitsi Web     (172.42.0.22)
    │
    ├── 3478/5349 ──► Coturn TURN/STUN (host network)
    │                  └── Voice relay for clients behind strict NAT
    │
    └── 10000 UDP ──► Jitsi JVB (host network)
                       └── WebRTC video/audio media bridge

Internal network (matrix-net 172.42.0.0/24):
    Synapse      ──► PostgreSQL  (172.42.0.2)
    Synapse      ──► Valkey      (172.42.0.7)
    Jitsi Jicofo ──► Prosody     (172.42.0.20)
    Jitsi Web    ──► Prosody     (172.42.0.20)  [BOSH]
    Jitsi JVB    ──► Prosody     (172.42.0.20)  [host → bridge IP]
```

### Voice and Video Call Flow

1. User clicks **Video Call** in Element Web
2. Element Web opens a Jitsi widget pointing to `meet.DOMAIN`
3. Jitsi Meet connects via WebSocket/BOSH to Prosody (XMPP signalling)
4. Jicofo coordinates the conference room
5. JVB routes audio and video between participants (WebRTC)
6. Coturn provides TURN relay for users behind strict NAT

---

## Port Forwarding (Router / Firewall)

These ports must be forwarded from your router/firewall to your Unraid server's IP address.

| Rule Name | Protocol | External Port | Internal Port | Purpose |
|---|---|---|---|---|
| nginx-443 | TCP/UDP | 443 | 60443 | HTTPS — Matrix client + Jitsi UI |
| nginx-80 | TCP/UDP | 80 | 60080 | HTTP + Let's Encrypt ACME challenge |
| Coturn-STUN-3478 | TCP/UDP | 3478 | 3478 | TURN/STUN relay for voice |
| CoturnTLS-5349 | TCP | 5349 | 5349 | TURNS over TLS |
| TURNmediarelay | UDP | 49160–49250 | 49160–49250 | Coturn media relay port range |
| jvbconference | UDP | 10000 | 10000 | Jitsi JVB WebRTC media bridge |

> **Unraid note:** Ports 80 and 443 are reserved by Unraid's web GUI.
> Map your router: **WAN 80 → Unraid:60080** and **WAN 443 → Unraid:60443**.
> The router handles the translation — your containers see 60080/60443 internally.

---

## DNS Records Required

```
chat.example.com    A    YOUR.PUBLIC.IP
meet.example.com    A    YOUR.PUBLIC.IP
```

Both `chat.DOMAIN` and `meet.DOMAIN` must have A records pointing to your public IP **before** running certbot. The Let's Encrypt certificate covers both domains.

---

## Admin Scripts

All scripts automatically read settings from the `.env` file generated by `setup.sh`. Run them from the project root directory.

| Script | Usage | Purpose |
|---|---|---|
| `scripts/create-user.sh` | `./scripts/create-user.sh <name>` | Create a regular user |
| `scripts/create-user.sh` | `./scripts/create-user.sh <name> --admin` | Create an admin user |
| `scripts/create-admin.sh` | `./scripts/create-admin.sh <name>` | Shortcut to create an admin user |
| `scripts/reset-password.sh` | `./scripts/reset-password.sh <name> <token>` | Reset a user's password |
| `scripts/list-users.sh` | `./scripts/list-users.sh <token>` | List all users (active + deactivated) |
| `scripts/deactivate-user.sh` | `./scripts/deactivate-user.sh <name> <token>` | Disable a user account |
| `scripts/toggle-registration.sh` | `./scripts/toggle-registration.sh on` | Enable open registration |
| `scripts/toggle-registration.sh` | `./scripts/toggle-registration.sh off` | Disable open registration |
| `scripts/status.sh` | `./scripts/status.sh` | Full health check of all services |
| `scripts/backup.sh` | `./scripts/backup.sh [dest]` | Full backup (DB + configs + media) |
| `scripts/restore.sh` | `./scripts/restore.sh <backup-dir>` | Restore from a backup |
| `scripts/certbot-init.sh` | `./scripts/certbot-init.sh` | Obtain initial Let's Encrypt certificate |
| `scripts/certbot-renew.sh` | `./scripts/certbot-renew.sh` | Renew existing certificate |
| `scripts/rotate-secrets.sh` | `./scripts/rotate-secrets.sh` | Rotate TURN and Jitsi secrets |

**How to get your admin access token:**  
Log into Element Web → click your username → **Settings** → **Help & About** → **Access Token**

---

## Makefile Shortcuts

```bash
make up            # Start all services
make down          # Stop all services
make restart       # Restart the stack
make logs          # Follow live logs
make status        # Run health check
make ps            # Show container status
make create-user   # Interactive user creation
make create-admin  # Interactive admin creation
make backup        # Run backup
make list-users    # List users (prompts for token)
```

---

## Unraid Notes

- The stack runs containers as root internally — `chmod 777` is applied to data directories for container compatibility
- Synapse data is additionally `chown`-ed to UID `991:991` (the Synapse container user) by `setup.sh`
- Uses `composeman` labels for Unraid Docker Manager integration
- Default data path is `/mnt/user/appdata/matrix-textvoicevideo/data`
- All containers include Unraid icon labels and WebUI link configurations
- The `.env` file format is fully compatible with Unraid Compose Manager — **no need to uncomment `env_file`** lines; Unraid loads `.env` automatically

---

## Security Defaults

- **Registration is closed by default** — use `scripts/create-user.sh` to add users, or `scripts/toggle-registration.sh on` to open it
- All secrets generated with `openssl rand` (cryptographically secure)
- `.env` is `chmod 600` — secrets are not readable by other system users
- Coturn blocks relay to all RFC 1918 private IP ranges (SSRF protection)
- No external Matrix key servers configured — fully self-contained federation
- TLS 1.2/1.3 only, strong cipher suites, HSTS preload header enabled
- If Let's Encrypt fails during setup, a self-signed certificate is automatically generated so the stack can start — replace it later by running `./scripts/certbot-init.sh` once DNS is ready

---

## Troubleshooting

### Synapse container exits immediately on first start
- Run `setup.sh` again (no `--reset`) — it bootstraps the Synapse signing key and log config
- Check logs: `docker compose logs matrix-synapse`

### "Cannot connect to homeserver"
- Check DNS: `nslookup chat.yourdomain.com` should return your public IP
- Check port forwarding: WAN 443 → Unraid:60443
- Check nginx logs: `docker compose logs matrix-nginx`

### Voice calls connect but no audio or video
- Verify `EXTERNAL_IP` in `.env` is your actual public WAN IP — not a LAN IP
- Ensure UDP 10000 is port-forwarded to your Unraid server
- Ensure UDP/TCP 3478 and TCP 5349 are port-forwarded for Coturn
- Run `./scripts/status.sh` to check which services are healthy

### Jitsi video room fails to start
- Check JVB is running: `docker compose ps jitsi-jvb`
- `JVB_ADVERTISE_IPS` in `.env` must match your public WAN IP
- Confirm UDP 10000 is open and forwarded

### Let's Encrypt certificate fails
- Port 80 must be publicly reachable from the internet (WAN 80 → Unraid:60080)
- DNS A records must already be propagated before running certbot
- On Unraid, `setup.sh` certbot will always fail (Unraid owns port 80) — this is expected
- Run `./scripts/certbot-init.sh` after the stack is up to get a real cert
- Check certbot logs: `docker compose logs matrix-certbot`

### Self-signed certificate warning in browser
- This is expected immediately after `setup.sh` on Unraid
- Run `./scripts/certbot-init.sh` to replace with a real Let's Encrypt cert
- Ensure DNS is propagated and WAN:80 → Unraid:60080 is active in your router first

### Behind-proxy mode — Matrix client gets mixed content errors
- Your external proxy must set `X-Forwarded-Proto: https` on all requests
- Verify the header is being sent: `docker compose logs matrix-nginx | grep forwarded`
- In NPM, ensure the *Advanced* tab includes `proxy_set_header X-Forwarded-Proto https;`

### Admin script reports "Could not reach Synapse"
- Ensure the full stack is running: `docker compose ps`
- Test internally: `curl http://172.42.0.3:8008/_matrix/client/versions`

---

## Backup and Restore

```bash
# Create a full backup (database + configs + signing key + media)
./scripts/backup.sh

# Restore the database
docker exec -i matrix-postgres pg_restore \
  -U synapse -d synapse < backups/TIMESTAMP/synapse.pgdump

# Restore configs
cp backups/TIMESTAMP/homeserver.yaml data/synapse/appdata/
cp backups/TIMESTAMP/dot.env .env && chmod 600 .env
docker compose restart
```

> **Critical:** The `*.signing.key` file is your server's cryptographic identity used for Matrix federation.
> Back it up regularly. If it is lost, remote federated servers cannot verify your homeserver.

---

## Updating

```bash
# Always back up before updating
./scripts/backup.sh

# Pull the latest images
docker compose pull

# Restart with the new images
docker compose down && docker compose up -d
```

---

## License

See [LICENSE](LICENSE) for details.

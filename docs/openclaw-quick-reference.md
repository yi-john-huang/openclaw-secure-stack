# OpenClaw + Cloudflare Tunnel - Quick Reference (Hybrid Deployment)

**Architecture:** Native OpenClaw (systemd) + Docker Proxy
**Domain:** https://yourdomain.com
**Date:** 2026-02-18

---

## Installation Order

```bash
# 1. Cloudflare Setup (in browser)
#    - Add domain to Cloudflare
#    - Update nameservers at registrar
#    - Wait for "Active" status

# 2. SSH to server
ssh your-username@your-server-ip

# 3. Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cloudflared
sudo install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared

# 4. Authenticate
cloudflared tunnel login
# → Opens browser, select yourdomain.com

# 5. Create tunnel
cloudflared tunnel create openclaw
# → Save the TUNNEL-ID shown in output

# 6. Create config (replace <TUNNEL-ID>)
sudo mkdir -p /etc/cloudflared
sudo tee /etc/cloudflared/config.yml > /dev/null << 'EOF'
tunnel: <TUNNEL-ID>
credentials-file: /etc/cloudflared/<TUNNEL-ID>.json
ingress:
  - hostname: yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
EOF

# 7. Edit config to replace <TUNNEL-ID>
sudo nano /etc/cloudflared/config.yml

# 8. Copy credentials (replace <TUNNEL-ID>)
sudo cp ~/.cloudflared/<TUNNEL-ID>.json /etc/cloudflared/
sudo chmod 600 /etc/cloudflared/<TUNNEL-ID>.json

# 9. Route DNS
cloudflared tunnel route dns openclaw yourdomain.com

# 10. Install & start tunnel service
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared

# 11. Run Hybrid Installer (Stable Release)
# First, sync repository to /tmp/openclaw-secure-stack/
# Then run:
cd /tmp/openclaw-secure-stack
sudo bash deploy/hybrid/install-hybrid.sh
# The installer will prompt for OAuth authentication and optionally Cloudflare Tunnel setup
```

---

## Installer Prompts

The hybrid installer will:
- Install Docker (if not present)
- Install Node.js 22 + pnpm
- Clone OpenClaw (latest stable release)
- Run `pnpm install` and `pnpm build`
- Prompt for **OpenAI OAuth authentication** (browser login)
- Build Docker proxy container
- Start both services

**Interactive prompts:**
- Domain name (for optional Cloudflare Tunnel setup)
- HDD mount point (default: `/home/openclaw-data`)
- OpenAI OAuth browser authentication

---

## Service Management

```bash
# Status
sudo systemctl status openclaw        # Native OpenClaw
docker ps                              # Docker proxy
sudo systemctl status cloudflared      # Tunnel

# Restart all
sudo systemctl restart openclaw
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml restart
sudo systemctl restart cloudflared

# Logs (follow)
sudo journalctl -u openclaw -f         # OpenClaw logs
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml logs -f proxy
sudo journalctl -u cloudflared -f      # Tunnel logs

# Stop all
sudo systemctl stop openclaw cloudflared
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml down

# Start all
sudo systemctl start openclaw cloudflared
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml up -d
```

---

## Testing

```bash
# Local health checks (on server)
curl http://127.0.0.1:3000/health  # OpenClaw Gateway (native)
curl http://127.0.0.1:8080/health  # Proxy (Docker)

# Public health (from your local machine)
curl https://yourdomain.com/health

# Get API token
ssh your-username@your-server-ip \
  "sudo grep OPENCLAW_TOKEN /opt/openclaw-secure-stack/.env | cut -d= -f2"

# Test chat API
curl -X POST https://yourdomain.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

---

## Key Files (Hybrid Deployment)

```
/opt/openclaw/                        # OpenClaw source (native, stable release)
/opt/openclaw-secure-stack/           # Proxy source + configs
  ├── docker-compose.yml              # Hybrid compose (proxy only)
  ├── .env                            # Tokens and secrets
  └── config/                         # Scanner rules, policies

/var/lib/openclaw/                    # OpenClaw data (native)
  └── .openclaw/openclaw.json         # Gateway config

/var/lib/openclaw-proxy/              # Proxy data (Docker mount)
  ├── governance.db
  ├── quarantine.db
  └── replay.db

/home/openclaw-data/                  # HDD storage
  └── openclaw-audit/                 # Audit logs

/etc/systemd/system/                  # Systemd services
  └── openclaw.service                # OpenClaw gateway (native)

/etc/cloudflared/                     # Cloudflare Tunnel
  ├── config.yml
  └── <tunnel-id>.json
```

---

## Troubleshooting

### Services won't start
```bash
# Check OpenClaw (native)
sudo journalctl -u openclaw -n 100

# Check proxy (Docker)
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml logs proxy

# Check tunnel
sudo journalctl -u cloudflared -n 100
```

### 502 Bad Gateway
```bash
# Proxy is down
docker ps  # Check if proxy container is running
curl http://127.0.0.1:8080/health
```

### 503 Service Unavailable
```bash
# Tunnel can't reach proxy
cat /etc/cloudflared/config.yml  # Verify points to localhost:8080
sudo systemctl status cloudflared
```

### Check ports
```bash
sudo lsof -i :3000  # OpenClaw (native)
sudo lsof -i :8080  # Proxy (Docker)
```

---

## Update OpenClaw (Stable Release)

```bash
cd /opt/openclaw
sudo git fetch origin --tags
sudo git checkout $(git describe --tags --abbrev=0)  # Latest release
sudo pnpm install
sudo pnpm build
sudo systemctl restart openclaw
```

---

## Update Proxy (Docker)

```bash
cd /opt/openclaw-secure-stack
git pull origin master
docker compose build proxy
docker compose up -d proxy
```

---

## Emergency Commands

```bash
# Stop everything
sudo systemctl stop openclaw cloudflared
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml down

# Check what's using ports
sudo netstat -tlnp | grep -E ':(3000|8080)'

# Kill process on port
sudo kill $(sudo lsof -t -i:8080)

# Reset failed services
sudo systemctl reset-failed

# View Docker logs
docker logs openclaw-proxy
```

---

## Architecture Summary

```
Internet → Cloudflare Edge (HTTPS)
           ↓ (Tunnel - outbound only)
           cloudflared (systemd)
           ↓ (localhost:8080)
           Proxy (Docker container, host network)
           ↓ (localhost:3000)
           OpenClaw Gateway (systemd, native)
           ↓
           LLM APIs
```

**Key Differences from Full Native:**
- ✅ Proxy runs in Docker (easier updates, isolated)
- ✅ OpenClaw runs natively (better OAuth, plugin support)
- ✅ Uses stable releases (not bleeding-edge main)
- ✅ Requires pnpm (for OpenClaw monorepo build)

---

**Full Guide:** `docs/openclaw-cloudflare-tunnel-setup.md`
**Installer:** `deploy/hybrid/install-hybrid.sh`

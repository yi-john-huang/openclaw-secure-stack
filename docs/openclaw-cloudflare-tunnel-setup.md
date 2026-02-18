# OpenClaw Secure Stack - Hybrid Deployment with Cloudflare Tunnel

**Architecture:** Native OpenClaw (systemd) + Docker Proxy
**Domain:** yourdomain.com
**Date:** 2026-02-18

---

## Overview

This guide deploys OpenClaw Secure Stack using a **hybrid approach**:
- **OpenClaw Gateway:** Native (systemd) - Better OAuth, plugin support
- **Security Proxy:** Docker container - Isolated, easy updates
- **Cloudflare Tunnel:** Private server with public HTTPS access

**No port forwarding needed!**

### Architecture Diagram

```
Internet → Cloudflare Edge (HTTPS)
            ↓ (Tunnel - outbound only)
            cloudflared daemon
            ↓ (localhost:8080)
            Docker Proxy (host network)
            ↓ (localhost:3000)
            Native OpenClaw Gateway
            ↓
            LLM APIs (OpenAI)
```

---

## Prerequisites

- [ ] Ubuntu 24.04 LTS server
- [ ] Domain name (e.g., `yourdomain.com`)
- [ ] Cloudflare account (free tier works)
- [ ] OpenAI account for OAuth
- [ ] SSH access with sudo
- [ ] Internet connection

---

## Part 1: Cloudflare Setup

### 1.1 Add Domain to Cloudflare

1. Go to https://dash.cloudflare.com
2. Click **"Add a Site"**
3. Enter your domain (e.g., `yourdomain.com`)
4. Select the **Free** plan
5. Note the nameservers shown (e.g., `ns1.cloudflare.com`)

### 1.2 Update Domain Nameservers

At your domain registrar:
1. Find DNS/Nameserver settings
2. Replace existing nameservers with Cloudflare's
3. Save changes

**Wait 5-15 minutes** for propagation. Cloudflare will email when active.

### 1.3 Verify Domain is Active

Check Cloudflare dashboard: status should show **"Active"** (not "Pending").

---

## Part 2: Cloudflare Tunnel Setup

### 2.1 SSH to Server

```bash
ssh your-username@your-server-ip
```

### 2.2 Install cloudflared

```bash
# Download cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cloudflared

# Install system-wide
sudo install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared

# Verify
cloudflared --version
```

### 2.3 Authenticate with Cloudflare

```bash
cloudflared tunnel login
```

**Steps:**
1. A URL appears (like `https://dash.cloudflare.com/argotunnel?...`)
2. Open it in your browser
3. Log in to Cloudflare
4. Select your domain
5. Click **"Authorize"**

**Result:** Credentials saved to `~/.cloudflared/cert.pem`

### 2.4 Create Tunnel

```bash
cloudflared tunnel create openclaw
```

**Output:**
```
Tunnel credentials written to /home/your-username/.cloudflared/<TUNNEL-ID>.json
Created tunnel openclaw with id <TUNNEL-ID>
```

**⚠️ Save the `<TUNNEL-ID>`** - you'll need it next!

### 2.5 Configure Tunnel

Replace `<TUNNEL-ID>` with your actual ID:

```bash
sudo mkdir -p /etc/cloudflared

sudo tee /etc/cloudflared/config.yml > /dev/null << 'EOF'
tunnel: <TUNNEL-ID>
credentials-file: /etc/cloudflared/<TUNNEL-ID>.json

ingress:
  - hostname: yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
EOF
```

**Edit to replace placeholders:**
```bash
sudo nano /etc/cloudflared/config.yml
```

Press `Ctrl+X`, `Y`, `Enter` to save.

### 2.6 Copy Credentials

Replace `<TUNNEL-ID>`:

```bash
sudo cp ~/.cloudflared/<TUNNEL-ID>.json /etc/cloudflared/
sudo chown root:root /etc/cloudflared/<TUNNEL-ID>.json
sudo chmod 600 /etc/cloudflared/<TUNNEL-ID>.json
```

### 2.7 Route DNS

```bash
cloudflared tunnel route dns openclaw yourdomain.com
```

**Output:** `Added CNAME yourdomain.com which will route to this tunnel`

### 2.8 Install as Service

```bash
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
sudo systemctl status cloudflared
```

**Expected:** `active (running)`

---

## Part 3: OpenClaw Hybrid Deployment

### 3.1 Sync Repository

Copy your `openclaw-secure-stack` repository to `/tmp/` on the server:

```bash
# From your local machine
rsync -avz --exclude='.git' --exclude='.venv' --exclude='node_modules' \
  /path/to/openclaw-secure-stack/ \
  your-username@your-server-ip:/tmp/openclaw-secure-stack/
```

### 3.2 Installer Location

The installer is included in the repository at `deploy/hybrid/install-hybrid.sh`. It will be synced to the server in the next step.

### 3.3 Clean Up (If Re-running)

```bash
# Stop any previous attempts
sudo systemctl stop openclaw 2>/dev/null || true
sudo docker compose -f /opt/openclaw-secure-stack/docker-compose.yml down 2>/dev/null || true

# Remove old installations
sudo rm -rf /opt/openclaw
sudo rm -rf /opt/openclaw-secure-stack
```

### 3.4 Run Hybrid Installer

```bash
cd /tmp/openclaw-secure-stack
sudo bash deploy/hybrid/install-hybrid.sh
```

### 3.5 What the Installer Does

**Phase 1:** Install Docker (if not present)
**Phase 2:** Install Node.js 22 + pnpm globally
**Phase 3:** Create `openclaw` system user
**Phase 4:** Create directories (`/opt/`, `/var/lib/`, `/home/openclaw-data/`)
**Phase 5:** Clone OpenClaw, checkout **latest stable release**, run `pnpm install` + `pnpm build` (~4-5 min)
**Phase 6:** **OAuth Authentication** (interactive - browser login)
**Phase 7:** Generate `.env` file with tokens
**Phase 8:** Install `openclaw.service` (systemd)
**Phase 9:** Build Docker proxy container (~2-3 min)
**Phase 10:** Start services and verify health

**Total time:** ~8-10 minutes

### 3.6 OAuth Authentication

During Phase 6, you'll see:

```
==========================================
INTERACTIVE: OpenAI OAuth Login Required
==========================================

https://platform.openai.com/activate?user_code=XXXX-YYYY
```

**Steps:**
1. Open the URL in your browser
2. Log in with your OpenAI account
3. Authorize the application
4. Return to terminal - installation continues automatically

---

## Part 4: Verification

### 4.1 Check Services

```bash
# OpenClaw (native)
sudo systemctl status openclaw

# Proxy (Docker)
docker ps

# Tunnel
sudo systemctl status cloudflared
```

All should be `active (running)` or `Up`.

### 4.2 Local Health Checks

```bash
# On the server
curl http://127.0.0.1:3000/health  # OpenClaw
curl http://127.0.0.1:8080/health  # Proxy
```

Both should return: `{"status":"healthy"}`

### 4.3 Public Health Check

**From your local machine:**

```bash
curl https://yourdomain.com/health
```

**Expected:** `{"status":"healthy"}`

### 4.4 Test Chat API

```bash
# Get the API token (on server)
ssh your-username@your-server-ip \
  "sudo grep OPENCLAW_TOKEN /opt/openclaw-secure-stack/.env | cut -d= -f2"

# Test from your local machine
TOKEN="<paste-token-here>"

curl -X POST https://yourdomain.com/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "Say hello!"}
    ]
  }'
```

**Expected:** JSON response with AI reply.

---

## Part 5: Monitoring & Maintenance

### 5.1 View Logs

```bash
# OpenClaw (native)
sudo journalctl -u openclaw -f

# Proxy (Docker)
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml logs -f proxy

# Tunnel
sudo journalctl -u cloudflared -f
```

Press `Ctrl+C` to stop.

### 5.2 Restart Services

```bash
# OpenClaw
sudo systemctl restart openclaw

# Proxy
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml restart

# Tunnel
sudo systemctl restart cloudflared
```

### 5.3 Update OpenClaw (Stable Release)

```bash
cd /opt/openclaw
sudo git fetch origin --tags
sudo git checkout $(git describe --tags --abbrev=0)  # Latest release
sudo pnpm install
sudo pnpm build
sudo systemctl restart openclaw
```

### 5.4 Update Proxy

```bash
cd /opt/openclaw-secure-stack
git pull origin master
docker compose build proxy
docker compose up -d proxy
```

---

## Part 6: Troubleshooting

### Tunnel Not Connecting

```bash
sudo systemctl status cloudflared
sudo journalctl -u cloudflared -n 100
```

**Common issues:**
- Wrong tunnel ID in `config.yml`
- Credentials file not found
- Firewall blocking outbound HTTPS (port 443)

### OpenClaw Not Starting

```bash
sudo journalctl -u openclaw -n 100
sudo lsof -i :3000  # Check if port in use
```

**Common issues:**
- pnpm dependencies not installed
- Missing OAuth credentials in `/var/lib/openclaw/.openclaw/openclaw.json`

### Proxy Not Starting

```bash
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml logs proxy
docker ps
```

**Common issues:**
- Port 8080 already in use
- Missing `.env` file

### 502 Bad Gateway

Tunnel is working but proxy is down:

```bash
docker ps  # Check if proxy container is running
curl http://127.0.0.1:8080/health
```

### 503 Service Unavailable

Tunnel can't reach proxy:

```bash
cat /etc/cloudflared/config.yml  # Verify points to localhost:8080
curl http://127.0.0.1:8080/health
```

---

## Part 7: Cloudflare Security (Optional)

### 7.1 Enable WAF

In Cloudflare Dashboard:
1. **Security** → **WAF**
2. Enable **OWASP Core Ruleset**

### 7.2 Rate Limiting

1. **Security** → **Rate Limiting Rules**
2. Create rule:
   - **If:** Hostname = `yourdomain.com`
   - **And:** Path starts with `/v1/chat/completions`
   - **Then:** Block for 60s
   - **When:** > 100 requests/min

### 7.3 IP Access Control

1. **Security** → **WAF** → **Custom Rules**
2. Allow only your IP:
   - **If:** Hostname = `yourdomain.com`
   - **And:** IP not in `<your-ip>`
   - **Then:** Block

---

## File Reference

### Key Locations

| Path | Description |
|------|-------------|
| `/opt/openclaw/` | OpenClaw source (native, stable release) |
| `/opt/openclaw-secure-stack/` | Proxy source + Docker compose |
| `/opt/openclaw-secure-stack/.env` | API token, secrets |
| `/opt/openclaw-secure-stack/docker-compose.yml` | Hybrid compose (proxy only) |
| `/var/lib/openclaw/.openclaw/openclaw.json` | Gateway config |
| `/var/lib/openclaw-proxy/` | Proxy DBs (Docker mount) |
| `/home/openclaw-data/openclaw-audit/` | Audit logs (HDD) |
| `/etc/systemd/system/openclaw.service` | OpenClaw systemd unit |
| `/etc/cloudflared/config.yml` | Tunnel config |

### Key Commands

```bash
# Service status
sudo systemctl status openclaw cloudflared
docker ps

# Restart all
sudo systemctl restart openclaw cloudflared
docker compose -f /opt/openclaw-secure-stack/docker-compose.yml restart

# Logs
sudo journalctl -u openclaw -f
docker logs -f openclaw-proxy
sudo journalctl -u cloudflared -f

# Get API token
sudo grep OPENCLAW_TOKEN /opt/openclaw-secure-stack/.env | cut -d= -f2
```

---

## Why Hybrid Deployment?

| Component | Deployment | Reason |
|-----------|------------|--------|
| **OpenClaw** | Native (systemd) | Better OAuth, plugin filesystem access, less overhead |
| **Proxy** | Docker | Isolated security layer, easy updates, portable config |
| **Release** | Stable tag | Tested, no TypeScript errors, production-ready |

**Benefits:**
- ✅ Best performance for OpenClaw (native)
- ✅ Isolated security layer (Docker proxy)
- ✅ Easy proxy updates (`docker compose build`)
- ✅ Stable, tested OpenClaw releases
- ✅ Works seamlessly with Cloudflare Tunnel

---

## Support

- **OpenClaw:** https://github.com/openclaw/openclaw/issues
- **Cloudflare Tunnel:** https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
- **Quick Reference:** `docs/openclaw-quick-reference.md`

---

**Last Updated:** 2026-02-18

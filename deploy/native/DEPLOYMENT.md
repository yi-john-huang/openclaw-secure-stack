# Native Deployment Guide: OpenClaw Secure Stack on Ubuntu 24.04 LTS

This guide covers native deployment (systemd-managed services) as an alternative to Docker Compose. Designed for systems that cannot run Docker Desktop, such as older Mac Minis or headless Linux servers.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Hardware Requirements](#hardware-requirements)
- [Pre-Installation Checklist](#pre-installation-checklist)
- [Installation](#installation)
- [Post-Installation Verification](#post-installation-verification)
- [Configuration](#configuration)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## Architecture Overview

### Service Topology

```
Internet
   ↓
Caddy (:443, 0.0.0.0) — TLS termination, reverse proxy
   ↓
OpenClaw Proxy (:8080, 127.0.0.1) — Security pipeline, governance, webhook relay
   ↓
OpenClaw Gateway (:3000, 127.0.0.1) — LLM routing, plugin execution
   ↓
LLM APIs (OpenAI, Anthropic)
```

**Key differences from Docker deployment:**

| Aspect | Docker | Native |
|--------|--------|--------|
| **Orchestration** | Docker Compose | systemd |
| **Network isolation** | Docker networks (172.28.0.0/16) | Localhost binding + UFW |
| **Process isolation** | Containers (cgroups, namespaces) | systemd sandboxing (ProtectSystem, NoNewPrivileges) |
| **Egress DNS filtering** | CoreDNS container (172.28.0.10) | None (user opted out) |
| **File paths** | `/app/data`, `/home/openclaw` | `/var/lib/openclaw-proxy`, `/var/lib/openclaw`, `/mnt/data` |

### Security Model

**Without Docker containers:**
- Services bind to `127.0.0.1` (loopback only) — not accessible from external network
- UFW firewall denies all incoming except SSH, 80, 443
- systemd sandboxing: `ProtectSystem=strict`, `NoNewPrivileges=yes`, `MemoryMax`, `RestrictAddressFamilies`
- Dedicated system users (`openclaw`, `ocproxy`) with minimal privileges
- Read-only application code, read-write data directories only where needed

**What we lose:** True network namespace isolation (no Docker network). OpenClaw has unrestricted outbound access. The **prompt-guard plugin + governance middleware** remain as the security boundary.

---

## Hardware Requirements

### Tested Configuration
**Target:** 2010 Mac Mini (Ubuntu 24.04 Server)
- **CPU:** 2 cores / 4 threads (Intel Core 2 Duo)
- **RAM:** 8GB
- **Storage:** 120GB SSD (OS, apps, DBs) + 500GB HDD (backups, audit logs)

### Minimum Requirements
- **CPU:** 2 cores (4 threads recommended)
- **RAM:** 6GB minimum, 8GB recommended
- **Storage:** 20GB SSD for OS/apps, 50GB+ secondary storage for backups/logs
- **Network:** Internet access for LLM APIs

### Storage Layout

#### SSD (120GB) — `/`
| Path | Size | Content |
|------|------|---------|
| `/opt/openclaw-secure-stack/` | ~100MB | Cloned repo (Python proxy, configs, plugin) |
| `/opt/openclaw/` | ~300MB | OpenClaw Node.js gateway installation |
| `/var/lib/openclaw/` | ~10MB | OpenClaw runtime data (`~/.openclaw/`) |
| `/var/lib/openclaw-proxy/` | ~50MB | SQLite DBs (governance, quarantine, replay) |
| `/etc/openclaw-secure-stack/` | <1MB | Environment files (secrets) |

#### HDD (500GB) — `/mnt/data`
| Path | Size | Content |
|------|------|---------|
| `/mnt/data/openclaw-audit/` | Variable | JSONL audit logs (auto-rotated, 10MB × 5) |
| `/mnt/data/backups/` | ~1GB/month | Daily SQLite + config backups (30-day retention) |

---

## Pre-Installation Checklist

### System Requirements
- [ ] **Operating System:** Ubuntu 24.04 LTS Server (headless recommended)
- [ ] **Root access:** Installation script must run as `root` or via `sudo`
- [ ] **Internet connectivity:** Required for package installation and LLM APIs
- [ ] **Secondary storage mounted:** Verify HDD is mounted at `/mnt/data` (or custom path)

### Prepare LLM API Keys
You'll need at least one:
- [ ] **OpenAI API key** — from [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- [ ] **Anthropic API key** — from [console.anthropic.com](https://console.anthropic.com/)

### Optional: Webhook Configuration
If using Telegram or WhatsApp webhooks:
- [ ] **Telegram:** Bot token from [@BotFather](https://t.me/BotFather)
- [ ] **WhatsApp:** Business API credentials (app secret, verify token, phone number ID, access token)

---

## Installation

### Step 1: Clone Repository

```bash
# As root or sudo user
cd /tmp
git clone https://github.com/yihuang/openclaw-secure-stack.git
cd openclaw-secure-stack
```

### Step 2: Run Installer

```bash
sudo bash deploy/native/install-native.sh
```

The installer runs **11 phases** automatically:

1. **Prerequisites** — Verifies Ubuntu 24.04, root access, internet connectivity
2. **System Packages** — Installs Node.js 22, Python 3.12, Caddy, uv, SQLite
3. **System Users** — Creates `openclaw` and `ocproxy` service users
4. **Directory Structure** — Sets up `/opt/`, `/var/lib/`, `/etc/`, `/mnt/data/`
5. **Deploy Code** — Clones repos, installs dependencies (`uv sync`, `npm ci`)
6. **OpenClaw Onboarding** — Interactive LLM authentication (API key or OAuth)
7. **Generate Environment Files** — Creates `/etc/openclaw-secure-stack/*.env` with secrets
8. **Install systemd Units** — Copies service files, Caddyfile, enables services
9. **Set Permissions** — Applies least-privilege ownership (`chown`, `chmod`)
10. **Firewall** — Configures UFW (allow SSH, 80, 443; deny all else)
11. **Start & Verify** — Starts services, waits for health checks, runs diagnostics

### Interactive Prompts

During installation, you'll be asked:

1. **HDD mount point** — Default: `/mnt/data` (press Enter to accept)
2. **LLM authentication:**
   - Option 1 (API key): Choose OpenAI or Anthropic, paste API key
   - Option 2 (OAuth): OpenAI browser login (not supported for Anthropic)
3. **Domain name:** Enter domain for Let's Encrypt TLS, or use localhost (self-signed)
4. **Telegram bot token** (optional)
5. **WhatsApp credentials** (optional)

### Expected Output

```
[INFO] OpenClaw Secure Stack Native Installer

=== Phase 1: Checking Prerequisites ===
[INFO] Detected Ubuntu 24.04.1 LTS ✓
[INFO] Using /mnt/data for backups and audit logs ✓

=== Phase 2: Installing System Packages ===
[INFO] Installing Node.js 22 LTS...
v22.11.0
[INFO] Installing Caddy web server...
v2.8.4
...

=== Phase 11: Starting Services ===
[INFO] Starting OpenClaw gateway...
[INFO] OpenClaw is healthy ✓
[INFO] Proxy is healthy ✓
[INFO] Caddy is running ✓

=== Installation Complete ===
```

---

## Post-Installation Verification

### 1. Check Service Status

```bash
systemctl status openclaw openclaw-proxy caddy
```

All three should show `active (running)`.

### 2. Run Health Check

```bash
/usr/local/bin/openclaw-health-check
```

Expected output:

```
=== OpenClaw Secure Stack Health Check ===

Systemd Services:
✓ openclaw is active
✓ openclaw-proxy is active
✓ caddy is active

HTTP Endpoints:
✓ OpenClaw Gateway responds at http://127.0.0.1:3000/health
✓ Proxy responds at http://127.0.0.1:8080/health
✓ Caddy (HTTPS) responds at https://localhost/health

Database Files:
✓ governance.db exists
✓ quarantine.db exists
✓ replay.db exists

Audit Logging:
✓ audit.jsonl exists
  └─ 0 audit events logged

Firewall:
✓ UFW firewall is active
✓ HTTPS (443) is allowed

=== All checks passed ===
```

### 3. Test API Call

Retrieve your API token:

```bash
grep OPENCLAW_TOKEN /etc/openclaw-secure-stack/proxy.env
```

Test the API:

```bash
curl -X POST https://localhost/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Say hello"}]
  }' \
  | jq .
```

### 4. Verify Network Isolation

From another machine on the network:

```bash
# This should FAIL (connection refused) — OpenClaw is not externally accessible
curl http://<server-ip>:3000/health

# This should SUCCEED — Caddy is the only public endpoint
curl https://<server-ip>/health
```

### 5. Check Logs

```bash
# Real-time logs
journalctl -u openclaw -f
journalctl -u openclaw-proxy -f
journalctl -u caddy -f

# Recent errors
journalctl -u openclaw -p err --since "1 hour ago"
```

---

## Configuration

### Environment Variables

Edit environment files:

```bash
# OpenClaw gateway
sudo nano /etc/openclaw-secure-stack/openclaw.env

# Proxy + governance + webhooks
sudo nano /etc/openclaw-secure-stack/proxy.env
```

**After editing, restart services:**

```bash
sudo systemctl restart openclaw openclaw-proxy
```

### OpenClaw Configuration

Edit OpenClaw's main config:

```bash
sudo -u openclaw nano /var/lib/openclaw/.openclaw/openclaw.json
```

**Important settings for native deployment:**

```json
{
  "gateway": {
    "trustedProxies": ["127.0.0.1/32"],  // Must be localhost
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    },
    "controlUi": {
      "allowInsecureAuth": false  // Keep secure in production
    }
  },
  "plugins": [
    {
      "name": "prompt-guard",
      "path": "/opt/openclaw-secure-stack/plugins/prompt-guard",
      "enabled": true
    }
  ]
}
```

After editing:

```bash
sudo systemctl restart openclaw
```

### Caddyfile

Edit Caddy reverse proxy config:

```bash
sudo nano /etc/caddy/Caddyfile
```

Reload Caddy:

```bash
sudo systemctl reload caddy
```

---

## Operations

### Daily Operations

**Check service health:**

```bash
/usr/local/bin/openclaw-health-check
```

**View recent logs:**

```bash
journalctl -u openclaw -u openclaw-proxy -u caddy --since "1 hour ago"
```

**Monitor resource usage:**

```bash
# CPU/memory per service
systemctl status openclaw openclaw-proxy caddy

# Overall system
htop
```

### Backups

**Automatic:** Daily cron job at `/etc/cron.daily/openclaw-backup` backs up:
- SQLite databases (governance, quarantine, replay)
- OpenClaw config (`openclaw.json`)
- Environment files (secrets)

Backups stored at: `/mnt/data/backups/YYYY-MM-DD.tar.gz` (30-day retention)

**Manual backup:**

```bash
sudo /etc/cron.daily/openclaw-backup
```

**Restore from backup:**

```bash
# Extract backup
cd /tmp
sudo tar -xzf /mnt/data/backups/2026-02-08.tar.gz

# Stop services
sudo systemctl stop openclaw-proxy openclaw

# Restore databases
sudo cp 2026-02-08/*.db /var/lib/openclaw-proxy/
sudo chown ocproxy:ocproxy /var/lib/openclaw-proxy/*.db

# Restore OpenClaw config
sudo cp 2026-02-08/openclaw.json /var/lib/openclaw/.openclaw/
sudo chown openclaw:openclaw /var/lib/openclaw/.openclaw/openclaw.json

# Restart services
sudo systemctl start openclaw openclaw-proxy
```

### Log Rotation

**Audit logs** (JSONL) are auto-rotated by Python's `RotatingFileHandler`:
- Max size: 10MB per file
- Backups: 5 files (50MB total)
- Path: `/mnt/data/openclaw-audit/audit.jsonl`

**systemd journal:** Managed by `journald`. To limit size:

```bash
sudo nano /etc/systemd/journald.conf

# Set:
SystemMaxUse=500M
```

Then restart:

```bash
sudo systemctl restart systemd-journald
```

### Updates

**Update OpenClaw Secure Stack:**

```bash
cd /opt/openclaw-secure-stack
sudo git pull origin master

# Restart proxy
sudo systemctl restart openclaw-proxy
```

**Update OpenClaw gateway:**

```bash
cd /opt/openclaw
sudo git fetch --tags
sudo git checkout <new-version-tag>
sudo npm ci --omit=dev
sudo npm run build

# Restart gateway
sudo systemctl restart openclaw
```

---

## Troubleshooting

### Service Won't Start

**Check status:**

```bash
sudo systemctl status openclaw
```

**View full logs:**

```bash
sudo journalctl -u openclaw -n 100 --no-pager
```

**Common issues:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Failed to bind to 127.0.0.1:3000` | Port already in use | `sudo lsof -i :3000` to find process, kill it |
| `Permission denied` | Wrong file ownership | Run Phase 9 of installer: `set_permissions()` |
| `Cannot find module` | Missing Node.js deps | `cd /opt/openclaw && sudo npm ci` |
| `MemoryDenyWriteExecute` error | Pydantic/V8 needs W+X | Edit service file, set `MemoryDenyWriteExecute=no` |

### Health Check Fails

**OpenClaw not responding:**

```bash
# Check if process is running
ps aux | grep "node dist/index.js"

# Check if listening on port
sudo ss -tlnp | grep :3000

# Restart
sudo systemctl restart openclaw
```

**Proxy not responding:**

```bash
# Check uvicorn workers
ps aux | grep uvicorn

# Check Python errors
sudo journalctl -u openclaw-proxy -p err --since "10 min ago"

# Restart
sudo systemctl restart openclaw-proxy
```

### Firewall Issues

**Cannot access from external network:**

```bash
# Check UFW status
sudo ufw status verbose

# Ensure 443 is allowed
sudo ufw allow 443/tcp

# Check if Caddy is listening on 0.0.0.0 (not 127.0.0.1)
sudo ss -tlnp | grep :443
```

**Accidentally locked out via SSH:**

If you're on the physical machine:
1. Login at console
2. `sudo ufw allow ssh`
3. `sudo ufw reload`

### Database Corruption

If SQLite DB is corrupted:

```bash
# Stop proxy
sudo systemctl stop openclaw-proxy

# Backup corrupted DB
sudo cp /var/lib/openclaw-proxy/governance.db /tmp/governance.db.corrupt

# Restore from backup
sudo cp /mnt/data/backups/YYYY-MM-DD.tar.gz /tmp/
cd /tmp && sudo tar -xzf YYYY-MM-DD.tar.gz
sudo cp YYYY-MM-DD/governance.db /var/lib/openclaw-proxy/
sudo chown ocproxy:ocproxy /var/lib/openclaw-proxy/governance.db

# Restart
sudo systemctl start openclaw-proxy
```

### Out of Memory

Check current usage:

```bash
free -h
```

If `MemAvailable` < 500MB:

1. **Reduce worker count** in `openclaw-proxy.service`:
   ```bash
   sudo nano /etc/systemd/system/openclaw-proxy.service
   # Change: --workers 2  →  --workers 1
   sudo systemctl daemon-reload
   sudo systemctl restart openclaw-proxy
   ```

2. **Lower memory limits:**
   ```bash
   # Edit service files
   sudo nano /etc/systemd/system/openclaw.service
   # Change: MemoryMax=3G  →  MemoryMax=2G

   sudo nano /etc/systemd/system/openclaw-proxy.service
   # Change: MemoryMax=2G  →  MemoryMax=1G

   sudo systemctl daemon-reload
   sudo systemctl restart openclaw openclaw-proxy
   ```

---

## Uninstallation

**Complete removal:**

```bash
sudo /opt/openclaw-secure-stack/deploy/native/uninstall.sh
```

This will:
- Stop and disable all services
- Remove systemd units
- Delete application code (`/opt/openclaw*`)
- Delete data directories (`/var/lib/openclaw*`, `/mnt/data/openclaw-audit`)
- Remove environment files (`/etc/openclaw-secure-stack`)
- Delete system users (`openclaw`, `ocproxy`)

**Manual cleanup required:**
- Backups: `/mnt/data/backups/` (not automatically deleted)
- UFW rules: `sudo ufw status numbered` → `sudo ufw delete <rule-number>`
- System packages: `sudo apt remove caddy nodejs`

---

## Comparison: Docker vs Native

| Feature | Docker Compose | Native (systemd) |
|---------|----------------|------------------|
| **Installation** | `./install.sh` | `deploy/native/install-native.sh` |
| **Prerequisites** | Docker Desktop / Podman | Ubuntu 24.04 LTS, root access |
| **Service management** | `docker compose up/down` | `systemctl start/stop/restart` |
| **Logs** | `docker compose logs -f` | `journalctl -u <service> -f` |
| **Updates** | `docker compose pull && up -d` | `git pull && systemctl restart` |
| **Backups** | Copy `.local-volumes/` | Daily cron → `/mnt/data/backups/` |
| **Network isolation** | Docker networks (strong) | Localhost + UFW (weaker) |
| **Resource limits** | Docker `mem_limit` | systemd `MemoryMax` |
| **Portability** | High (any Docker host) | Low (Ubuntu 24.04 specific) |
| **Overhead** | ~200MB Docker daemon | None (native processes) |

---

## Support

**Issues:** [github.com/yihuang/openclaw-secure-stack/issues](https://github.com/yihuang/openclaw-secure-stack/issues)

**Logs to include when reporting issues:**

```bash
# System info
uname -a
cat /etc/os-release

# Service status
systemctl status openclaw openclaw-proxy caddy

# Recent logs
sudo journalctl -u openclaw -u openclaw-proxy -u caddy --since "30 min ago" > /tmp/openclaw-logs.txt

# Health check
/usr/local/bin/openclaw-health-check
```

Attach `/tmp/openclaw-logs.txt` to your issue.

---

**End of Native Deployment Guide**

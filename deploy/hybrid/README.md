# Hybrid Deployment Installer

**One-click deployment** for OpenClaw Secure Stack with optional Cloudflare Tunnel integration.

## Architecture

- **OpenClaw Gateway**: Native (systemd) - stable release, better OAuth and plugin support
- **Security Proxy**: Docker container - isolated, easy updates
- **Cloudflare Tunnel**: Optional - public HTTPS access without port forwarding

## Usage

### Prerequisites

- Ubuntu 24.04+ server
- SSH access with sudo
- Internet connection
- (Optional) Domain name for public access

### Installation

1. **Sync repository to server:**
   ```bash
   rsync -avz --exclude='.git' --exclude='.venv' --exclude='node_modules' \
     --exclude='.local-volumes' \
     /path/to/openclaw-secure-stack/ \
     your-username@your-server-ip:/tmp/openclaw-secure-stack/
   ```

2. **Run installer:**
   ```bash
   ssh -t your-username@your-server-ip \
     "cd /tmp/openclaw-secure-stack && sudo bash deploy/hybrid/install-hybrid.sh"
   ```

The `-t` flag allocates a TTY for interactive prompts.

### Interactive Prompts

The installer will ask:

1. **Domain for public access?** (Y/N)
   - If Yes: Prompts for domain name and sets up Cloudflare Tunnel
   - If No: Local-only deployment

2. **HDD mount point** (default: `/home/openclaw-data`)
   - Where to store audit logs and backups

3. **OpenAI OAuth login**
   - Browser URL appears for authentication

### What Gets Installed

**Phase 1**: Cloudflare Tunnel (optional)
- Installs `cloudflared`
- Creates tunnel with unique ID
- Routes DNS
- Installs systemd service

**Phase 2**: Docker
- Installs Docker if not present

**Phase 3**: System packages
- Node.js 22
- pnpm

**Phase 4**: System user
- Creates `openclaw` user

**Phase 5**: Directories
- `/opt/openclaw` - OpenClaw source
- `/opt/openclaw-secure-stack` - Proxy source
- `/var/lib/openclaw` - OpenClaw data
- `/var/lib/openclaw-proxy` - Proxy data
- `/home/openclaw-data/openclaw-audit` - Audit logs (HDD)

**Phase 6**: Deploy code
- Clones OpenClaw from GitHub
- Checks out latest stable release
- Runs `pnpm install && pnpm build`
- Builds prompt-guard plugin

**Phase 7**: OpenClaw onboarding
- OAuth authentication
- Configures gateway (HTTP endpoints, trusted proxies, plugins)

**Phase 8**: Environment
- Generates `.env` with tokens

**Phase 9**: Systemd service
- Installs `openclaw.service`

**Phase 10**: Docker proxy
- Builds proxy container
- Starts with `docker compose up -d`

**Phase 11**: Verification
- Health checks for OpenClaw and proxy

## Files

- `install-hybrid.sh` - Main installer script
- `docker-compose.hybrid.yml` - Docker Compose config for proxy-only deployment

## Post-Installation

### Service Management

```bash
# Status
sudo systemctl status openclaw
docker ps
sudo systemctl status cloudflared  # If tunnel enabled

# Logs
journalctl -u openclaw -f
docker logs -f openclaw-proxy
```

### Health Checks

```bash
# Local
curl http://localhost:3000/health  # OpenClaw
curl http://localhost:8080/health  # Proxy

# Public (if tunnel enabled)
curl https://yourdomain.com/health
```

### Get API Token

```bash
sudo grep OPENCLAW_TOKEN /opt/openclaw-secure-stack/.env | cut -d= -f2
```

## Troubleshooting

See the main deployment guide: `../../docs/openclaw-cloudflare-tunnel-setup.md`

## References

- [Full Deployment Guide](../../docs/openclaw-cloudflare-tunnel-setup.md)
- [Quick Reference](../../docs/openclaw-quick-reference.md)
- [Cloudflare Tunnel Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)

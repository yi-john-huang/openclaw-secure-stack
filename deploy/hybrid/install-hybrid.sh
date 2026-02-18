#!/usr/bin/env bash
# OpenClaw Secure Stack - Hybrid Deployment Installer
# One-click setup: Cloudflare Tunnel + Native OpenClaw + Docker Proxy
#
# Usage: sudo bash deploy/hybrid/install-hybrid.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fail()  { error "$*"; exit 1; }
step()  { echo -e "${BLUE}[STEP]${NC} $*"; }

generate_token() {
    openssl rand -base64 32 | tr -d '=' 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '='
}

# =============================================================================
# Banner
# =============================================================================
show_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  OpenClaw Secure Stack - Hybrid Deployment Installer         ║"
    echo "║  Native OpenClaw + Docker Proxy + Cloudflare Tunnel          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
}

# =============================================================================
# Phase 0: Prerequisites
# =============================================================================
check_prerequisites() {
    step "=== Phase 0: Checking Prerequisites ==="

    if [ "$EUID" -ne 0 ]; then
        fail "This installer must be run as root (use sudo)"
    fi

    if [ ! -f /etc/os-release ]; then
        fail "/etc/os-release not found"
    fi

    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        fail "This installer requires Ubuntu (found: $ID)"
    fi

    local version_major
    version_major=$(echo "$VERSION_ID" | cut -d. -f1)
    if [ "$version_major" -lt 24 ]; then
        fail "This installer requires Ubuntu 24.04+ (found: $VERSION_ID)"
    fi

    info "Detected Ubuntu $VERSION_ID ✓"

    # Prompt for domain (optional - for Cloudflare Tunnel)
    echo ""
    read -rp "Do you have a domain for public access? [y/N]: " has_domain
    if [[ "$has_domain" =~ ^[Yy]$ ]]; then
        read -rp "Enter your domain name (e.g., example.com): " DOMAIN_NAME
        USE_TUNNEL=true
    else
        info "Skipping Cloudflare Tunnel - local deployment only"
        USE_TUNNEL=false
    fi

    # HDD mount point
    echo ""
    read -rp "Enter HDD mount point for backups/audit logs [default: /home/openclaw-data]: " hdd_mount
    HDD_MOUNT="${hdd_mount:-/home/openclaw-data}"

    if [ ! -d "$HDD_MOUNT" ]; then
        warn "$HDD_MOUNT does not exist"
        read -rp "Create it now? [y/N]: " create_mount
        case "$create_mount" in
            y|Y) mkdir -p "$HDD_MOUNT" ;;
            *) fail "HDD mount point required" ;;
        esac
    fi

    info "Using $HDD_MOUNT for storage ✓"
}

# =============================================================================
# Phase 1: Cloudflare Tunnel Setup (Optional)
# =============================================================================
setup_cloudflare_tunnel() {
    if [ "$USE_TUNNEL" != "true" ]; then
        return 0
    fi

    step "=== Phase 1: Cloudflare Tunnel Setup ==="

    # Install cloudflared
    if ! command -v cloudflared &>/dev/null; then
        info "Installing cloudflared..."
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  CF_ARCH="amd64" ;;
            aarch64|arm64) CF_ARCH="arm64" ;;
            *) fail "Unsupported architecture: $ARCH (only x86_64 and arm64 are supported)" ;;
        esac
        curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" \
            -o /tmp/cloudflared
        install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared
        rm /tmp/cloudflared
    fi
    info "cloudflared: $(cloudflared --version | head -1) ✓"

    # Authenticate
    echo ""
    warn "=========================================="
    warn "INTERACTIVE: Cloudflare Authentication"
    warn "=========================================="
    echo ""
    info "A browser URL will appear. Open it to authenticate."
    info "Select '$DOMAIN_NAME' from the domain list."
    echo ""
    read -rp "Press Enter when ready to authenticate..."

    cloudflared tunnel login

    info "Cloudflare authentication complete ✓"

    # Create tunnel
    echo ""
    info "Creating Cloudflare Tunnel..."

    TUNNEL_NAME="openclaw-$(date +%s)"
    TUNNEL_OUTPUT=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1)

    # Extract tunnel ID
    TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | grep -oP 'Created tunnel \K[a-f0-9-]+' || \
                echo "$TUNNEL_OUTPUT" | grep -oP 'with id \K[a-f0-9-]+')

    if [ -z "$TUNNEL_ID" ]; then
        error "Failed to extract tunnel ID. Output:"
        echo "$TUNNEL_OUTPUT"
        fail "Tunnel creation failed"
    fi

    info "Tunnel created: $TUNNEL_NAME (ID: $TUNNEL_ID) ✓"

    # Create tunnel config
    mkdir -p /etc/cloudflared

    cat > /etc/cloudflared/config.yml <<EOF
tunnel: $TUNNEL_ID
credentials-file: /etc/cloudflared/$TUNNEL_ID.json

ingress:
  - hostname: $DOMAIN_NAME
    service: http://localhost:8080
  - service: http_status:404
EOF

    # Copy credentials
    cp "$HOME/.cloudflared/$TUNNEL_ID.json" /etc/cloudflared/
    chmod 600 /etc/cloudflared/$TUNNEL_ID.json

    info "Tunnel config created ✓"

    # Route DNS
    info "Routing DNS for $DOMAIN_NAME..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN_NAME" || \
        warn "DNS routing failed - you may need to configure it manually in Cloudflare"

    # Install service
    cloudflared service install
    systemctl enable cloudflared
    systemctl start cloudflared

    info "Cloudflare Tunnel installed and started ✓"
    echo ""
    info "Public URL: https://$DOMAIN_NAME"
    echo ""
}

# =============================================================================
# Phase 2: Install Docker
# =============================================================================
install_docker() {
    step "=== Phase 2: Installing Docker ==="

    if ! command -v docker &>/dev/null; then
        info "Installing Docker..."
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sh /tmp/get-docker.sh
        rm /tmp/get-docker.sh
    else
        info "Docker already installed ✓"
    fi

    docker --version
}

# =============================================================================
# Phase 3: System Packages
# =============================================================================
install_system_packages() {
    step "=== Phase 3: Installing System Packages ==="

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl git build-essential ca-certificates gnupg rsync

    # Node.js 22
    if ! command -v node &>/dev/null; then
        info "Installing Node.js 22..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y -qq nodejs
    fi
    info "Node.js: $(node --version) ✓"

    # pnpm
    if ! command -v pnpm &>/dev/null; then
        info "Installing pnpm..."
        npm install -g pnpm
    fi
    info "pnpm: $(pnpm --version) ✓"
}

# =============================================================================
# Phase 4: Create User
# =============================================================================
create_system_user() {
    step "=== Phase 4: Creating System User ==="

    if ! id openclaw &>/dev/null; then
        useradd --system --shell /usr/sbin/nologin \
            --home-dir /var/lib/openclaw --create-home openclaw
        info "Created user: openclaw ✓"
    else
        info "User openclaw already exists ✓"
    fi
}

# =============================================================================
# Phase 5: Directories
# =============================================================================
create_directories() {
    step "=== Phase 5: Creating Directories ==="

    mkdir -p /opt/openclaw
    mkdir -p /var/lib/openclaw/.openclaw
    mkdir -p /var/lib/openclaw-proxy
    mkdir -p "$HDD_MOUNT/openclaw-audit"

    chown -R openclaw:openclaw /var/lib/openclaw
    chown 65534:65534 /var/lib/openclaw-proxy
    chown 65534:65534 "$HDD_MOUNT/openclaw-audit"

    info "Directories created ✓"
}

# =============================================================================
# Phase 6: Deploy Code
# =============================================================================
deploy_code() {
    step "=== Phase 6: Deploying Code ==="

    # Determine source directory
    if [ -f "$(pwd)/pyproject.toml" ] && [ -f "$(pwd)/docker-compose.yml" ]; then
        REPO_DIR="$(pwd)"
        info "Running from openclaw-secure-stack repository ✓"
    else
        fail "Please run this script from the openclaw-secure-stack repository root"
    fi

    info "Copying to /opt/openclaw-secure-stack..."
    rsync -a --exclude='.git' --exclude='.local-volumes' --exclude='.venv' \
        "$REPO_DIR/" /opt/openclaw-secure-stack/

    # Clone OpenClaw
    if [ ! -d /opt/openclaw/.git ]; then
        info "Cloning OpenClaw..."
        git clone https://github.com/openclaw/openclaw.git /opt/openclaw
        cd /opt/openclaw
    else
        info "OpenClaw exists, updating..."
        cd /opt/openclaw
        git fetch origin --tags
    fi

    # Checkout latest stable release
    info "Finding latest stable release..."
    latest_tag=$(git describe --tags --abbrev=0 origin/main 2>/dev/null || \
                 git tag --list 'v*' --sort=-version:refname | head -1 || \
                 echo "v2026.2.15")

    info "Using OpenClaw release: $latest_tag"
    git checkout "$latest_tag"

    info "Installing dependencies with pnpm (3-4 minutes)..."
    pnpm install

    info "Building OpenClaw..."
    pnpm build

    # Build plugin
    cd /opt/openclaw-secure-stack/plugins/prompt-guard
    info "Building prompt-guard plugin..."
    npm install --omit=dev

    info "Code deployed ✓"
}

# =============================================================================
# Phase 7: OpenClaw Onboarding
# =============================================================================
onboard_openclaw() {
    step "=== Phase 7: OpenClaw Onboarding ==="

    GATEWAY_TOKEN=$(generate_token)

    cd /opt/openclaw

    echo ""
    warn "=========================================="
    warn "INTERACTIVE: OpenAI OAuth Login"
    warn "=========================================="
    echo ""
    info "A URL will appear. Open it in your browser to authenticate."
    echo ""

    sudo -u openclaw -E env HOME=/var/lib/openclaw \
        node dist/index.js onboard \
            --mode local \
            --gateway-port 3000 \
            --gateway-bind localhost \
            --gateway-auth token \
            --gateway-token "$GATEWAY_TOKEN" \
            --skip-daemon \
            --skip-channels \
            --skip-skills \
            --skip-health \
            --skip-ui \
            --auth-choice openai-codex

    echo ""
    info "OAuth complete ✓"

    # Configure OpenClaw
    info "Configuring OpenClaw..."
    sudo -u openclaw -E env HOME=/var/lib/openclaw \
        node -e "
          const fs = require('fs');
          const p = '/var/lib/openclaw/.openclaw/openclaw.json';
          const c = JSON.parse(fs.readFileSync(p, 'utf8'));
          c.gateway = c.gateway || {};
          c.gateway.http = c.gateway.http || {};
          c.gateway.http.endpoints = c.gateway.http.endpoints || {};
          c.gateway.http.endpoints.chatCompletions = { enabled: true };
          c.gateway.trustedProxies = ['127.0.0.1/32'];
          c.plugins = c.plugins || [];
          if (!c.plugins.some(function(p2) { return p2.name === 'prompt-guard'; })) {
            c.plugins.push({
              name: 'prompt-guard',
              path: '/opt/openclaw-secure-stack/plugins/prompt-guard',
              enabled: true
            });
          }
          fs.writeFileSync(p, JSON.stringify(c, null, 2));
        "

    info "OpenClaw configured ✓"
}

# =============================================================================
# Phase 8: Generate Environment
# =============================================================================
generate_env() {
    step "=== Phase 8: Generating Environment ==="

    GOV_SECRET=$(generate_token)

    cat > /opt/openclaw-secure-stack/.env <<EOF
OPENCLAW_TOKEN=${GATEWAY_TOKEN}
GOVERNANCE_SECRET=${GOV_SECRET}
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
TELEGRAM_BOT_TOKEN=
WHATSAPP_APP_SECRET=
WHATSAPP_VERIFY_TOKEN=
WHATSAPP_PHONE_NUMBER_ID=
WHATSAPP_ACCESS_TOKEN=
EOF

    chmod 600 /opt/openclaw-secure-stack/.env

    info ".env created ✓"
}

# =============================================================================
# Phase 9: Systemd Service
# =============================================================================
install_systemd_service() {
    step "=== Phase 9: Installing OpenClaw Service ==="

    cat > /etc/systemd/system/openclaw.service <<'EOF'
[Unit]
Description=OpenClaw Gateway
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=openclaw
Group=openclaw
WorkingDirectory=/opt/openclaw
Environment="HOME=/var/lib/openclaw"
Environment="NODE_ENV=production"
ExecStart=/usr/bin/node /opt/openclaw/dist/index.js gateway start
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/openclaw

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclaw

    info "Systemd service installed ✓"
}

# =============================================================================
# Phase 10: Docker Proxy
# =============================================================================
deploy_docker_proxy() {
    step "=== Phase 10: Building Docker Proxy ==="

    cd /opt/openclaw-secure-stack

    # Copy hybrid docker-compose and substitute HDD mount path
    if cp "$(dirname "$0")/docker-compose.hybrid.yml" docker-compose.yml 2>/dev/null; then
        # Substitute the HDD mount path if user chose a non-default location
        if [ "$HDD_MOUNT" != "/home/openclaw-data" ]; then
            sed -i "s|/home/openclaw-data/openclaw-audit|$HDD_MOUNT/openclaw-audit|g" docker-compose.yml
        fi
    else
        # Fallback: generate inline docker-compose with user's HDD path
        cat > docker-compose.yml <<EOF
version: '3.8'

services:
  proxy:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: openclaw-proxy
    restart: unless-stopped
    network_mode: host
    environment:
      - UPSTREAM_URL=http://127.0.0.1:3000
      - OPENCLAW_TOKEN=\${OPENCLAW_TOKEN}
      - GOVERNANCE_ENABLED=true
      - GOVERNANCE_SECRET=\${GOVERNANCE_SECRET}
      - AUDIT_LOG_PATH=/app/audit/audit.jsonl
    volumes:
      - ./config:/app/config:ro
      - /var/lib/openclaw-proxy:/app/data
      - $HDD_MOUNT/openclaw-audit:/app/audit
    user: "65534:65534"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
EOF
    fi

    info "Building proxy container (2-3 minutes)..."
    docker compose build --no-cache proxy

    info "Starting proxy container..."
    docker compose up -d

    info "Docker proxy deployed ✓"
}

# =============================================================================
# Phase 11: Start and Verify
# =============================================================================
start_and_verify() {
    step "=== Phase 11: Starting and Verifying ==="

    info "Starting OpenClaw..."
    systemctl start openclaw

    sleep 5

    # Wait for OpenClaw
    retries=0
    while [ $retries -lt 30 ]; do
        if curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        warn "OpenClaw health check timeout"
    else
        info "OpenClaw is healthy ✓"
    fi

    # Wait for proxy
    retries=0
    while [ $retries -lt 30 ]; do
        if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        warn "Proxy health check timeout"
    else
        info "Proxy is healthy ✓"
    fi
}

# =============================================================================
# Summary
# =============================================================================
show_summary() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              INSTALLATION COMPLETE!                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    info "Architecture:"
    info "  - OpenClaw: Native (systemd, stable release)"
    info "  - Proxy:    Docker container"
    if [ "$USE_TUNNEL" = "true" ]; then
        info "  - Tunnel:   Cloudflare (${DOMAIN_NAME})"
    fi
    echo ""
    info "Services:"
    info "  systemctl status openclaw"
    info "  docker ps"
    if [ "$USE_TUNNEL" = "true" ]; then
        info "  systemctl status cloudflared"
    fi
    echo ""
    info "Health Checks:"
    info "  Local:  curl http://localhost:8080/health"
    if [ "$USE_TUNNEL" = "true" ]; then
        info "  Public: curl https://$DOMAIN_NAME/health"
    fi
    echo ""
    info "API Token (SAVE THIS!):"
    echo "  $GATEWAY_TOKEN"
    echo ""
    info "Logs:"
    info "  journalctl -u openclaw -f"
    info "  docker logs -f openclaw-proxy"
    echo ""
    if [ "$USE_TUNNEL" = "true" ]; then
        info "Next Steps:"
        info "  1. Test: curl https://$DOMAIN_NAME/health"
        info "  2. Configure Cloudflare WAF/rate limiting (optional)"
    fi
    echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    show_banner
    check_prerequisites
    setup_cloudflare_tunnel
    install_docker
    install_system_packages
    create_system_user
    create_directories
    deploy_code
    onboard_openclaw
    generate_env
    install_systemd_service
    deploy_docker_proxy
    start_and_verify
    show_summary
}

main "$@"

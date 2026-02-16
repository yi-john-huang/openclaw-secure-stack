#!/usr/bin/env bash
# Native installer for OpenClaw Secure Stack on Ubuntu 24.04 LTS
# Replaces Docker Compose with systemd-managed services.
# Target: 2010 Mac Mini (2 CPU / 4 threads, 8GB RAM, 120GB SSD + 500GB HDD)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fail()  { error "$*"; exit 1; }

# Utilities
generate_token() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 32 | tr -d '='
    elif [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom | base64 | tr -d '='
    else
        fail "Cannot generate random token: no openssl or /dev/urandom"
    fi
}

sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

sed_escape_rhs() {
    printf '%s' "$1" | sed 's/[&|/\]/\\&/g'
}

# =============================================================================
# Phase 1: Prerequisites
# =============================================================================
check_prerequisites() {
    info "=== Phase 1: Checking Prerequisites ==="

    # Check root
    if [ "$EUID" -ne 0 ]; then
        fail "This installer must be run as root"
    fi

    # Check Ubuntu 24.04
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
        fail "This installer requires Ubuntu 24.04 or newer (found: $VERSION_ID)"
    fi

    info "Detected Ubuntu $VERSION_ID ✓"

    # Check internet
    if ! curl -sf https://www.google.com >/dev/null 2>&1; then
        warn "No internet connectivity detected — installation may fail"
    fi

    # Prompt for HDD mount point
    echo ""
    info "This installer expects a secondary storage device for backups and audit logs."
    read -rp "Enter HDD mount point [default: /mnt/data]: " hdd_mount
    HDD_MOUNT="${hdd_mount:-/mnt/data}"

    if [ ! -d "$HDD_MOUNT" ]; then
        warn "$HDD_MOUNT does not exist"
        read -rp "Create it now? [y/N]: " create_mount
        case "$create_mount" in
            y|Y) mkdir -p "$HDD_MOUNT" ;;
            *) fail "HDD mount point $HDD_MOUNT does not exist" ;;
        esac
    fi

    info "Using $HDD_MOUNT for backups and audit logs ✓"
}

# =============================================================================
# Phase 2: System Packages
# =============================================================================
install_system_packages() {
    info "=== Phase 2: Installing System Packages ==="

    export DEBIAN_FRONTEND=noninteractive

    info "Updating package lists..."
    apt-get update -qq

    info "Installing base packages..."
    apt-get install -y -qq \
        curl \
        git \
        build-essential \
        sqlite3 \
        python3.12 \
        python3.12-venv \
        python3-pip \
        ca-certificates \
        gnupg \
        lsb-release

    # Node.js 22 LTS from NodeSource
    info "Installing Node.js 22 LTS..."
    if ! command -v node &>/dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y -qq nodejs
    fi
    node --version

    # Caddy from official APT repo
    info "Installing Caddy web server..."
    if ! command -v caddy &>/dev/null; then
        curl -fsSL https://caddyserver.com/api/download?os=linux&arch=amd64 \
            -o /usr/bin/caddy
        chmod +x /usr/bin/caddy
        setcap CAP_NET_BIND_SERVICE=+eip /usr/bin/caddy
    fi
    caddy version

    # uv (Python package manager)
    info "Installing uv..."
    if ! command -v uv &>/dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="/root/.cargo/bin:$PATH"
    fi
    uv --version

    info "System packages installed ✓"
}

# =============================================================================
# Phase 3: System Users
# =============================================================================
create_system_users() {
    info "=== Phase 3: Creating System Users ==="

    if ! id openclaw &>/dev/null; then
        useradd --system --shell /usr/sbin/nologin \
            --home-dir /var/lib/openclaw --create-home openclaw
        info "Created user: openclaw"
    else
        info "User openclaw already exists"
    fi

    if ! id ocproxy &>/dev/null; then
        useradd --system --shell /usr/sbin/nologin \
            --home-dir /var/lib/openclaw-proxy --create-home ocproxy
        info "Created user: ocproxy"
    else
        info "User ocproxy already exists"
    fi
}

# =============================================================================
# Phase 4: Directory Structure
# =============================================================================
create_directories() {
    info "=== Phase 4: Creating Directory Structure ==="

    # SSD directories
    mkdir -p /opt/openclaw-secure-stack
    mkdir -p /opt/openclaw
    mkdir -p /var/lib/openclaw/.openclaw
    mkdir -p /var/lib/openclaw-proxy
    mkdir -p /etc/openclaw-secure-stack
    mkdir -p /var/log/caddy

    # HDD directories
    mkdir -p "$HDD_MOUNT/openclaw-audit"
    mkdir -p "$HDD_MOUNT/backups"

    info "Directory structure created ✓"
}

# =============================================================================
# Phase 5: Deploy Code
# =============================================================================
deploy_code() {
    info "=== Phase 5: Deploying Code ==="

    # Determine if we're running inside the repo or need to clone
    if [ -f "$(pwd)/pyproject.toml" ] && [ -f "$(pwd)/docker-compose.yml" ]; then
        info "Running from openclaw-secure-stack repository"
        REPO_DIR="$(pwd)"
        info "Copying repository to /opt/openclaw-secure-stack..."
        rsync -a --exclude='.git' --exclude='.local-volumes' \
            "$REPO_DIR/" /opt/openclaw-secure-stack/
    else
        info "Cloning openclaw-secure-stack repository..."
        if [ -d /opt/openclaw-secure-stack/.git ]; then
            cd /opt/openclaw-secure-stack
            git pull origin master
        else
            git clone https://github.com/yihuang/openclaw-secure-stack.git \
                /opt/openclaw-secure-stack
            cd /opt/openclaw-secure-stack
        fi
    fi

    cd /opt/openclaw-secure-stack

    # Install Python dependencies with uv
    info "Installing Python dependencies..."
    export PATH="/root/.cargo/bin:$PATH"
    uv sync --frozen --no-dev

    # Clone/update OpenClaw source
    info "Installing OpenClaw gateway..."
    if [ -d /opt/openclaw/.git ]; then
        cd /opt/openclaw
        git pull origin main
    else
        # Use latest stable release
        git clone https://github.com/openclaw/openclaw.git /opt/openclaw
        cd /opt/openclaw
        # Pin to latest release tag (query GitHub API)
        latest_tag=$(curl -s https://api.github.com/repos/openclaw/openclaw/releases/latest \
            | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -n "$latest_tag" ]; then
            info "Checking out OpenClaw $latest_tag"
            git checkout "$latest_tag"
        else
            warn "Could not determine latest release, using main branch"
        fi
    fi

    info "Building OpenClaw..."
    npm ci --omit=dev
    npm run build

    # Build prompt-guard plugin
    cd /opt/openclaw-secure-stack/plugins/prompt-guard
    if [ -f package.json ]; then
        info "Building prompt-guard plugin..."
        npm ci --omit=dev
    fi

    info "Code deployment complete ✓"
}

# =============================================================================
# Phase 6: OpenClaw Onboarding
# =============================================================================
onboard_openclaw() {
    info "=== Phase 6: OpenClaw Onboarding ==="

    echo ""
    info "OpenClaw needs credentials for an LLM provider."
    echo ""
    echo "  1) API key  — paste an OpenAI or Anthropic API key"
    echo "  2) OAuth    — interactive browser login (recommended for personal use)"
    echo ""
    read -rp "Choose auth method [1/2]: " auth_choice

    local onboard_auth_flags=()
    local openai_key=""
    local anthropic_key=""

    case "$auth_choice" in
        1)
            echo ""
            echo "  a) OpenAI"
            echo "  b) Anthropic"
            read -rp "Which provider? [a/b]: " provider_choice
            case "$provider_choice" in
                a)
                    read -rp "Enter your OpenAI API key: " openai_key
                    onboard_auth_flags=(--auth-choice openai-api-key --openai-api-key "$openai_key")
                    ;;
                b)
                    read -rp "Enter your Anthropic API key: " anthropic_key
                    onboard_auth_flags=(--auth-choice apiKey --anthropic-api-key "$anthropic_key")
                    ;;
                *)
                    fail "Unknown provider"
                    ;;
            esac
            ;;
        2)
            warn "OAuth is only available for OpenAI. Anthropic does not support OAuth."
            read -rp "Continue with OpenAI OAuth? [y/N]: " oauth_confirm
            case "$oauth_confirm" in
                y|Y) onboard_auth_flags=(--auth-choice openai-codex) ;;
                *) fail "Cancelled" ;;
            esac
            ;;
        *)
            fail "Invalid choice"
            ;;
    esac

    # Generate gateway token
    GATEWAY_TOKEN=$(generate_token)

    # Run onboarding as openclaw user
    info "Configuring OpenClaw gateway..."
    cd /opt/openclaw

    if [ "$auth_choice" = "2" ]; then
        # OAuth: interactive
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
                "${onboard_auth_flags[@]}"
    else
        # API key: non-interactive
        sudo -u openclaw -E env HOME=/var/lib/openclaw \
            node dist/index.js onboard \
                --non-interactive \
                --accept-risk \
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
                "${onboard_auth_flags[@]}"
    fi

    # Patch openclaw.json
    info "Patching openclaw.json for native deployment..."
    sudo -u openclaw -E env HOME=/var/lib/openclaw \
        node -e "
          const fs = require('fs');
          const p = '/var/lib/openclaw/.openclaw/openclaw.json';
          const c = JSON.parse(fs.readFileSync(p, 'utf8'));

          // Enable HTTP chat completions endpoint
          c.gateway = c.gateway || {};
          c.gateway.http = c.gateway.http || {};
          c.gateway.http.endpoints = c.gateway.http.endpoints || {};
          c.gateway.http.endpoints.chatCompletions = { enabled: true };

          // Set trusted proxies to localhost (native deployment)
          c.gateway.trustedProxies = ['127.0.0.1/32'];

          // Keep controlUi secure (do not enable allowInsecureAuth)
          c.gateway.controlUi = c.gateway.controlUi || {};

          // Register prompt-guard plugin
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

    # Store API keys for env file
    OPENAI_KEY="$openai_key"
    ANTHROPIC_KEY="$anthropic_key"

    info "OpenClaw onboarding complete ✓"
}

# =============================================================================
# Phase 7: Generate Environment Files
# =============================================================================
generate_env_files() {
    info "=== Phase 7: Generating Environment Files ==="

    GOV_SECRET=$(generate_token)

    # OpenClaw env
    cat > /etc/openclaw-secure-stack/openclaw.env <<EOF
# OpenClaw Gateway Environment Configuration
# Auto-generated by install-native.sh

OPENAI_API_KEY=${OPENAI_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}
PROMPT_GUARD_ENFORCEMENT=true
INDIRECT_RULES_PATH=/opt/openclaw-secure-stack/config/indirect-injection-rules.json
QUARANTINE_LIST_PATH=/opt/openclaw-secure-stack/config/quarantine-list.json
TELEGRAM_BOT_TOKEN=
EOF

    # Proxy env
    cat > /etc/openclaw-secure-stack/proxy.env <<EOF
# OpenClaw Secure Proxy Environment Configuration
# Auto-generated by install-native.sh

UPSTREAM_URL=http://127.0.0.1:3000
OPENCLAW_TOKEN=${GATEWAY_TOKEN}
RULES_PATH=/opt/openclaw-secure-stack/config/scanner-rules.json
PROMPT_RULES_PATH=/opt/openclaw-secure-stack/config/prompt-rules.json
INDIRECT_RULES_PATH=/opt/openclaw-secure-stack/config/indirect-injection-rules.json
AUDIT_LOG_PATH=${HDD_MOUNT}/openclaw-audit/audit.jsonl
GOVERNANCE_ENABLED=true
GOVERNANCE_SECRET=${GOV_SECRET}
GOVERNANCE_APPROVAL_TIMEOUT=3600
GOVERNANCE_ALLOW_SELF_APPROVAL=true
GOVERNANCE_DB_PATH=/var/lib/openclaw-proxy/governance.db
GOVERNANCE_POLICY_PATH=/opt/openclaw-secure-stack/config/governance-policies.json
GOVERNANCE_PATTERNS_PATH=/opt/openclaw-secure-stack/config/intent-patterns.json
QUARANTINE_DB_PATH=/var/lib/openclaw-proxy/quarantine.db
REPLAY_DB_PATH=/var/lib/openclaw-proxy/replay.db
TELEGRAM_BOT_TOKEN=
WHATSAPP_APP_SECRET=
WHATSAPP_VERIFY_TOKEN=
WHATSAPP_PHONE_NUMBER_ID=
WHATSAPP_ACCESS_TOKEN=
WHATSAPP_REPLAY_WINDOW_SECONDS=300
WEBHOOK_RATE_LIMIT=60
EOF

    # Optional: prompt for Telegram/WhatsApp tokens
    echo ""
    read -rp "Configure Telegram webhook? [y/N]: " telegram_choice
    if [[ "$telegram_choice" =~ ^[Yy]$ ]]; then
        read -rp "Enter Telegram bot token: " telegram_token
        sed_inplace "s|TELEGRAM_BOT_TOKEN=|TELEGRAM_BOT_TOKEN=$telegram_token|" \
            /etc/openclaw-secure-stack/openclaw.env
        sed_inplace "s|TELEGRAM_BOT_TOKEN=|TELEGRAM_BOT_TOKEN=$telegram_token|" \
            /etc/openclaw-secure-stack/proxy.env
    fi

    read -rp "Configure WhatsApp webhook? [y/N]: " whatsapp_choice
    if [[ "$whatsapp_choice" =~ ^[Yy]$ ]]; then
        read -rp "Enter WhatsApp app secret: " wa_secret
        read -rp "Enter WhatsApp verify token: " wa_verify
        read -rp "Enter WhatsApp phone number ID: " wa_phone
        read -rp "Enter WhatsApp access token: " wa_access
        sed_inplace "s|WHATSAPP_APP_SECRET=|WHATSAPP_APP_SECRET=$wa_secret|" \
            /etc/openclaw-secure-stack/proxy.env
        sed_inplace "s|WHATSAPP_VERIFY_TOKEN=|WHATSAPP_VERIFY_TOKEN=$wa_verify|" \
            /etc/openclaw-secure-stack/proxy.env
        sed_inplace "s|WHATSAPP_PHONE_NUMBER_ID=|WHATSAPP_PHONE_NUMBER_ID=$wa_phone|" \
            /etc/openclaw-secure-stack/proxy.env
        sed_inplace "s|WHATSAPP_ACCESS_TOKEN=|WHATSAPP_ACCESS_TOKEN=$wa_access|" \
            /etc/openclaw-secure-stack/proxy.env
    fi

    info "Environment files generated ✓"
}

# =============================================================================
# Phase 8: Install systemd Units + Caddyfile
# =============================================================================
install_systemd_units() {
    info "=== Phase 8: Installing systemd Units ==="

    # Copy service files
    cp /opt/openclaw-secure-stack/deploy/native/openclaw.service \
        /etc/systemd/system/
    cp /opt/openclaw-secure-stack/deploy/native/openclaw-proxy.service \
        /etc/systemd/system/
    cp /opt/openclaw-secure-stack/deploy/native/caddy.service \
        /etc/systemd/system/

    # Template HDD_MOUNT in openclaw-proxy.service
    sed_inplace "s|\${HDD_MOUNT}|$HDD_MOUNT|g" \
        /etc/systemd/system/openclaw-proxy.service

    # Create /etc/caddy/ directory (Caddy installed as binary, not APT)
    mkdir -p /etc/caddy

    # Caddyfile
    echo ""
    read -rp "Do you have a public domain name for this server? [y/N]: " domain_choice
    if [[ "$domain_choice" =~ ^[Yy]$ ]]; then
        read -rp "Enter your domain name (e.g., api.example.com): " domain_name
        cp /opt/openclaw-secure-stack/deploy/native/Caddyfile.domain \
            /etc/caddy/Caddyfile
        sed_inplace "s|{\$DOMAIN}|$domain_name|g" /etc/caddy/Caddyfile
        info "Caddyfile configured for domain: $domain_name"
    else
        cp /opt/openclaw-secure-stack/deploy/native/Caddyfile.localhost \
            /etc/caddy/Caddyfile
        info "Caddyfile configured for localhost (self-signed TLS)"
    fi

    # Reload systemd
    systemctl daemon-reload

    # Enable services
    systemctl enable openclaw
    systemctl enable openclaw-proxy
    systemctl enable caddy

    info "systemd units installed ✓"
}

# =============================================================================
# Phase 9: Set Permissions
# =============================================================================
set_permissions() {
    info "=== Phase 9: Setting Permissions ==="

    # Application directories (read-only for service users)
    chown -R root:root /opt/openclaw-secure-stack
    chown -R root:root /opt/openclaw

    # OpenClaw data (RW for openclaw user)
    chown -R openclaw:openclaw /var/lib/openclaw
    chmod 700 /var/lib/openclaw

    # Proxy data (RW for ocproxy user)
    chown -R ocproxy:ocproxy /var/lib/openclaw-proxy
    chmod 700 /var/lib/openclaw-proxy

    # HDD data
    chown -R ocproxy:ocproxy "$HDD_MOUNT/openclaw-audit"
    chmod 755 "$HDD_MOUNT/openclaw-audit"
    chown -R root:root "$HDD_MOUNT/backups"
    chmod 700 "$HDD_MOUNT/backups"

    # Environment files (least privilege)
    chown root:openclaw /etc/openclaw-secure-stack/openclaw.env
    chmod 640 /etc/openclaw-secure-stack/openclaw.env
    chown root:ocproxy /etc/openclaw-secure-stack/proxy.env
    chmod 640 /etc/openclaw-secure-stack/proxy.env

    # Caddy log directory
    chown -R caddy:caddy /var/log/caddy 2>/dev/null || chown -R root:root /var/log/caddy

    info "Permissions set ✓"
}

# =============================================================================
# Phase 10: Firewall
# =============================================================================
configure_firewall() {
    info "=== Phase 10: Configuring Firewall ==="

    if ! command -v ufw &>/dev/null; then
        info "Installing ufw..."
        apt-get install -y -qq ufw
    fi

    # Default policies
    ufw --force default deny incoming
    ufw --force default allow outgoing

    # Allow SSH (preserve existing access)
    ufw allow ssh

    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp

    # Enable firewall
    ufw --force enable

    info "Firewall configured ✓"
    ufw status
}

# =============================================================================
# Phase 11: Start & Verify
# =============================================================================
start_and_verify() {
    info "=== Phase 11: Starting Services ==="

    # Start services in order
    info "Starting OpenClaw gateway..."
    systemctl start openclaw

    # Wait for OpenClaw to be healthy
    local retries=0
    while [ $retries -lt 30 ]; do
        if curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        warn "OpenClaw did not become healthy in time"
        warn "Check logs: journalctl -u openclaw -n 50"
    else
        info "OpenClaw is healthy ✓"
    fi

    info "Starting proxy..."
    systemctl start openclaw-proxy

    retries=0
    while [ $retries -lt 30 ]; do
        if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        warn "Proxy did not become healthy in time"
        warn "Check logs: journalctl -u openclaw-proxy -n 50"
    else
        info "Proxy is healthy ✓"
    fi

    info "Starting Caddy..."
    systemctl start caddy

    sleep 2
    if systemctl is-active --quiet caddy; then
        info "Caddy is running ✓"
    else
        warn "Caddy failed to start"
        warn "Check logs: journalctl -u caddy -n 50"
    fi

    # Install operational scripts
    info "Installing operational scripts..."
    cp /opt/openclaw-secure-stack/deploy/native/openclaw-backup.sh \
        /etc/cron.daily/openclaw-backup
    chmod +x /etc/cron.daily/openclaw-backup
    # Template HDD_MOUNT in backup script
    sed_inplace "s|\${HDD_MOUNT}|$HDD_MOUNT|g" \
        /etc/cron.daily/openclaw-backup

    cp /opt/openclaw-secure-stack/deploy/native/health-check.sh \
        /usr/local/bin/openclaw-health-check
    chmod +x /usr/local/bin/openclaw-health-check
    # Template HDD_MOUNT in health check script
    sed_inplace "s|\${HDD_MOUNT}|$HDD_MOUNT|g" \
        /usr/local/bin/openclaw-health-check

    # Final health check
    echo ""
    info "Running health check..."
    /usr/local/bin/openclaw-health-check || true
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "OpenClaw Secure Stack Native Installer"
    echo ""

    check_prerequisites
    install_system_packages
    create_system_users
    create_directories
    deploy_code
    onboard_openclaw
    generate_env_files
    install_systemd_units
    set_permissions
    configure_firewall
    start_and_verify

    echo ""
    info "=== Installation Complete ==="
    echo ""
    info "OpenClaw Secure Stack is running!"
    echo ""
    info "Access:"
    info "  - Proxy health:  curl http://127.0.0.1:8080/health"
    info "  - HTTPS:         curl -k https://localhost/health"
    echo ""
    info "API token stored in: /etc/openclaw-secure-stack/proxy.env"
    echo ""
    info "Test with:"
    echo "  curl -X POST https://localhost/v1/chat/completions \\"
    echo "    -H 'Authorization: Bearer ${GATEWAY_TOKEN}' \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}]}'"
    echo ""
    info "Monitoring:"
    info "  - systemctl status openclaw openclaw-proxy caddy"
    info "  - journalctl -u openclaw -f"
    info "  - /usr/local/bin/openclaw-health-check"
    echo ""
    info "Backups: Daily at /etc/cron.daily/openclaw-backup → ${HDD_MOUNT}/backups/"
    info "Uninstall: /opt/openclaw-secure-stack/deploy/native/uninstall.sh"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Detect container runtime: docker or podman
detect_runtime() {
    if command -v docker &>/dev/null; then
        CONTAINER_RT="docker"
    elif command -v podman &>/dev/null; then
        CONTAINER_RT="podman"
        info "Docker not found — using Podman as container runtime"
    else
        error "docker or podman is required but neither is installed."
        exit 1
    fi
}

check_docker_version() {
    if [ "$CONTAINER_RT" = "podman" ]; then
        local version
        version=$(podman --version | awk '{print $NF}')
        info "Podman $version detected"
        return
    fi
    local version
    version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0.0")
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    if [ "$major" -lt 20 ] || { [ "$major" -eq 20 ] && [ "$minor" -lt 10 ]; }; then
        error "Docker >= 20.10 required (found $version)"
        exit 1
    fi
    info "Docker $version detected"
}

check_compose_version() {
    local version
    version=$($CONTAINER_RT compose version --short 2>/dev/null || echo "0.0")
    local major
    major=$(echo "$version" | cut -d. -f1)
    if [ "$major" -lt 2 ]; then
        if [ "$CONTAINER_RT" = "podman" ] && command -v podman-compose &>/dev/null; then
            version=$(podman-compose version 2>/dev/null | grep podman-compose | awk '{print $NF}')
            info "podman-compose $version detected"
            COMPOSE_CMD="podman-compose"
            return
        fi
        error "Docker Compose >= 2.0 (or podman-compose) required"
        exit 1
    fi
    info "Compose $version detected"
    COMPOSE_CMD="$CONTAINER_RT compose"
}

generate_token() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 32 | tr -d '='
    elif [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom | base64 | tr -d '='
    else
        error "Cannot generate random token: no openssl or /dev/urandom"
        exit 1
    fi
}

# Generate CoreDNS zone file from egress allowlist
generate_zone_file() {
    local allowlist="config/egress-allowlist.conf"
    local output="config/allowlist.db"

    if [ ! -f "$allowlist" ]; then
        error "$allowlist not found"
        exit 1
    fi

    {
        cat <<'ZONE_HEADER'
$ORIGIN .
@  IN SOA ns.local. admin.local. (
       1      ; serial
       3600   ; refresh
       900    ; retry
       86400  ; expire
       300    ; minimum
)
   IN NS  ns.local.

ZONE_HEADER
        while IFS= read -r domain || [ -n "$domain" ]; do
            domain=$(echo "$domain" | sed 's/#.*//' | tr -d '[:space:]')
            [ -z "$domain" ] && continue
            echo "$domain. IN A 0.0.0.0"
        done < "$allowlist"
    } > "$output"

    info "Generated DNS zone file from $allowlist ($(grep -c 'IN A' "$output") domains)"
}

sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Escape special characters for use in a sed replacement string.
sed_escape_rhs() {
    printf '%s' "$1" | sed 's/[&|/\]/\\&/g'
}

fail() { error "$*"; exit 1; }

validate_image_hardening() {
    local image="$1"
    info "Validating image hardening for $image..."

    # Check: runs as non-root (65534 = nobody, 65532 = distroless nonroot)
    local user
    user=$($CONTAINER_RT inspect --format '{{.Config.User}}' "$image" 2>/dev/null)
    if [ "$user" != "65534" ] && [ "$user" != "65532" ] && [ "$user" != "nonroot" ]; then
        fail "Image $image runs as root (user=$user)"
    fi

    # For distroless images, shell/find checks are unnecessary (no shell exists)
    # Check if image has a shell by trying to run it
    if $CONTAINER_RT run --rm --entrypoint="/bin/sh" "$image" -c "exit 0" 2>/dev/null; then
        warn "Shell present in $image - checking for SUID binaries..."
        if $CONTAINER_RT run --rm --entrypoint="" "$image" \
            find / -perm /6000 -type f 2>/dev/null | grep -q .; then
            fail "SUID/SGID binaries found in $image"
        fi
    else
        info "No shell in $image (distroless) - inherently hardened"
    fi

    info "Image hardening checks passed for $image"
}

main() {
    info "OpenClaw Secure Stack Installer"
    echo ""

    # Check prerequisites
    detect_runtime
    check_docker_version
    check_compose_version

    # Generate .env if not present
    if [ -f .env ]; then
        warn ".env already exists — not overwriting"
    else
        if [ ! -f .env.example ]; then
            error ".env.example not found"
            exit 1
        fi
        cp .env.example .env
        TOKEN=$(generate_token)
        sed_inplace "s|OPENCLAW_TOKEN=.*|OPENCLAW_TOKEN=$TOKEN|" .env
        info "Generated .env with random API token"
    fi

    # Generate DNS zone file
    generate_zone_file

    # --- LLM Auth Setup (before starting containers) ---
    echo ""
    info "=== LLM Authentication Setup ==="
    echo ""
    echo "OpenClaw needs credentials for an LLM provider."
    echo ""
    echo "  1) API key  — paste an OpenAI or Anthropic API key"
    echo "  2) OAuth    — interactive browser login (recommended for personal use)"
    echo ""
    read -rp "Choose auth method [1/2]: " auth_choice

    local onboard_auth_flags=()

    case "$auth_choice" in
        1)
            echo ""
            echo "  a) OpenAI"
            echo "  b) Anthropic"
            read -rp "Which provider? [a/b]: " provider_choice
            case "$provider_choice" in
                a)
                    read -rp "Enter your OpenAI API key: " api_key
                    sed_inplace "s|OPENAI_API_KEY=.*|OPENAI_API_KEY=$(sed_escape_rhs "$api_key")|" .env
                    onboard_auth_flags=(--auth-choice openai-api-key --openai-api-key "$api_key")
                    info "Saved OpenAI API key"
                    ;;
                b)
                    read -rp "Enter your Anthropic API key: " api_key
                    sed_inplace "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$(sed_escape_rhs "$api_key")|" .env
                    onboard_auth_flags=(--auth-choice apiKey --anthropic-api-key "$api_key")
                    info "Saved Anthropic API key"
                    ;;
                *)
                    error "Unknown provider. Please re-run install.sh."
                    exit 1
                    ;;
            esac
            ;;
        2)
            echo ""
            warn "OAuth is only available for OpenAI (Codex). Anthropic does not"
            warn "support OAuth for third-party applications — use an API key instead."
            echo ""
            read -rp "Continue with OpenAI OAuth? [y/N]: " oauth_confirm
            case "$oauth_confirm" in
                y|Y) onboard_auth_flags=(--auth-choice openai-codex) ;;
                *) error "Cancelled. Please re-run install.sh and choose option 1 for API key."; exit 1 ;;
            esac
            ;;
        *)
            error "Invalid choice. Please re-run install.sh."
            exit 1
            ;;
    esac

    # Build containers
    info "Building containers..."
    $COMPOSE_CMD build

    # Validate image hardening
    local proxy_image
    proxy_image=$($COMPOSE_CMD images proxy -q 2>/dev/null || echo "")
    if [ -n "$proxy_image" ]; then
        validate_image_hardening "$proxy_image"
    fi

    # Read token from .env
    local gateway_token
    gateway_token=$(sed -n 's/^OPENCLAW_TOKEN=//p' .env)
    local openclaw_image
    openclaw_image=$(sed -n 's/^OPENCLAW_IMAGE=//p' .env)
    openclaw_image="${openclaw_image:-ghcr.io/openclaw/openclaw:latest}"

    # Ensure the openclaw-data volume exists
    $CONTAINER_RT volume create openclaw-secure-stack_openclaw-data 2>/dev/null || true

    # Run onboard inside the openclaw image to configure credentials
    info "Configuring OpenClaw gateway..."
    if [ "$auth_choice" = "2" ]; then
        # OAuth: interactive — needs tty
        $CONTAINER_RT run --rm -it \
            --user 65534 \
            -e HOME=/home/openclaw \
            -v openclaw-secure-stack_openclaw-data:/home/openclaw/.openclaw \
            "$openclaw_image" \
            node dist/index.js onboard \
                --mode local \
                --gateway-port 3000 \
                --gateway-bind lan \
                --gateway-auth token \
                --gateway-token "$gateway_token" \
                --skip-daemon \
                --skip-channels \
                --skip-skills \
                --skip-health \
                --skip-ui \
                "${onboard_auth_flags[@]}"
    else
        # API key: non-interactive
        $CONTAINER_RT run --rm \
            --user 65534 \
            -e HOME=/home/openclaw \
            -v openclaw-secure-stack_openclaw-data:/home/openclaw/.openclaw \
            "$openclaw_image" \
            node dist/index.js onboard \
                --non-interactive \
                --accept-risk \
                --mode local \
                --gateway-port 3000 \
                --gateway-bind lan \
                --gateway-auth token \
                --gateway-token "$gateway_token" \
                --skip-daemon \
                --skip-channels \
                --skip-skills \
                --skip-health \
                --skip-ui \
                "${onboard_auth_flags[@]}"
    fi

    # Enable the OpenAI-compatible HTTP API (disabled by default)
    info "Enabling HTTP chat completions endpoint..."
    $CONTAINER_RT run --rm \
        --user 65534 \
        -e HOME=/home/openclaw \
        -v openclaw-secure-stack_openclaw-data:/home/openclaw/.openclaw \
        "$openclaw_image" \
        node -e "
          const fs = require('fs');
          const p = '/home/openclaw/.openclaw/openclaw.json';
          const c = JSON.parse(fs.readFileSync(p, 'utf8'));
          c.gateway = c.gateway || {};
          c.gateway.http = c.gateway.http || {};
          c.gateway.http.endpoints = c.gateway.http.endpoints || {};
          c.gateway.http.endpoints.chatCompletions = { enabled: true };
          c.gateway.trustedProxies = ['172.28.0.0/16'];
          c.gateway.controlUi = c.gateway.controlUi || {};
          c.gateway.controlUi.allowInsecureAuth = true;
          c.plugins = c.plugins || [];
          if (!c.plugins.some(function(p2) { return p2.name === 'prompt-guard'; })) {
            c.plugins.push({ name: 'prompt-guard', path: '/home/openclaw/plugins/prompt-guard', enabled: true });
          }
          fs.writeFileSync(p, JSON.stringify(c, null, 2));
        "

    # Start all services
    info "Starting services..."
    $COMPOSE_CMD up -d

    # Wait for openclaw to be healthy
    info "Waiting for OpenClaw gateway to be ready..."
    local retries=0
    while [ $retries -lt 30 ]; do
        if $COMPOSE_CMD ps openclaw 2>/dev/null | grep -q "(healthy)"; then
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        warn "OpenClaw gateway did not become healthy in time."
        warn "Check logs with: $COMPOSE_CMD logs openclaw"
    else
        info "OpenClaw gateway is healthy."
    fi

    echo ""
    info "=== OpenClaw Secure Stack is running! ==="
    info "Proxy:       http://localhost:${PROXY_PORT:-8080}"
    info "Health:      curl http://localhost:${PROXY_PORT:-8080}/health"
    info "API token:   stored in .env (OPENCLAW_TOKEN)"
    echo ""
    info "Test with:"
    info "  curl -X POST http://localhost:${PROXY_PORT:-8080}/v1/chat/completions \\"
    info "    -H 'Authorization: Bearer $(sed -n "s/^OPENCLAW_TOKEN=//p" .env)' \\"
    info "    -H 'Content-Type: application/json' \\"
    info "    -d '{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}]}'"
}

main "$@"

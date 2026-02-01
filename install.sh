#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_command() {
    if ! command -v "$1" &>/dev/null; then
        error "$1 is required but not installed."
        exit 1
    fi
}

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
    # 32 bytes -> 44 char base64 string
    if command -v openssl &>/dev/null; then
        openssl rand -base64 32
    elif [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom | base64
    else
        error "Cannot generate random token: no openssl or /dev/urandom"
        exit 1
    fi
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
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s|OPENCLAW_TOKEN=.*|OPENCLAW_TOKEN=$TOKEN|" .env
        else
            sed -i "s|OPENCLAW_TOKEN=.*|OPENCLAW_TOKEN=$TOKEN|" .env
        fi
        info "Generated .env with random API token"
    fi

    # Build and start
    info "Building containers..."
    $COMPOSE_CMD build

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
    fi

    echo ""
    info "OpenClaw Secure Stack is running!"
    info "Proxy available at http://localhost:${PROXY_PORT:-8080}"
    info "API token is in .env (OPENCLAW_TOKEN)"
    echo ""

    # --- LLM Auth Setup ---
    info "=== LLM Authentication Setup ==="
    echo ""
    echo "OpenClaw needs credentials for an LLM provider (OpenAI or Anthropic)."
    echo ""
    echo "  1) API key  — paste an API key (stored in .env)"
    echo "  2) OAuth    — interactive browser login (recommended for personal use)"
    echo "  3) Skip     — configure later"
    echo ""
    read -rp "Choose auth method [1/2/3]: " auth_choice

    case "$auth_choice" in
        1)
            echo ""
            echo "  a) OpenAI"
            echo "  b) Anthropic"
            read -rp "Which provider? [a/b]: " provider_choice
            case "$provider_choice" in
                a)
                    read -rp "Enter your OpenAI API key: " api_key
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        sed -i '' "s|OPENAI_API_KEY=.*|OPENAI_API_KEY=$api_key|" .env
                    else
                        sed -i "s|OPENAI_API_KEY=.*|OPENAI_API_KEY=$api_key|" .env
                    fi
                    info "Saved OpenAI API key to .env — restarting containers..."
                    $COMPOSE_CMD up -d
                    ;;
                b)
                    read -rp "Enter your Anthropic API key: " api_key
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        sed -i '' "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$api_key|" .env
                    else
                        sed -i "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$api_key|" .env
                    fi
                    info "Saved Anthropic API key to .env — restarting containers..."
                    $COMPOSE_CMD up -d
                    ;;
                *)
                    warn "Unknown provider — skipping. Edit .env manually."
                    ;;
            esac
            ;;
        2)
            echo ""
            info "Starting interactive OAuth login inside the OpenClaw container..."
            info "Follow the prompts in your browser."
            local container_name
            container_name=$($COMPOSE_CMD ps -q openclaw)
            $CONTAINER_RT exec -it "$container_name" openclaw onboard || {
                warn "OAuth setup exited with an error. You can retry with:"
                warn "  $CONTAINER_RT exec -it \$($COMPOSE_CMD ps -q openclaw) openclaw onboard"
            }
            ;;
        3|*)
            warn "Skipping LLM auth setup. Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env,"
            warn "or run OAuth later with:"
            warn "  $CONTAINER_RT exec -it \$($COMPOSE_CMD ps -q openclaw) openclaw onboard"
            ;;
    esac

    echo ""
    info "=== Verify ==="
    info "Health check:  curl http://localhost:${PROXY_PORT:-8080}/health"
    info "Chat request:  curl -H 'Authorization: Bearer <token>' http://localhost:${PROXY_PORT:-8080}/v1/chat/completions -d '{...}'"
    info "Your API token is in .env (OPENCLAW_TOKEN)"
}

main "$@"

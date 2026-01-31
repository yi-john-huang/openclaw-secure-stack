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

check_docker_version() {
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
    version=$(docker compose version --short 2>/dev/null || echo "0.0")
    local major
    major=$(echo "$version" | cut -d. -f1)
    if [ "$major" -lt 2 ]; then
        error "Docker Compose >= 2.0 required (found $version)"
        exit 1
    fi
    info "Docker Compose $version detected"
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
    check_command docker
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
    docker compose build

    info "Starting services..."
    docker compose up -d

    echo ""
    info "OpenClaw Secure Stack is running!"
    info "Proxy available at http://localhost:${PROXY_PORT:-8080}"
    info "API token is in .env (OPENCLAW_TOKEN)"
}

main "$@"

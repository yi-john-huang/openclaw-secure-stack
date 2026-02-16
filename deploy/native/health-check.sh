#!/usr/bin/env bash
# Health check script for OpenClaw Secure Stack
# Verifies all services are running and responsive.
# Install to: /usr/local/bin/openclaw-health-check (chmod +x)
# Optional: add to cron for periodic monitoring.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

fail() { echo -e "${RED}✗${NC} $*"; }
pass() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }

check_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        pass "$service is active"
        return 0
    else
        fail "$service is NOT active"
        return 1
    fi
}

check_http() {
    local name=$1
    local url=$2
    if curl -sf "$url" >/dev/null 2>&1; then
        pass "$name responds at $url"
        return 0
    else
        fail "$name does NOT respond at $url"
        return 1
    fi
}

echo "=== OpenClaw Secure Stack Health Check ==="
echo ""

all_pass=0

# Check systemd services
echo "Systemd Services:"
check_service openclaw || all_pass=1
check_service openclaw-proxy || all_pass=1
check_service caddy || all_pass=1
echo ""

# Check HTTP endpoints
echo "HTTP Endpoints:"
check_http "OpenClaw Gateway" "http://127.0.0.1:3000/health" || all_pass=1
check_http "Proxy" "http://127.0.0.1:8080/health" || all_pass=1
check_http "Caddy (HTTPS)" "https://localhost/health" || all_pass=1
echo ""

# Check database files
echo "Database Files:"
if [ -f "/var/lib/openclaw-proxy/governance.db" ]; then
    pass "governance.db exists"
else
    warn "governance.db does not exist (first run?)"
fi

if [ -f "/var/lib/openclaw-proxy/quarantine.db" ]; then
    pass "quarantine.db exists"
else
    warn "quarantine.db does not exist (first run?)"
fi

if [ -f "/var/lib/openclaw-proxy/replay.db" ]; then
    pass "replay.db exists"
else
    warn "replay.db does not exist (first run?)"
fi
echo ""

# Check audit log
echo "Audit Logging:"
if [ -f "${HDD_MOUNT}/openclaw-audit/audit.jsonl" ]; then
    pass "audit.jsonl exists"
    lines=$(wc -l < ${HDD_MOUNT}/openclaw-audit/audit.jsonl)
    echo "  └─ $lines audit events logged"
else
    warn "audit.jsonl does not exist (no traffic yet?)"
fi
echo ""

# Check firewall
echo "Firewall:"
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        pass "UFW firewall is active"
        # Check critical rules
        if ufw status | grep -qE "443/tcp.*ALLOW"; then
            pass "HTTPS (443) is allowed"
        else
            warn "HTTPS (443) rule not found"
        fi
    else
        fail "UFW firewall is INACTIVE"
        all_pass=1
    fi
else
    warn "UFW not installed"
fi
echo ""

# Overall status
if [ $all_pass -eq 0 ]; then
    echo -e "${GREEN}=== All checks passed ===${NC}"
    exit 0
else
    echo -e "${RED}=== Some checks failed ===${NC}"
    echo "Troubleshooting:"
    echo "  - Check logs: journalctl -u openclaw -u openclaw-proxy -u caddy --since '10 min ago'"
    echo "  - Restart services: systemctl restart openclaw openclaw-proxy caddy"
    exit 1
fi

#!/usr/bin/env bash
# Uninstall script for OpenClaw Secure Stack (native deployment)
# Stops services, removes systemd units, deletes data, and cleans up users.

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

echo "=== OpenClaw Secure Stack Uninstaller ==="
echo ""
warn "This will remove ALL OpenClaw data and configurations."
warn "Backups in /mnt/data/backups/ will NOT be deleted (manual cleanup required)."
echo ""
read -rp "Are you sure you want to uninstall? [y/N]: " confirm

case "$confirm" in
    y|Y) ;;
    *) echo "Cancelled."; exit 0 ;;
esac

echo ""
echo "Stopping services..."
systemctl stop openclaw-proxy || true
systemctl stop openclaw || true
systemctl stop caddy || true

echo "Disabling services..."
systemctl disable openclaw-proxy || true
systemctl disable openclaw || true

echo "Removing systemd units..."
rm -f /etc/systemd/system/openclaw.service
rm -f /etc/systemd/system/openclaw-proxy.service
systemctl daemon-reload

echo "Removing Caddyfile..."
rm -f /etc/caddy/Caddyfile

echo "Removing environment files..."
rm -rf /etc/openclaw-secure-stack

echo "Removing application directories..."
rm -rf /opt/openclaw-secure-stack
rm -rf /opt/openclaw

echo "Removing data directories..."
rm -rf /var/lib/openclaw
rm -rf /var/lib/openclaw-proxy
rm -rf /mnt/data/openclaw-audit

echo "Removing cron job..."
rm -f /etc/cron.daily/openclaw-backup

echo "Removing health check script..."
rm -f /usr/local/bin/openclaw-health-check

echo "Removing system users..."
userdel openclaw 2>/dev/null || true
userdel ocproxy 2>/dev/null || true

echo ""
echo "=== Uninstall Complete ==="
echo ""
warn "Manual cleanup required:"
warn "  - Backups: /mnt/data/backups/"
warn "  - UFW rules: ufw status numbered && ufw delete <rule-number>"
warn "  - Caddy package: apt remove caddy"
warn "  - Node.js: apt remove nodejs"
warn "  - Python 3.12 venv: (already removed with /opt/openclaw-secure-stack)"

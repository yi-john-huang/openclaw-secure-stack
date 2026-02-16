#!/usr/bin/env bash
# Daily backup script for OpenClaw Secure Stack
# Install to: /etc/cron.daily/openclaw-backup (chmod +x)
# Backs up SQLite databases and OpenClaw config to ${HDD_MOUNT}/backups/
# Retains backups for 30 days (auto-prune).

set -euo pipefail

BACKUP_DIR="${HDD_MOUNT}/backups"
RETENTION_DAYS=30
DATE=$(date +%Y-%m-%d)
BACKUP_TARGET="$BACKUP_DIR/$DATE"

# Create backup directory
mkdir -p "$BACKUP_TARGET"

echo "[$(date -Iseconds)] Starting OpenClaw Secure Stack backup..."

# Backup SQLite databases using .backup command (safe for running DBs)
for db in governance quarantine replay; do
    if [ -f "/var/lib/openclaw-proxy/${db}.db" ]; then
        sqlite3 "/var/lib/openclaw-proxy/${db}.db" ".backup '$BACKUP_TARGET/${db}.db'"
        echo "  ✓ Backed up ${db}.db"
    fi
done

# Backup OpenClaw configuration
if [ -f "/var/lib/openclaw/.openclaw/openclaw.json" ]; then
    cp "/var/lib/openclaw/.openclaw/openclaw.json" "$BACKUP_TARGET/openclaw.json"
    echo "  ✓ Backed up openclaw.json"
fi

# Backup environment files (contains secrets — restrict permissions)
if [ -f "/etc/openclaw-secure-stack/openclaw.env" ]; then
    cp "/etc/openclaw-secure-stack/openclaw.env" "$BACKUP_TARGET/openclaw.env"
    chmod 600 "$BACKUP_TARGET/openclaw.env"
    echo "  ✓ Backed up openclaw.env"
fi

if [ -f "/etc/openclaw-secure-stack/proxy.env" ]; then
    cp "/etc/openclaw-secure-stack/proxy.env" "$BACKUP_TARGET/proxy.env"
    chmod 600 "$BACKUP_TARGET/proxy.env"
    echo "  ✓ Backed up proxy.env"
fi

# Compress backup
cd "$BACKUP_DIR"
tar -czf "${DATE}.tar.gz" "$DATE"
rm -rf "$DATE"
echo "  ✓ Compressed to ${DATE}.tar.gz"

# Prune old backups (keep last 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete
echo "  ✓ Pruned backups older than $RETENTION_DAYS days"

echo "[$(date -Iseconds)] Backup completed: $BACKUP_DIR/${DATE}.tar.gz"

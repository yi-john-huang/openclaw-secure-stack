#!/bin/sh
# Generates a CoreDNS zone file from egress-allowlist.conf
# Allowed domains get forwarded; everything else returns NXDOMAIN.
set -e

ALLOWLIST="${1:-/etc/coredns/egress-allowlist.conf}"
OUTPUT="${2:-/etc/coredns/allowlist.db}"

echo ". SOA ns.local admin.local 1 3600 900 86400 300" > "$OUTPUT"
echo ". NS ns.local" >> "$OUTPUT"

while IFS= read -r domain || [ -n "$domain" ]; do
    domain=$(echo "$domain" | sed 's/#.*//' | tr -d '[:space:]')
    [ -z "$domain" ] && continue
    echo "$domain. IN A 0.0.0.0" >> "$OUTPUT"
done < "$ALLOWLIST"

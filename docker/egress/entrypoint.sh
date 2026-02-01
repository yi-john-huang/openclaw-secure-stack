#!/bin/sh
set -e

# Generate zone file from the mounted allowlist config
/bin/sh /usr/local/bin/generate-zone.sh

exec /coredns -conf /etc/coredns/Corefile

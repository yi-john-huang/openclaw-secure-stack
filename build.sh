#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-openclaw-secure-stack:latest}"

# Auto-detect container runtime
if command -v docker &>/dev/null; then
    RUNTIME=docker
elif command -v podman &>/dev/null; then
    RUNTIME=podman
else
    echo "ERROR: No container runtime found (docker or podman)" >&2
    exit 1
fi

echo "Building ${TAG} with ${RUNTIME}..."
${RUNTIME} build -t "${TAG}" .

echo ""
echo "Build complete: ${TAG}"
echo "Image size: $(${RUNTIME} image inspect "${TAG}" --format '{{.Size}}' | awk '{printf "%.1fMB", $1/1048576}')"

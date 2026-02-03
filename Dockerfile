# Stage 1: Build dependencies with uv
# Pin base image by digest for reproducible builds. Update digest periodically.
# To find latest: podman pull python:3.12-slim && podman inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:4b70b3e968be0f795f45cc2c8c159cb8034d256917573b0e8eacbc23596cd71a AS builder

ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.5.0
COPY --from=${UV_IMAGE} /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY config/ config/
RUN uv sync --frozen --no-dev

# Stage 2: Distroless runtime - no shell, no package manager, minimal attack surface
# To find latest: podman pull gcr.io/distroless/python3-debian12:nonroot && podman inspect --format='{{index .RepoDigests 0}}' gcr.io/distroless/python3-debian12:nonroot
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:17b27c84c985a53d0cd2adef4f196ca327fa9b6755369be605cf45533b4e700b AS runtime

WORKDIR /app

# Copy the venv and app code from builder
# Distroless has Python at /usr/bin/python3, we copy our venv's site-packages
COPY --from=builder /app/.venv/lib/python3.12/site-packages /app/site-packages
COPY --from=builder /app/src /app/src
COPY --from=builder /app/config /app/config

# nonroot image already runs as non-root user (65532)

ENV PYTHONPATH=/app/src:/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Use exec form - distroless has no shell
ENTRYPOINT ["python3", "-m", "uvicorn", "src.proxy.app:create_app_from_env", "--host", "0.0.0.0", "--port", "8080", "--factory"]

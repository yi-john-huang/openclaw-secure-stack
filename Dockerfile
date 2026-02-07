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

# Stage 2: Slim runtime — same Python 3.12 as builder to avoid native extension ABI mismatch.
# distroless/python3-debian12 only ships Python 3.11, which breaks pydantic_core's compiled .so files.
# To find latest digest: podman pull python:3.12-slim && podman inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim AS runtime

# Hardening: create non-root user matching distroless UID convention
RUN groupadd -g 65532 nonroot && \
    useradd -u 65532 -g 65532 -s /usr/sbin/nologin -d /app nonroot

WORKDIR /app

# Copy the venv and app code from builder
COPY --from=builder /app/.venv/lib/python3.12/site-packages /app/site-packages
COPY --from=builder /app/src /app/src
COPY --from=builder /app/config /app/config

# Drop to non-root
USER nonroot

ENV PYTHONPATH=/app/src:/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["python3", "-m", "uvicorn", "src.proxy.app:create_app_from_env", "--host", "0.0.0.0", "--port", "8080", "--factory"]

# Global ARG for uv image (must be before first FROM for use in FROM stages)
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.5.0

# Named uv stage so COPY --from can reference a stage name (variable expansion not supported in --from)
FROM ${UV_IMAGE} AS uv

# Stage 1: Build dependencies with uv
# Base image is not pinned by digest to support multi-arch builds (amd64/arm64).
# For single-arch production: python:3.12-slim@sha256:<digest from `docker buildx imagetools inspect python:3.12-slim`>
FROM python:3.12-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY config/ config/
RUN uv sync --frozen --no-dev

# Stage 2: Slim runtime — same Python 3.12 as builder to avoid native extension ABI mismatch.
# distroless/python3-debian12 only ships Python 3.11, which breaks pydantic_core's compiled .so files.
# Not digest-pinned for the same multi-arch reason as Stage 1.
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

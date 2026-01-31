# Stage 1: Build
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY config/ config/
RUN uv sync --frozen --no-dev

# Stage 2: Runtime — distroless Python
FROM gcr.io/distroless/python3-debian12

COPY --from=builder /app /app
WORKDIR /app

# Run as non-root (distroless nonroot user = 65534)
USER 65534

ENV PYTHONPATH=/app/src
EXPOSE 8080

ENTRYPOINT ["python", "-m", "uvicorn", "src.proxy.app:create_app", "--host", "0.0.0.0", "--port", "8080", "--factory"]

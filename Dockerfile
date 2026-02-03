# Stage 1: Build dependencies with uv
# Pin base image by digest for reproducible builds. Update digest periodically.
# To find latest: docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:5dc6f84b5e97bfb0c90abfb7c55f3cacc668cb30b4560e27e0c92a3a32e8c34d AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY config/ config/
RUN uv sync --frozen --no-dev

# Stage 2: Hardened minimal runtime
FROM python:3.12-slim@sha256:5dc6f84b5e97bfb0c90abfb7c55f3cacc668cb30b4560e27e0c92a3a32e8c34d AS runtime

# Remove package manager, shells, and unnecessary files to approximate distroless
RUN apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/* /var/cache/* /var/log/* \
       /usr/bin/apt* /usr/bin/dpkg* /usr/lib/apt /usr/lib/dpkg \
       /usr/bin/perl* /usr/share/perl* \
       /usr/share/doc /usr/share/man /usr/share/info \
       /tmp/* /root/.cache \
    && find / -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; true \
    && find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app

# Copy only the venv and app code from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/config /app/config

# Run as non-root
USER 65534

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["python", "-m", "uvicorn", "src.proxy.app:create_app_from_env", "--host", "0.0.0.0", "--port", "8080", "--factory"]

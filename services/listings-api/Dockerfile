# =====================================================================================================================
# PF-Shield listings-api: Hardened Multi-Stage Distroless/Slim Container
# CIS Docker Benchmark & NIST SP 800-190 Compliant
# =====================================================================================================================

# Stage 1: Build Dependencies
FROM python:3.15-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Hardened Runtime Container
FROM python:3.15-slim-bookworm AS runtime

# Install minimal curl for container health check probes
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/share/doc /usr/share/man

# Enforce non-root execution: Create dedicated unprivileged user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy application source code
COPY --chown=appuser:appgroup app.py .

# Harden filesystem permissions
RUN chmod -R 550 /app && \
    chmod 440 /app/app.py

# Drop all privileges
USER 10001:10001

EXPOSE 8000

# Native container health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

ENTRYPOINT ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim-bookworm AS base

# Install system deps for PyNaCl (libsodium) and serial port access
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium-dev \
    libffi-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install the adapter package
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

# Create runtime directories
RUN mkdir -p /data/lxmf /data/reticulum /var/log/spine-reticulum

# Copy gateway configs
COPY pi-gateway/config/ /etc/spine-reticulum/

# Non-root user
RUN useradd -r -s /bin/false spine && \
    chown -R spine:spine /data /var/log/spine-reticulum
USER spine

ENV SPINE_RETICULUM_CONFIG=/etc/spine-reticulum/adapter.yaml

ENTRYPOINT ["spine-reticulum"]
CMD ["run"]

# ============================================================
#  GraphRaider — single image running the Python backend (:8000)
#  and the Node static frontend (:3000).
# ============================================================
FROM python:3.12-slim

# Node.js + npm for the frontend (Debian bookworm ships Node 18, fine for Express).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Backend dependencies (cached layer) ─────────────────────
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# ── Frontend dependencies (cached layer) ────────────────────
COPY frontend/package.json frontend/package-lock.json* frontend/
RUN cd frontend && npm install --omit=dev --no-audit --no-fund

# ── Application source ──────────────────────────────────────
COPY backend/ backend/
COPY frontend/ frontend/
COPY storage/ storage/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persisted config + request log live on a mounted volume (see docker-compose.yml).
ENV GRAPHRAIDER_CONFIG=/data/config.json \
    GRAPHRAIDER_LOG=/data/request_log.json
VOLUME ["/data"]

EXPOSE 8000 3000

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

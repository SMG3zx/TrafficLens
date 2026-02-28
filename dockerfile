FROM python:3.12-slim AS runtime

# ---- system deps (keep reasonably small but compatible) ----
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bash \
    curl \
    gcc \
    build-essential \
    libpq-dev \
    libpcap-dev \
  && rm -rf /var/lib/apt/lists/*

# ---- python env ----
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd -m -u 10001 appuser

WORKDIR /app

# Copy repo
COPY . /app

# Django project appears to live here per repo structure
WORKDIR /app/TrafficLensFrontend

# Install Python deps if present, else install minimal runtime deps
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    if [ -f requirements.txt ]; then \
      pip install --no-cache-dir -r requirements.txt; \
    else \
      pip install --no-cache-dir "Django>=4.2,<6" gunicorn; \
    fi

# Entrypoint: infer DJANGO_SETTINGS_MODULE from manage.py and run gunicorn
RUN cat > /usr/local/bin/entrypoint.sh <<'EOF' && chmod +x /usr/local/bin/entrypoint.sh
#!/usr/bin/env bash
set -euo pipefail

cd /app/TrafficLensFrontend

if [ -z "${DJANGO_SETTINGS_MODULE}" ]; then
  echo "ERROR: Could not infer DJANGO_SETTINGS_MODULE from manage.py"
  echo "Fix: set DJANGO_SETTINGS_MODULE env var at runtime (e.g. myproj.settings)."
  exit 1
fi

export DJANGO_SETTINGS_MODULE

# Derive wsgi module (myproj.settings -> myproj.wsgi)
WSGI_MODULE="${DJANGO_SETTINGS_MODULE%.settings}.wsgi:application"

# Default bind/port for platforms
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

# If you want, you can enable this later:
# python manage.py migrate --noinput || true
# python manage.py collectstatic --noinput || true

exec gunicorn "$WSGI_MODULE" \
  --bind "${HOST}:${PORT}" \
  --workers "${WEB_CONCURRENCY:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-60}"
EOF

EXPOSE 8000

USER appuser

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
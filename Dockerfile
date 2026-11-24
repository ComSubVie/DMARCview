# syntax=docker/dockerfile:1

# ---- frontend -------------------------------------------------------------
# Build the SPA on the native build platform; the static output is reused for
# every target architecture (keeps multi-arch builds fast).
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- backend --------------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    DATABASE_URL=sqlite:////data/dmarc.db \
    FRONTEND_DIST=/app/frontend/dist

WORKDIR /app

RUN addgroup --system --gid 1000 app \
    && adduser --system --uid 1000 --ingroup app --home /app app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/alembic.ini ./alembic.ini
COPY backend/migrations ./migrations
COPY --from=web /web/dist ./frontend/dist

RUN chown -R app:app /app \
    && mkdir -p /data/geoip \
    && chown -R app:app /data

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

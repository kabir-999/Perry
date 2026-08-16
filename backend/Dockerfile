# Render's native (non-Docker) Python build has no root/apt access, so it
# can never install Chromium's system libraries — `playwright install
# chromium` there only downloads the browser binary, which then fails to
# launch. This Dockerfile installs Chromium *and* its OS dependencies via
# Playwright's own `--with-deps` (needs apt, hence needs a real Debian
# base + root), so the browser crawler (SPA click-through discovery,
# network capture, cross-origin backend testing) actually runs in
# production instead of silently degrading to the static HTML-only crawler.
FROM python:3.11-slim

WORKDIR /app

# Playwright's apt-get install (via --with-deps) needs these present first
# on a bare slim image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Downloads the Chromium binary AND installs its required OS libraries
# (libnss3, libatk, libgbm, fonts, etc.) — the actual missing piece on
# Render's native build.
RUN playwright install --with-deps chromium

COPY . .

# Render sets $PORT at runtime; migrations run before the server starts so
# a fresh deploy is never serving against a stale schema.
CMD alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}

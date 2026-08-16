# Render's native (non-Docker) Python build has no root/apt access, so it
# can never install Chromium's system libraries — `playwright install
# chromium` there only downloads the browser binary, which then fails to
# launch. Installs Chromium *and* its OS dependencies via Playwright's own
# `--with-deps` (needs apt, hence needs a real Debian base + root, hence
# Docker) — only Chromium, not Firefox/WebKit, to keep the image small
# (Microsoft's own all-browsers Playwright image runs ~4.5GB, a plausible
# reason a build could fail on a disk/resource-constrained plan).
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

# Render sets $PORT at runtime; migrations run before the server starts so
# a fresh deploy is never serving against a stale schema.
CMD ["/bin/sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

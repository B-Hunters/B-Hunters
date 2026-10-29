# The B-Hunters platform: the API, the web console and the agent runtime.
#
# The scanner workers are separate images, built from their own
# repositories; see docs/workers.md.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    BHUNTERS_HOST=0.0.0.0 \
    BHUNTERS_PORT=8080 \
    BHUNTERS_CONFIG=/etc/b-hunters/b-hunters.ini

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
    fonts-liberation libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The dependencies are installed before the source, so that a change to
# the code does not invalidate the dependency layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The browser that prints the PDF report.  It is installed as a system
# browser rather than a per-user download, so that the platform and the
# runner — which share the image — find the same one.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN playwright install --with-deps chromium \
 && chmod -R a+rX /opt/ms-playwright

COPY setup.py MANIFEST.in ./
COPY b_hunters ./b_hunters

RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 --create-home --home-dir /home/bhunters bhunters \
 && mkdir -p /var/lib/b-hunters/workspaces \
 && chown -R bhunters:bhunters /var/lib/b-hunters /app

USER bhunters
VOLUME ["/var/lib/b-hunters"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1

ENTRYPOINT ["b-hunters"]
CMD ["serve"]

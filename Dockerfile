FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETSHIELD_ENV=development
WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home-dir /app app \
    && mkdir -p /app/instance /app/uploads \
    && chown -R app:app /app/instance /app/uploads

# Apply OS security updates available at build time, then drop the apt lists.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-runtime.txt ./requirements-runtime.txt
# pip ships a CycloneDX BOM describing its *vendored* dependencies. Image
# scanners read that file as installed packages (Trivy marks them
# AnalyzedBy=sbom) and report CVEs for versions that are not installed, e.g.
# setuptools 70.3.0 while the real installed setuptools is 84.x. The BOM is
# metadata for pip's vendored copies, not for this image, so remove it.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel "jaraco.context>=6.1.0" \
    && pip install --no-cache-dir -r requirements-runtime.txt \
    && rm -f /usr/local/lib/python3.11/site-packages/pip/_vendor/bom.cdx.json
COPY --chown=app:app . .

USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)"

# Keep one worker: the prototype uses in-process Socket.IO state and SQLite by default.
CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:5000", "--timeout", "120", "app:app"]

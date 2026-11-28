# phishlens: web interface (default) or mailbox scanner (`phishlens scan --every 300`)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHISHLENS_DB=/data/phishlens.db \
    PHISHLENS_HOST=0.0.0.0 \
    PHISHLENS_PORT=8000

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY phishlens ./phishlens
RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin phishlens \
    && install -d -o phishlens -g phishlens -m 700 /data

USER phishlens
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["phishlens", "web"]

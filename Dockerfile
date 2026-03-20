# Stage 1: Build
FROM python:3.12.4-slim-bookworm AS builder

WORKDIR /build

COPY src/requirements.txt .

RUN pip install --no-cache-dir --prefix=/build/deps -r requirements.txt

COPY src/ ./src/

RUN python -m compileall -q ./src/

RUN PYTHONPATH=/build/deps/lib/python3.12/site-packages \
    python -c "import flask; print(f'Flask {flask.__version__} instalado com sucesso')"


# Stage 2: Production (hardened)
FROM python:3.12.4-slim-bookworm AS production

LABEL maintainer="devops-lab"
LABEL org.opencontainers.image.source="https://github.com/seu-usuario/container-hardening-lab"

# Remove ferramentas de rede que ampliam superfície de ataque
RUN apt-get purge -y --auto-remove \
        wget curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && rm -rf /tmp/* /var/tmp/* \
    && find /usr/lib/python3* -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

RUN groupadd --gid 10001 appgroup \
    && useradd \
        --uid 10001 \
        --gid appgroup \
        --no-create-home \
        --shell /usr/sbin/nologin \
        appuser

WORKDIR /app

COPY --from=builder /build/deps /usr/local
COPY --from=builder /build/src/ ./

RUN test -f /app/templates/index.html || (echo 'ERRO: template não encontrado' && exit 1)

RUN chown -R appuser:appgroup /app \
    && chmod -R 555 /app

EXPOSE 5000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')"]

ENTRYPOINT ["python", "-u", "app.py"]

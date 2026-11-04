# TrafficLens — анализ сетевого трафика: Zeek + Suricata + IOC + веб-UI.
# Сборка:   podman build -t localhost/trafficlens:latest .
# Базовый образ — официальный Zeek (Debian). Для другой версии: --build-arg ZEEK_IMAGE=docker.io/zeek/zeek:8.0.11
ARG ZEEK_IMAGE=docker.io/zeek/zeek:lts
FROM ${ZEEK_IMAGE}

ARG BAKE_RULES=1
ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:/usr/local/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    TL_DATA_DIR=/data \
    TMPDIR=/data/.tmp \
    TZ=UTC

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        suricata suricata-update tcpdump python3 python3-venv ca-certificates tini tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Правила ET Open, «запечённые» в образ: работают сразу, пока не скачаны свежие в /data/suricata.
RUN mkdir -p /opt/trafficlens/rules-baked \
 && if [ "$BAKE_RULES" = "1" ]; then \
        suricata-update --no-test --no-reload --data-dir /var/lib/suricata \
            --output /opt/trafficlens/rules-baked || echo "!! правила не скачались — обновите их из веб-UI"; \
    fi

COPY trafficlens /app/trafficlens
COPY bin /app/bin
COPY tools /app/tools
RUN chmod +x /app/bin/*.sh \
 && zeek --version && suricata -V && python3 -c "import trafficlens.web"

VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/app/bin/entrypoint.sh"]
CMD ["web"]

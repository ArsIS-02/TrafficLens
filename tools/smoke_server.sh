#!/usr/bin/env bash
# Smoke-проверка TrafficLens на хосте с Podman.
# Не трогает боевой каталог данных: создаёт временный /tmp/trafficlens-smoke.* и удаляет его в конце.
# Переменные:
#   IMAGE       — образ для проверки (по умолчанию localhost/trafficlens:latest)
#   HEALTH_URL  — URL healthcheck живого сервиса; пусто — пропустить проверку сервиса
#   KEEP=1      — не удалять временный каталог (для отладки)
set -euo pipefail

IMAGE=${IMAGE:-localhost/trafficlens:latest}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8095/healthz}
KEEP=${KEEP:-0}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORKDIR=$(mktemp -d /tmp/trafficlens-smoke.XXXXXX)

cleanup() {
  if [[ "$KEEP" == "1" ]]; then
    echo "KEEP=1: временные данные оставлены в $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "ОШИБКА: не найдена команда $1" >&2; exit 2; }; }
need podman
need grep

step() { echo; echo "[$1/4] $2"; }

step 1 "загрузка custom IOC во временную базу"
mkdir -p "$WORKDIR/ioc/custom"
cp "$SCRIPT_DIR/test-iocs.txt" "$WORKDIR/ioc/custom/test.txt"
podman run --rm -v "$WORKDIR:/data:z" "$IMAGE" update-iocs --source custom

step 2 "генерация тестового PCAP"
podman run --rm -v "$WORKDIR:/data:z" "$IMAGE" python3 /app/tools/make_test_pcap.py /data/test.pcap
[[ -s "$WORKDIR/test.pcap" ]] || { echo "ОШИБКА: test.pcap не создан" >&2; exit 1; }

step 3 "анализ и проверка отчётов"
podman run --rm -v "$WORKDIR:/data:z" "$IMAGE" analyze /data/test.pcap -o /data/test-report.html
grep -q "Приоритетные хосты" "$WORKDIR/test-report.html" || { echo "ОШИБКА: в HTML нет блока «Приоритетные хосты»" >&2; exit 1; }
reports=( "$WORKDIR"/jobs/*/report.json )
[[ -f "${reports[0]}" ]] || { echo "ОШИБКА: не найден report.json" >&2; exit 1; }
grep -q '"priority_hosts"' "${reports[0]}" || { echo "ОШИБКА: в report.json нет priority_hosts" >&2; exit 1; }
grep -q "203.0.113.66:8443" "${reports[0]}" || { echo "ОШИБКА: в verdict reasons нет ожидаемого маяка 203.0.113.66:8443" >&2; exit 1; }

step 4 "healthcheck живого сервиса"
if [[ -n "$HEALTH_URL" ]]; then
  need curl
  curl -sf "$HEALTH_URL" | grep -q '"ok":true' || { echo "ОШИБКА: healthcheck не прошёл: $HEALTH_URL" >&2; exit 1; }
else
  echo "HEALTH_URL пуст — проверка сервиса пропущена"
fi

echo
echo "SMOKE OK: $IMAGE"

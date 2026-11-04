#!/bin/sh
# Живой захват: tcpdump пишет файлы с ротацией, закрытый файл перекладывается в spool/ready,
# откуда его забирает веб-контейнер и ставит в очередь анализа.
#
#   CAPTURE_IFACE    интерфейс (enp3s0, eth0, any)              по умолчанию any
#   CAPTURE_ROTATE   длина одного файла, секунд                  по умолчанию 300
#   CAPTURE_FILTER   BPF-фильтр, например "not port 9000"        по умолчанию нет
#   CAPTURE_SNAPLEN  байт пакета (0 — целиком)                   по умолчанию 0
#   CAPTURE_MAX_SPOOL_MB  предел незабранных файлов в ready/     по умолчанию 5120
set -eu
DATA="${TL_DATA_DIR:-/data}"
SPOOL="$DATA/spool"
IFACE="${CAPTURE_IFACE:-any}"
ROT="${CAPTURE_ROTATE:-300}"
FILTER="${CAPTURE_FILTER:-}"
MAXMB="${CAPTURE_MAX_SPOOL_MB:-5120}"
mkdir -p "$SPOOL/ready"

# незакрытые файлы прошлого запуска — в обработку
for f in "$SPOOL"/cap-*.pcap; do
  [ -e "$f" ] && mv "$f" "$SPOOL/ready/" || true
done

# heartbeat для веб-UI + защита диска, если веб-контейнер не забирает файлы
(
  while true; do
    echo "интерфейс $IFACE, ротация ${ROT} с${FILTER:+, фильтр: $FILTER}" > "$SPOOL/.capture-heartbeat"
    used=$(du -sm "$SPOOL/ready" 2>/dev/null | cut -f1)
    while [ "${used:-0}" -gt "$MAXMB" ]; do
      oldest=$(ls -1tr "$SPOOL/ready"/cap-* 2>/dev/null | head -1)
      [ -z "$oldest" ] && break
      echo "spool переполнен (${used} МБ > ${MAXMB}), удаляю $oldest" >&2
      rm -f "$oldest"
      used=$(du -sm "$SPOOL/ready" 2>/dev/null | cut -f1)
    done
    sleep 30
  done
) &

set -- -i "$IFACE" -s "${CAPTURE_SNAPLEN:-0}" -n -U -G "$ROT" \
       -w "$SPOOL/cap-%Y%m%d-%H%M%S.pcap" -z /app/bin/spool-done.sh -Z root
# для -i any фиксируем классический Linux cooked (SLL v1) — его понимают и Zeek, и Suricata
[ "$IFACE" = "any" ] && set -- "$@" -y LINUX_SLL
[ -n "$FILTER" ] && set -- "$@" "$FILTER"
echo "tcpdump $*" >&2
exec tcpdump "$@"

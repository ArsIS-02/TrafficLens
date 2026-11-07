#!/bin/sh
# Режимы контейнера:
#   web                     — веб-UI + очередь анализа + обновление IOC/правил (по умолчанию)
#   capture                 — живой захват tcpdump с ротацией в /data/spool (нужны --network=host и NET_RAW)
#   analyze <pcap> [-o out] — разовый анализ из командной строки
#   update-iocs | update-rules
set -e
cmd="${1:-web}"
[ $# -gt 0 ] && shift
case "$cmd" in
  web)                       exec python3 -m trafficlens web ;;
  capture)                   exec /app/bin/capture.sh ;;
  analyze|update-iocs|update-rules|retro) exec python3 -m trafficlens "$cmd" "$@" ;;
  *)                         exec "$cmd" "$@" ;;
esac

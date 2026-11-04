#!/bin/sh
# Вызывается tcpdump (-z) для каждого закрытого файла ротации.
f="$1"
[ -f "$f" ] || exit 0
mv "$f" "$(dirname "$f")/ready/"

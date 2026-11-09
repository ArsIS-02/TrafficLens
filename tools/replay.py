#!/usr/bin/env python3
"""Replay-лаборатория: регрессионная проверка детектов TrafficLens.

Проигрывает эталонные дампы из каталога TR_REPLAY_DIR через CLI контейнера
(`podman exec trafficlens analyze /data/replay/<file>`) и сверяет свежий
отчёт report.json с ожиданиями из manifest.json:

  [{"file": "demo-c2-eicar-3.pcap",
    "expect": {"verdict": "critical", "min_ioc_hits": 4,
               "min_alert_sigs": 3, "min_beacons": 1, "dga": false}}]

Результат — одно GELF-событие (tool:tlreplay): pass/fail по каждому дампу.
Падение ожидания = регрессия детектов после обновления кода или фидов.
Запускать на хосте с контейнером trafficlens (данные смонтированы в /data).

ENV: TR_CONTAINER (trafficlens), TR_DATA_DIR (~/trafficlens/data),
     TR_REPLAY_DIR (<data>/replay), TR_GELF_HOST/PORT (127.0.0.1:12206),
     TR_JOB_TIMEOUT (900)
"""
import gzip
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path

CONTAINER = os.environ.get("TR_CONTAINER", "trafficlens")
DATA_DIR = Path(os.environ.get("TR_DATA_DIR", "~/trafficlens/data")).expanduser()
DIR = Path(os.environ.get("TR_REPLAY_DIR", str(DATA_DIR / "replay")))
GELF_HOST = os.environ.get("TR_GELF_HOST", "127.0.0.1")
GELF_PORT = int(os.environ.get("TR_GELF_PORT", "12206"))
JOB_TIMEOUT = int(os.environ.get("TR_JOB_TIMEOUT", "900"))
HOST = socket.gethostname()

JOB_RE = re.compile(r"задача\s+(\S+?):")


def analyze(pcap: Path) -> tuple[str, dict]:
    """Прогон дампа через CLI контейнера. Возвращает (job_id, report.json)."""
    rel = pcap.relative_to(DATA_DIR)  # replay/<name>.pcap
    r = subprocess.run(
        ["podman", "exec", CONTAINER, "/app/bin/entrypoint.sh", "analyze", f"/data/{rel}"],
        capture_output=True, text=True, timeout=JOB_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:200] or "analyze failed")
    m = JOB_RE.search(r.stdout)
    if not m:
        raise RuntimeError(f"не нашёл id задачи в выводе: {r.stdout[:150]}")
    job_id = m.group(1)
    rep_path = DATA_DIR / "jobs" / job_id / "report.json"
    if not rep_path.exists():
        raise RuntimeError(f"нет report.json для задачи {job_id}")
    return job_id, json.loads(rep_path.read_text(encoding="utf-8"))


def check(rep: dict, expect: dict) -> list[str]:
    """Список несовпадений (пусто = PASS)."""
    fails = []
    v = (rep.get("verdict") or {}).get("level")
    if expect.get("verdict") and v != expect["verdict"]:
        fails.append(f"verdict: {v} != {expect['verdict']}")
    t = rep.get("totals") or {}
    if "min_ioc_hits" in expect and t.get("ioc_hits", 0) < expect["min_ioc_hits"]:
        fails.append(f"ioc_hits: {t.get('ioc_hits', 0)} < {expect['min_ioc_hits']}")
    if "min_alert_sigs" in expect and t.get("alert_sigs", 0) < expect["min_alert_sigs"]:
        fails.append(f"alert_sigs: {t.get('alert_sigs', 0)} < {expect['min_alert_sigs']}")
    beacons = len((rep.get("findings") or {}).get("beacons") or [])
    if "min_beacons" in expect and beacons < expect["min_beacons"]:
        fails.append(f"beacons: {beacons} < {expect['min_beacons']}")
    if "dga" in expect:
        has_dga = any((s.get("reason") == "dga") for s in (rep.get("dns") or {}).get("suspicious") or [])
        if has_dga != bool(expect["dga"]):
            fails.append(f"dga: {has_dga} != {expect['dga']}")
    return fails


def send_gelf(short, **fields):
    msg = {"version": "1.1", "host": HOST, "short_message": short,
           "timestamp": time.time(), "level": 4 if fields.get("failed") else 5}
    msg.update({f"_{k}": v for k, v in fields.items()})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(gzip.compress(json.dumps(msg, ensure_ascii=False).encode()),
                (GELF_HOST, GELF_PORT))
    sock.close()


def main() -> int:
    manifest = json.loads((DIR / "manifest.json").read_text(encoding="utf-8"))
    passed, failed, details = 0, 0, []
    for item in manifest:
        f = DIR / item["file"]
        name = item["file"]
        try:
            if not f.exists():
                raise RuntimeError("файл отсутствует")
            job_id, rep = analyze(f)
            fails = check(rep, item.get("expect") or {})
            if fails:
                failed += 1
                details.append(f"{name}: FAIL ({'; '.join(fails)})")
            else:
                passed += 1
                details.append(f"{name}: OK ({job_id})")
        except Exception as e:
            failed += 1
            details.append(f"{name}: ERROR ({str(e)[:120]})")
    print("\n".join(details))
    try:
        send_gelf(f"tlreplay: регрессия детектов — {passed} ок / {failed} провалов",
                  tool="tlreplay", homelab_app="trafficlens", tr_event="replay",
                  passed=passed, failed=failed, details=" | ".join(details)[:900])
    except Exception as e:
        print(f"GELF не отправлен: {e}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

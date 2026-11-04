"""Командная строка: web | analyze | update-iocs | update-rules."""
from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from . import pipeline, worker
from .config import load
from .db import DB


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="trafficlens", description="Анализ сетевого трафика: Zeek + Suricata + IOC")
    ap.add_argument("--data", help="каталог данных (по умолчанию /data или $TL_DATA_DIR)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("web", help="веб-интерфейс и фоновые задачи")
    a = sub.add_parser("analyze", help="проанализировать PCAP и сохранить HTML-отчёт")
    a.add_argument("pcap", type=Path)
    a.add_argument("-o", "--out", type=Path, help="куда скопировать report.html")
    a.add_argument("--update-iocs", action="store_true", help="сначала обновить IOC")
    u = sub.add_parser("update-iocs", help="обновить индикаторы из всех источников")
    u.add_argument("--source", help="только один источник (custom, abusech-threatfox, misp, ...)")
    sub.add_parser("update-rules", help="обновить правила Suricata (ET Open)")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load(args.data)
    db = DB(cfg.db_path)

    if args.cmd == "web":
        from .web import create_app
        app = create_app(cfg)
        try:
            from waitress import serve
        except ImportError:
            logging.warning("waitress не установлен — использую встроенный сервер Flask")
            app.run(host=cfg["listen"], port=int(cfg["port"]), threaded=True)
            return 0
        serve(app, host=cfg["listen"], port=int(cfg["port"]), threads=8, max_request_body_size=app.config["MAX_CONTENT_LENGTH"],
              channel_timeout=600)
        return 0

    if args.cmd == "update-iocs":
        for k, v in worker.run_ioc_update(cfg, db, only=args.source).items():
            print(f"{k:24} {v}")
        return 0

    if args.cmd == "update-rules":
        ok, msg = worker.run_rules_update(cfg)
        print(("OK: " if ok else "ОШИБКА: ") + msg)
        return 0 if ok else 1

    if args.cmd == "analyze":
        if not args.pcap.exists():
            print(f"нет файла {args.pcap}", file=sys.stderr)
            return 2
        if args.update_iocs:
            worker.run_ioc_update(cfg, db)
        # задача сразу «running», чтобы её не забрал фоновый обработчик веб-контейнера
        jid = worker.enqueue_file(cfg, db, args.pcap, args.pcap.name, "cli", move=False, status="running")
        pipeline.process(cfg, db, db.job(jid))
        j = db.job(jid)
        if j["status"] != "done":
            print(f"ошибка: {j['error']}", file=sys.stderr)
            return 1
        rep = pipeline.job_dir(cfg, jid) / "report.html"
        if args.out:
            shutil.copy2(rep, args.out)
            rep = args.out
        s = j["summary"]
        print(f"задача {jid}: {s.get('verdict_label')}; IOC: {s.get('ioc_hits')}, алертов: {s.get('alerts')}, файлов: {s.get('files')}")
        print(f"отчёт: {rep}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

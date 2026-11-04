"""Конвейер обработки одной задачи."""
from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path

from . import report as report_mod
from . import runner
from .config import Config
from .db import DB
from .ioc_store import IOCIndex
from .render import render_report

log = logging.getLogger("trafficlens.pipeline")


def job_dir(cfg: Config, job_id: str) -> Path:
    return cfg.jobs_dir / job_id


def _write(p: Path, text: str) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)


def build_report(cfg: Config, db: DB, job: dict) -> dict:
    jd = job_dir(cfg, job["id"])
    index = IOCIndex(db)
    pcap = Path(job["pcap_path"])
    meta = {"job_id": job["id"], "filename": job["filename"], "source": job["source"], "size": job["size"],
            "pcap_sha256": job.get("summary", {}).get("pcap_sha256") or (report_mod.sha256_file(pcap) if pcap.exists() else ""),
            "tools": runner.tool_versions(cfg)}
    rep = report_mod.build(jd, index, cfg, meta)
    _write(jd / "report.json", json.dumps(rep, ensure_ascii=False, default=_json_default))
    _write(jd / "report.html", render_report(rep, embedded=False))
    s = report_mod.summary(rep)
    s["pcap_sha256"] = meta["pcap_sha256"]
    return s


def _json_default(o):
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def process(cfg: Config, db: DB, job: dict) -> None:
    jd = job_dir(cfg, job["id"])
    jd.mkdir(parents=True, exist_ok=True)
    logfile = jd / "job.log"
    pcap = Path(job["pcap_path"])
    t0 = time.time()
    try:
        if not pcap.exists():
            raise runner.ToolError("PCAP-файл не найден")
        db.update_job(job["id"], stage="Zeek: разбор протоколов")
        zdir = jd / "zeek"
        if zdir.exists():
            shutil.rmtree(zdir)
        runner.run_zeek(cfg, pcap, zdir, logfile)
        db.update_job(job["id"], stage="Suricata: сигнатуры")
        sdir = jd / "suricata"
        if sdir.exists():
            shutil.rmtree(sdir)
        runner.run_suricata(cfg, pcap, sdir, logfile)
        db.update_job(job["id"], stage="Сверка с IOC и отчёт")
        s = build_report(cfg, db, job)
        db.update_job(job["id"], status="done", stage="", finished=time.time(), summary=s)
        log.info("job %s done in %.1fs", job["id"], time.time() - t0)
    except Exception as e:  # noqa: BLE001
        log.exception("job %s failed", job["id"])
        with logfile.open("a", encoding="utf-8") as lf:
            lf.write(f"ОШИБКА: {e}\n")
        db.update_job(job["id"], status="error", stage="", finished=time.time(), error=str(e)[:500])


def rematch(cfg: Config, db: DB, job_id: str) -> dict:
    """Пересобрать отчёт по уже готовым логам с актуальной базой IOC."""
    job = db.job(job_id)
    if not job or not (job_dir(cfg, job_id) / "zeek").exists():
        raise FileNotFoundError("нет логов для пересборки")
    s = build_report(cfg, db, job)
    db.update_job(job_id, summary=s)
    return s


def delete(cfg: Config, db: DB, job_id: str) -> None:
    job = db.job(job_id)
    if not job:
        return
    jd = job_dir(cfg, job_id)
    if jd.exists():
        shutil.rmtree(jd, ignore_errors=True)
    p = Path(job["pcap_path"])
    if p.exists() and cfg.data in p.parents:
        p.unlink(missing_ok=True)
    db.delete_job(job_id)

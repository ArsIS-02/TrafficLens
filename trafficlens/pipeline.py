"""Конвейер обработки одной задачи."""
from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path

from . import gelf
from . import report as report_mod
from . import retro
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
    flt = (job.get("summary") or {}).get("filter")
    if flt:
        meta["filter"] = flt
    rep = report_mod.build(jd, index, cfg, meta, marks=db.marks_for(job["id"]), allow=db.allowlist())
    _write(jd / "report.json", json.dumps(rep, ensure_ascii=False, default=_json_default))
    _write(jd / "report.html", render_report(rep, embedded=False))
    s = report_mod.summary(rep)
    s["pcap_sha256"] = meta["pcap_sha256"]
    return s


def notify(cfg: Config, db: DB, job_id: str, retro_rows: list[dict] | None = None) -> int:
    """Отправить в Graylog (GELF) то, что по задаче ещё не отправлялось. Ошибки не пробрасываются."""
    if not gelf.enabled(cfg):
        return 0
    try:
        job = db.job(job_id)
        rep = json.loads((job_dir(cfg, job_id) / "report.json").read_text(encoding="utf-8"))
        return gelf.notify_job(cfg, db, job, rep, retro_rows)
    except Exception:  # noqa: BLE001
        log.exception("gelf notify %s", job_id)
        return 0


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
        db.update_job(job["id"], stage="zeek")
        zdir = jd / "zeek"
        if zdir.exists():
            shutil.rmtree(zdir)
        runner.run_zeek(cfg, pcap, zdir, logfile)
        db.update_job(job["id"], stage="suricata")
        sdir = jd / "suricata"
        if sdir.exists():
            shutil.rmtree(sdir)
        runner.run_suricata(cfg, pcap, sdir, logfile)
        db.update_job(job["id"], stage="match")
        s = build_report(cfg, db, job)
        db.update_job(job["id"], status="done", stage="", finished=time.time(), summary=s)
        try:   # наблюдаемые значения для ретропроверки — один раз, пока логи «горячие»
            (jd / retro.OBS_FILE).unlink(missing_ok=True)
            retro.ensure(jd)
        except Exception:  # noqa: BLE001
            log.exception("observables %s", job["id"])
        notify(cfg, db, job["id"])
        log.info("job %s done in %.1fs", job["id"], time.time() - t0)
    except Exception as e:  # noqa: BLE001
        log.exception("job %s failed", job["id"])
        with logfile.open("a", encoding="utf-8") as lf:
            lf.write(f"ОШИБКА: {e}\n")
        db.update_job(job["id"], status="error", stage="", finished=time.time(), error=str(e)[:500])


def rematch(cfg: Config, db: DB, job_id: str, send: bool = True) -> dict:
    """Пересобрать отчёт по уже готовым логам с актуальной базой IOC."""
    job = db.job(job_id)
    if not job or not (job_dir(cfg, job_id) / "zeek").exists():
        raise FileNotFoundError("нет логов для пересборки")
    s = build_report(cfg, db, job)
    db.update_job(job_id, summary=s)
    if send:
        notify(cfg, db, job_id)
    return s


def _report_haystack(rep: dict) -> str:
    """Текст для поиска по готовому отчёту: хосты, IOC, имена файлов, DNS-имена."""
    parts = [rep.get("meta", {}).get("filename", "")]
    for h in rep.get("local_hosts", []):
        parts += [h.get("ip", ""), h.get("name", ""), h.get("mac", "")]
    for e in rep.get("top_external", []):
        parts += [e.get("ip", ""), e.get("name", "")]
    for h in rep.get("ioc_hits", []):
        parts.append(h.get("value", ""))
        parts += h.get("observed", [])
    for f in rep.get("files", []):
        parts += [f.get("filename", ""), f.get("sha256", ""), f.get("md5", "")]
    for d in rep.get("dns", {}).get("top", []):
        parts.append(d.get("name", ""))
    return "\n".join(p for p in parts if p).lower()


def search_jobs(cfg: Config, db: DB, q: str, limit: int = 200) -> list[dict]:
    """Поиск задач: подстрока в имени файла, а для готовых — по содержимому отчёта (хосты, IOC, файлы, DNS)."""
    q = (q or "").strip().lower()
    jobs = db.jobs(limit=limit)
    if not q:
        return jobs
    out = []
    for j in jobs:
        if q in (j.get("filename") or "").lower():
            out.append(j)
            continue
        if j["status"] != "done":
            continue
        rp = job_dir(cfg, j["id"]) / "report.json"
        try:
            rep = json.loads(rp.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if q in _report_haystack(rep):
            out.append(j)
    return out


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

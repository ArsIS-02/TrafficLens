"""Фоновые потоки: очередь анализа, планировщик обновлений, приём файлов живого захвата."""
from __future__ import annotations

import gzip
import hashlib
import logging
import secrets
import shutil
import threading
import time
from pathlib import Path

from . import asn, feeds, pipeline, retro, runner
from .config import Config
from .db import DB

log = logging.getLogger("trafficlens.worker")
PCAP_EXT = (".pcap", ".pcapng", ".cap", ".dmp")


def new_job_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def _copy_sha256(fi, fo, chunk_size: int = 1 << 20) -> str:
    """Копирует поток fo и за один проход возвращает SHA256 потока."""
    h = hashlib.sha256()
    while True:
        chunk = fi.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
        fo.write(chunk)
    return h.hexdigest()


def enqueue_file(cfg: Config, db: DB, src: Path, filename: str, source: str, move: bool = True, status: str = "queued",
                 bpf: str = "", ts_from: float | None = None, ts_to: float | None = None) -> str:
    """Положить PCAP в каталог задачи и поставить её в очередь. .gz распаковывается.

    Если задан BPF-фильтр и/или окно времени, PCAP обрезается до анализа —
    в сводке задачи сохраняется описание фильтра. ValueError (невалидный BPF
    или формат) пробрасывается вызывающему, каталог задачи при этом убирается.
    """
    from . import pcapfilter

    job_id = new_job_id()
    jd = pipeline.job_dir(cfg, job_id)
    jd.mkdir(parents=True)
    name = Path(filename).name
    try:
        if name.lower().endswith(".gz"):
            dst = jd / ("input" + (Path(name[:-3]).suffix or ".pcap"))
            tmp = dst.with_suffix(dst.suffix + ".part")
            try:
                with gzip.open(src, "rb") as fi, tmp.open("wb") as fo:
                    pcap_sha256 = _copy_sha256(fi, fo)
                tmp.replace(dst)
            finally:
                tmp.unlink(missing_ok=True)
            if move:
                src.unlink(missing_ok=True)
        else:
            dst = jd / ("input" + (Path(name).suffix.lower() or ".pcap"))
            tmp = dst.with_suffix(dst.suffix + ".part")
            try:
                with src.open("rb") as fi, tmp.open("wb") as fo:
                    pcap_sha256 = _copy_sha256(fi, fo)
                tmp.replace(dst)
            finally:
                tmp.unlink(missing_ok=True)
            if move:
                src.unlink(missing_ok=True)
        summary = {"pcap_sha256": pcap_sha256}
        if bpf or ts_from is not None or ts_to is not None:
            filtered = dst.with_suffix(dst.suffix + ".filtered")
            try:
                summary["filter"] = pcapfilter.filter_pcap(dst, filtered, bpf=bpf, ts_from=ts_from, ts_to=ts_to)
            finally:
                filtered.replace(dst) if filtered.exists() else None
            with dst.open("rb") as fi:  # хэш — от того файла, что реально пойдёт в анализ
                h = hashlib.sha256()
                for chunk in iter(lambda: fi.read(1 << 20), b""):
                    h.update(chunk)
                summary["pcap_sha256"] = h.hexdigest()
    except Exception:
        shutil.rmtree(jd, ignore_errors=True)
        raise
    db.add_job(job_id, source, name, str(dst), dst.stat().st_size, status=status)
    db.update_job(job_id, summary=summary)
    wake.set()
    return job_id


wake = threading.Event()
_state = {"ioc_update": None, "rules_update": None, "busy": set()}
_lock = threading.Lock()


def state() -> dict:
    with _lock:
        return {k: (sorted(v) if isinstance(v, set) else v) for k, v in _state.items()}


def _mark(task: str, on: bool):
    with _lock:
        (_state["busy"].add if on else _state["busy"].discard)(task)


def run_ioc_update(cfg: Config, db: DB, only: str | None = None, retro_sync: bool = False) -> dict:
    _mark("iocs", True)
    try:
        res = feeds.update_all(cfg, db, only=only)
        with _lock:
            _state["ioc_update"] = {"ts": time.time(), "result": res}
    finally:
        _mark("iocs", False)
    if (cfg.get("retro") or {}).get("enabled", True):
        if retro_sync:
            run_retro(cfg, db)
        else:   # в фоне: первый проход строит observables для всех задач и может занять минуты
            threading.Thread(target=run_retro, args=(cfg, db), daemon=True, name="retro").start()
    return res


def run_asn_update(cfg: Config, db: DB) -> dict:
    """Скачать офлайн-базу ASN (iptoasn); результат — в kv asn_status."""
    _mark("asn", True)
    try:
        res = asn.update(cfg)
        db.kv_set("asn_status", {"ts": time.time(), **res})
        return res
    except Exception as e:  # noqa: BLE001
        log.exception("asn update")
        db.kv_set("asn_status", {"ts": time.time(), "error": str(e)[:300]})
        return {"error": str(e)[:300]}
    finally:
        _mark("asn", False)


def run_retro(cfg: Config, db: DB, full: bool = False) -> dict | None:
    """Ретропроверка новых IOC по прошлым задачам; повторный запуск во время работы пропускается."""
    with _lock:
        if "retro" in _state["busy"]:
            return None
        _state["busy"].add("retro")
    try:
        return retro.run(cfg, db, full=full)
    except Exception:  # noqa: BLE001
        log.exception("retro")
        return None
    finally:
        _mark("retro", False)


def run_rules_update(cfg: Config) -> tuple[bool, str]:
    _mark("rules", True)
    try:
        ok, msg = runner.update_rules(cfg)
        with _lock:
            _state["rules_update"] = {"ts": time.time(), "ok": ok, "msg": msg}
        return ok, msg
    finally:
        _mark("rules", False)


def busy(task: str) -> bool:
    with _lock:
        return task in _state["busy"]


class JobWorker(threading.Thread):
    def __init__(self, cfg: Config, db: DB, n: int):
        super().__init__(daemon=True, name=f"job-worker-{n}")
        self.cfg, self.db = cfg, db

    def run(self):
        while True:
            try:
                job = self.db.claim_next()
                if job:
                    pipeline.process(self.cfg, self.db, job)
                    continue
            except Exception:  # noqa: BLE001
                log.exception("worker loop")
            wake.wait(5)
            wake.clear()


class Scheduler(threading.Thread):
    def __init__(self, cfg: Config, db: DB):
        super().__init__(daemon=True, name="scheduler")
        self.cfg, self.db = cfg, db

    def run(self):
        time.sleep(5)
        last_ioc = last_rules = last_ret = 0.0
        feeds_state = self.db.feeds()
        if feeds_state:
            last_ioc = max((f.get("updated") or 0) for f in feeds_state.values())
        rf = self.cfg.rules_dir / "rules" / "suricata.rules"
        if rf.exists():
            last_rules = rf.stat().st_mtime
        while True:
            now = time.time()
            try:
                if not busy("iocs") and now - last_ioc >= float(self.cfg["iocs"]["update_hours"]) * 3600:
                    last_ioc = now
                    run_ioc_update(self.cfg, self.db)
                if (self.cfg["suricata"].get("enabled") and not busy("rules")
                        and now - last_rules >= float(self.cfg["suricata"]["rules_update_hours"]) * 3600):
                    last_rules = now
                    run_rules_update(self.cfg)
                if now - last_ret >= 3600:
                    last_ret = now
                    self.retention()
            except Exception:  # noqa: BLE001
                log.exception("scheduler")
            time.sleep(60)

    def retention(self):
        r = self.cfg.get("retention") or {}
        days = r.get("days")
        if days is None:  # обратная совместимость со старым ключом
            days = self.cfg["capture"].get("retention_days", 7)
        days = float(days or 0)
        max_gb = float(r.get("max_total_gb") or 0)
        keep = set(r.get("keep_verdicts") or ["critical"])
        dry_run = bool(r.get("dry_run", False))

        def verdict_level(j):
            v = (j.get("summary") or {}).get("verdict")
            return v.get("level") if isinstance(v, dict) else v

        def delete(j):
            if dry_run:
                log.info("retention dry-run: удалил бы %s", j["id"])
                return
            pipeline.delete(self.cfg, self.db, j["id"])
            log.info("retention: удалена задача %s (%s)", j["id"], j.get("filename", ""))

        def active_jobs():
            return [j for j in self.db.jobs(limit=100000) if j["status"] in ("done", "error")]

        # 1) по возрасту — для всех источников (upload и capture)
        if days > 0:
            cutoff = time.time() - days * 86400
            for j in active_jobs():
                if j["created"] < cutoff and verdict_level(j) not in keep:
                    delete(j)

        # 2) по квоте — удаляем самые старые, пока не уложимся в лимит
        if max_gb > 0:
            limit = max_gb * 1024 ** 3

            def dir_size(j):
                jd = pipeline.job_dir(self.cfg, j["id"])
                if not jd.exists():
                    return 0
                return sum(f.stat().st_size for f in jd.rglob("*") if f.is_file())

            jobs = active_jobs()
            total = sum(dir_size(j) for j in jobs)
            for j in sorted(jobs, key=lambda x: x["created"]):
                if total <= limit:
                    break
                if verdict_level(j) in keep:
                    continue
                sz = dir_size(j)
                delete(j)
                total -= sz


class SpoolWatcher(threading.Thread):
    """capture-контейнер кладёт закрытые файлы ротации в <data>/spool/ready/."""

    def __init__(self, cfg: Config, db: DB):
        super().__init__(daemon=True, name="spool-watcher")
        self.cfg, self.db = cfg, db
        self.ready = cfg.spool_dir / "ready"
        self.last_file: dict | None = None

    def run(self):
        while True:
            try:
                for p in sorted(self.ready.iterdir()):
                    if p.name.startswith(".") or not p.is_file():
                        continue
                    if not p.name.lower().endswith(PCAP_EXT + tuple(e + ".gz" for e in PCAP_EXT)):
                        continue
                    if time.time() - p.stat().st_mtime < 5:
                        continue
                    if p.stat().st_size <= 24:   # только заголовок pcap — пустой интервал
                        p.unlink(missing_ok=True)
                        continue
                    jid = enqueue_file(self.cfg, self.db, p, p.name, "capture", move=True)
                    self.last_file = {"name": p.name, "ts": time.time(), "job": jid}
            except FileNotFoundError:
                self.ready.mkdir(parents=True, exist_ok=True)
            except Exception:  # noqa: BLE001
                log.exception("spool watcher")
            time.sleep(10)


_started = False


def start(cfg: Config, db: DB) -> dict:
    global _started
    threads = {}
    if _started:
        return threads
    _started = True
    db.reset_running()
    for n in range(max(1, int(cfg.get("workers", 1)))):
        JobWorker(cfg, db, n).start()
    Scheduler(cfg, db).start()
    if cfg["capture"].get("watch_spool", True):
        sw = SpoolWatcher(cfg, db)
        sw.start()
        threads["spool"] = sw
    return threads


def capture_status(cfg: Config) -> dict:
    """Признак живого захвата: capture-контейнер обновляет heartbeat-файл."""
    hb = cfg.spool_dir / ".capture-heartbeat"
    info = {"active": False}
    if hb.exists():
        age = time.time() - hb.stat().st_mtime
        try:
            text = hb.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        info = {"active": age < 180, "age": age, "info": text}
    cur = [p for p in cfg.spool_dir.glob("*.pcap*") if p.is_file()]
    if cur:
        newest = max(cur, key=lambda p: p.stat().st_mtime)
        info["current"] = {"name": newest.name, "size": newest.stat().st_size}
    return info

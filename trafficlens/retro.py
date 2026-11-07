"""Ретропроверка: новые индикаторы сверяются с уже разобранным трафиком прошлых задач.

Сценарий: C2-адрес попал в ThreatFox сегодня, а хост ходил на него во вторник.
После каждого обновления IOC берутся индикаторы, появившиеся в базе после
прошлой ретропроверки, и сверяются с «наблюдаемыми» значениями задач за
последние retro.days дней. Наблюдаемые (адреса, домены, URL, хэши, JA3/JA4)
извлекаются из логов Zeek/Suricata один раз и кешируются в observables.json
рядом с отчётом, поэтому повторные проверки почти ничего не стоят.

Если находится совпадение, которого не было в отчёте, оно записывается в
retro_hits, а отчёт задачи пересобирается с актуальной базой IOC.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from .config import Config
from .db import DB
from .ioc_store import Indicator, IOCIndex
from .ioc_types import norm_url
from .report import read_log, suri_ts

log = logging.getLogger("trafficlens.retro")
OBS_FILE = "observables.json"
OBS_VERSION = 1
KINDS = ("ip", "domain", "url", "md5", "sha1", "sha256", "ja3", "ja4")


def _job_dir(cfg: Config, job_id: str) -> Path:
    return cfg.jobs_dir / job_id


def extract(job_dir: Path) -> dict:
    """{kind: {value: первое_время}} по логам задачи."""
    z, s = job_dir / "zeek", job_dir / "suricata"
    obs: dict[str, dict] = {k: {} for k in KINDS}

    def put(kind: str, value, ts) -> None:
        if not value:
            return
        v = str(value).strip().strip(".").lower() if kind != "url" else str(value)
        d = obs[kind]
        t = float(ts or 0)
        if v not in d or (t and t < d[v]):
            d[v] = t

    for r in read_log(z / "conn.log"):
        put("ip", r.get("id.orig_h"), r.get("ts"))
        put("ip", r.get("id.resp_h"), r.get("ts"))
    for r in read_log(z / "dns.log"):
        put("domain", r.get("query"), r.get("ts"))
        for a in r.get("answers") or []:
            a = str(a).strip(".")
            kind = "ip" if (a.replace(".", "").isdigit() or ":" in a) else "domain"
            put(kind, a, r.get("ts"))
    for r in read_log(z / "http.log"):
        host = (r.get("host") or r.get("id.resp_h") or "").lower()
        port = r.get("id.resp_p")
        hostport = host if port in (80, None) or ":" in host else f"{host}:{port}"
        put("domain", host.split(":")[0], r.get("ts"))
        put("url", norm_url("http://" + hostport + (r.get("uri") or "/")), r.get("ts"))
    for r in read_log(z / "ssl.log"):
        put("domain", r.get("server_name"), r.get("ts"))
    for r in read_log(z / "files.log"):
        for k in ("md5", "sha1", "sha256"):
            put(k, r.get(k), r.get("ts"))
    for r in read_log(s / "eve.json"):
        if r.get("event_type") == "tls":
            t = r.get("tls") or {}
            ts = suri_ts(r.get("timestamp", ""))
            if isinstance(t.get("ja3"), dict):
                put("ja3", t["ja3"].get("hash"), ts)
            if isinstance(t.get("ja4"), str):
                put("ja4", t["ja4"], ts)
    return {"v": OBS_VERSION, "obs": obs, "built": time.time()}


def ensure(job_dir: Path) -> dict | None:
    """observables.json задачи: читаем кеш или строим по логам. None — логов нет."""
    p = job_dir / OBS_FILE
    if p.exists():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if d.get("v") == OBS_VERSION:
                return d
        except ValueError:
            pass
    if not (job_dir / "zeek").exists():
        return None
    d = extract(job_dir)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)
    return d


def _known_hits(job_dir: Path) -> set[tuple[str, str]]:
    try:
        rep = json.loads((job_dir / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {(h.get("type"), h.get("value")) for h in rep.get("ioc_hits") or []}


def _index(rows: list[dict]) -> IOCIndex:
    idx = IOCIndex()
    for r in rows:
        idx.add(Indicator(r["type"], r["value"], r.get("info") or "", r.get("tags") or "",
                          int(r.get("confidence") or 0), r.get("port")), r["source"])
    return idx


def match(idx: IOCIndex, obs: dict) -> list[tuple]:
    """[(Match, наблюдаемое значение, время)] — совпадения наблюдаемых с индексом."""
    out = []
    o = obs.get("obs") or {}
    for v, ts in (o.get("ip") or {}).items():
        m = idx.ip(v)
        if m:
            out.append((m, v, ts))
    for v, ts in (o.get("domain") or {}).items():
        m = idx.domain(v)
        if m:
            out.append((m, v, ts))
    for v, ts in (o.get("url") or {}).items():
        m = idx.url(v)
        if m:
            out.append((m, v, ts))
    for kind in ("md5", "sha1", "sha256", "ja3", "ja4"):
        for v, ts in (o.get(kind) or {}).items():
            m = idx.hash(kind, v)
            if m:
                out.append((m, v, ts))
    return out


def run(cfg: Config, db: DB, full: bool = False) -> dict:
    """Ретропроверка. full=False — только IOC, появившиеся после прошлого запуска."""
    from . import pipeline   # pipeline импортирует report; избегаем цикла на уровне модуля

    rc = cfg.get("retro") or {}
    started = time.time()
    last = 0.0 if full else float(db.kv_get("retro_last", 0) or 0)
    rows = db.iocs_since(last)
    status = {"ts": started, "full": full, "new_iocs": len(rows), "jobs": 0, "hits": 0, "jobs_hit": 0}
    if not rows:
        db.kv_set("retro_last", started)
        db.kv_set("retro_status", status)
        return status
    idx = _index(rows)
    horizon = started - float(rc.get("days", 30)) * 86400
    jobs = [j for j in db.jobs(limit=int(rc.get("max_jobs", 2000)))
            if j["status"] == "done" and (j.get("finished") or j["created"]) >= horizon]
    hit_jobs = []
    for j in jobs:
        jd = _job_dir(cfg, j["id"])
        try:
            obs = ensure(jd)
        except Exception:  # noqa: BLE001 — одна битая задача не должна останавливать проверку
            log.exception("observables %s", j["id"])
            continue
        if not obs:
            continue
        status["jobs"] += 1
        found = match(idx, obs)
        if not found:
            continue
        known = _known_hits(jd)
        new_rows = []
        for m, observed, ts in found:
            if (m.type, m.value) in known:
                continue          # уже было в отчёте на момент анализа
            for e in m.entries:
                new_rows.append({"job_id": j["id"], "ioc_type": m.type, "ioc_value": m.value, "source": e["source"],
                                 "observed": observed, "info": (e.get("info") or "")[:300],
                                 "confidence": int(e.get("confidence") or 0), "seen_ts": ts or None, "detected": started})
        added = db.add_retro_hits(new_rows)
        if added:
            status["hits"] += added
            hit_jobs.append(j["id"])
    for jid in hit_jobs:
        try:
            pipeline.rematch(cfg, db, jid, send=False)
            # сначала retro_hit (с временем в трафике), затем ioc_hit по пересобранному отчёту
            pipeline.notify(cfg, db, jid, retro_rows=[h for h in db.retro_hits(job_id=jid) if h["detected"] == started])
        except Exception:  # noqa: BLE001
            log.exception("rematch %s", jid)
    status["jobs_hit"] = len(hit_jobs)
    status["took"] = round(time.time() - started, 1)
    db.kv_set("retro_last", started)
    db.kv_set("retro_status", status)
    log.info("retro: %s", status)
    return status

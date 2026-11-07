"""Отправка находок в Graylog по GELF (UDP или TCP).

События (поле tl_event):
  verdict   — итог задачи уровня не ниже gelf.min_level: файл, score, причины, хосты, ссылка на отчёт;
  ioc_hit   — каждое совпадение с IOC (по одному сообщению на индикатор);
  retro_hit — совпадение, найденное ретропроверкой после анализа.

Повторная пересборка отчёта не шлёт уже отправленное: что ушло по задаче,
хранится в kv (gelf_sent:<job>). Отправка — «лучшее усилие»: ошибка сети
пишется в журнал и не ломает анализ.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import time
import zlib

log = logging.getLogger("trafficlens.gelf")
LEVELS = {"clean": 0, "suspicious": 1, "critical": 2}
SYSLOG = {"critical": 2, "suspicious": 4, "clean": 6}   # crit / warning / info
CHUNK = 8000          # байт полезной нагрузки в UDP-чанке (меньше типичного MTU-предела Graylog 8192)
MAX_CHUNKS = 128


def _cfg(cfg) -> dict:
    return (cfg.get("gelf") or {}) if isinstance(cfg, dict) else {}


def enabled(cfg) -> bool:
    g = _cfg(cfg)
    return bool(g.get("enabled") and g.get("host"))


def _udp_packets(payload: bytes) -> list[bytes]:
    data = zlib.compress(payload)
    if len(data) <= CHUNK:
        return [data]
    parts = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
    if len(parts) > MAX_CHUNKS:
        raise ValueError("сообщение GELF слишком большое")
    mid = os.urandom(8)
    return [b"\x1e\x0f" + mid + struct.pack("BB", n, len(parts)) + p for n, p in enumerate(parts)]


class Sender:
    def __init__(self, cfg):
        g = _cfg(cfg)
        self.host, self.port = g.get("host"), int(g.get("port") or 12201)
        self.proto = (g.get("protocol") or "udp").lower()
        self.source = g.get("source") or socket.gethostname()
        self._sock = None

    def __enter__(self):
        fam = socket.AF_INET6 if ":" in (self.host or "") else socket.AF_INET
        if self.proto == "tcp":
            self._sock = socket.create_connection((self.host, self.port), timeout=5)
        else:
            self._sock = socket.socket(fam, socket.SOCK_DGRAM)
            self._sock.settimeout(5)
        return self

    def __exit__(self, *exc):
        if self._sock:
            self._sock.close()

    def send(self, short: str, fields: dict, level: int = 6, full: str = "", ts: float | None = None) -> None:
        msg = {"version": "1.1", "host": self.source, "short_message": short[:250], "timestamp": ts or time.time(),
               "level": level, "_tl_source": "trafficlens"}
        if full:
            msg["full_message"] = full
        for k, v in fields.items():
            if v is None or v == "" or v == []:
                continue
            if isinstance(v, (list, tuple, set)):
                v = ", ".join(str(x) for x in v)
            key = "_" + "".join(c if c.isalnum() or c == "_" else "_" for c in k)
            msg[key] = v if isinstance(v, (int, float)) else str(v)[:32000]
        payload = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        if self.proto == "tcp":
            self._sock.sendall(payload + b"\x00")
        else:
            for pkt in _udp_packets(payload):
                self._sock.sendto(pkt, (self.host, self.port))


def _report_url(cfg, job_id: str, anchor: str = "") -> str:
    base = (_cfg(cfg).get("base_url") or "").rstrip("/")
    return f"{base}/jobs/{job_id}{anchor}" if base else ""


def notify_job(cfg, db, job: dict, rep: dict, retro_rows: list[dict] | None = None) -> int:
    """Отправить новые для этой задачи события. Возвращает число отправленных сообщений."""
    if not enabled(cfg):
        return 0
    g = _cfg(cfg)
    v = rep.get("verdict") or {}
    level = v.get("level", "clean")
    key = f"gelf_sent:{job['id']}"
    sent = db.kv_get(key, {}) or {}
    sent_level = sent.get("level", "clean")
    sent_iocs = set(sent.get("iocs") or [])
    sent_retro = set(sent.get("retro") or [])
    min_level = LEVELS.get(g.get("min_level", "suspicious"), 1)
    meta = rep.get("meta") or {}
    hosts = [h.get("ip") for h in (rep.get("priority_hosts") or [])[:5]]
    host_names = {}
    for sec in ("local_hosts", "priority_hosts"):
        for h in rep.get(sec) or []:
            if isinstance(h, dict) and h.get("ip") and h.get("name"):
                host_names[h["ip"]] = h["name"]

    def names_for(ips):
        return [host_names[i] for i in ips if i in host_names]
    common = {"tl_job": job["id"], "tl_file": job.get("filename") or meta.get("filename", ""),
              "tl_job_source": job.get("source", ""), "tl_level": level, "tl_score": v.get("score", 0),
              "tl_report": _report_url(cfg, job["id"])}
    n = 0
    try:
        with Sender(cfg) as s:
            if LEVELS.get(level, 0) >= min_level and LEVELS.get(level, 0) > LEVELS.get(sent_level, 0):
                reasons = [r.get("k", "") + ":" + str(r.get("target") or r.get("v") or r.get("name") or "")
                           for r in (v.get("reasons") or [])[:8] if isinstance(r, dict)]
                t = rep.get("totals") or {}
                s.send(f"TrafficLens: {level} — {common['tl_file']} (score {v.get('score', 0)})",
                       {**common, "tl_event": "verdict", "tl_hosts": hosts, "tl_host_names": names_for(hosts), "tl_reasons": reasons,
                        "tl_ioc_hits": t.get("ioc_hits", 0), "tl_alerts": t.get("alerts", 0), "tl_files": t.get("files", 0),
                        "tl_period_start": (meta.get("period") or {}).get("start"), "tl_gated": bool(v.get("gated"))},
                       level=SYSLOG.get(level, 6))
                sent_level = level
                n += 1
            for r in retro_rows or []:
                k = f"{r['ioc_type']}|{r['ioc_value']}|{r['source']}"
                if k in sent_retro:
                    continue
                s.send(f"TrafficLens ретропроверка: {r['ioc_value']} в {common['tl_file']}",
                       {**common, "tl_event": "retro_hit", "tl_ioc_type": r["ioc_type"], "tl_ioc_value": r["ioc_value"],
                        "tl_ioc_source": r["source"], "tl_ioc_info": r.get("info", ""), "tl_ioc_conf": r.get("confidence", 0),
                        "tl_observed": r.get("observed", ""), "tl_seen_ts": r.get("seen_ts"),
                        "tl_report": _report_url(cfg, job["id"], "#ioc")}, level=2)
                sent_retro.add(k)
                n += 1
            if g.get("send_ioc_hits", True):
                for h in rep.get("ioc_hits") or []:
                    k = f"{h.get('type')}|{h.get('value')}"
                    if k in sent_iocs:
                        continue
                    src = (h.get("sources") or [{}])[0]
                    s.send(f"TrafficLens IOC: {h.get('value')} ({h.get('type')}) — {common['tl_file']}",
                           {**common, "tl_event": "ioc_hit", "tl_ioc_type": h.get("type"), "tl_ioc_value": h.get("value"),
                            "tl_ioc_source": src.get("source", ""), "tl_ioc_info": src.get("info", ""),
                            "tl_ioc_conf": h.get("max_conf", 0), "tl_hosts": h.get("hosts", [])[:10],
                            "tl_host_names": names_for(h.get("hosts", [])[:10]),
                            "tl_observed": h.get("observed", [])[:10], "tl_contexts": list((h.get("contexts") or {}).keys()),
                            "tl_first_seen": h.get("first"), "tl_count": h.get("count", 0),
                            "tl_report": _report_url(cfg, job["id"], "#ioc")},
                           level=2 if (h.get("max_conf") or 0) >= 70 else 4)
                    sent_iocs.add(k)
                    n += 1
    except (OSError, ValueError) as e:
        log.warning("GELF %s:%s: %s", _cfg(cfg).get("host"), _cfg(cfg).get("port"), e)
        db.kv_set("gelf_status", {"ts": time.time(), "ok": False, "error": str(e)[:200]})
        return n
    if n:
        db.kv_set(key, {"level": sent_level, "iocs": sorted(sent_iocs), "retro": sorted(sent_retro)})
        db.kv_set("gelf_status", {"ts": time.time(), "ok": True, "sent": n})
    return n


def test_message(cfg, db) -> tuple[bool, str]:
    if not enabled(cfg):
        return False, "gelf_err_disabled"
    try:
        with Sender(cfg) as s:
            s.send("TrafficLens: тестовое сообщение", {"tl_event": "test"}, level=6)
    except OSError as e:
        db.kv_set("gelf_status", {"ts": time.time(), "ok": False, "error": str(e)[:200]})
        return False, str(e)[:200]
    db.kv_set("gelf_status", {"ts": time.time(), "ok": True, "sent": 1})
    return True, ""

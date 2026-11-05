"""Отрисовка HTML: фильтры Jinja и автономный отчёт."""
from __future__ import annotations

import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .i18n import bundle as i18n_bundle

PKG = Path(__file__).parent
STATIC = PKG / "static"


def fmt_bytes(n) -> str:
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "—"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_ts(ts, fmt: str = "%d.%m.%Y %H:%M:%S") -> str:
    if not ts:
        return "—"
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return "—"


def fmt_dur(sec) -> str:
    try:
        sec = float(sec or 0)
    except (TypeError, ValueError):
        return "—"
    if sec < 1:
        return f"{sec * 1000:.0f} мс"
    if sec < 60:
        return f"{sec:.1f} с"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d} д {h} ч"
    if h:
        return f"{h} ч {m} мин"
    return f"{m} мин {s} с"


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "—"


def fmt_bucket(sec: int) -> str:
    if sec < 60:
        return f"{sec} с"
    if sec < 3600:
        return f"{sec // 60} мин"
    if sec < 86400:
        return f"{sec // 3600} ч"
    return f"{sec // 86400} д"


def env() -> Environment:
    e = Environment(loader=FileSystemLoader(str(PKG / "templates")), autoescape=select_autoescape(["html"]),
                    trim_blocks=True, lstrip_blocks=True)
    e.filters.update(bytes=fmt_bytes, ts=fmt_ts, dur=fmt_dur, int=fmt_int, bucket=fmt_bucket)
    e.globals["inline_css"] = lambda: (STATIC / "style.css").read_text(encoding="utf-8")
    e.globals["inline_js"] = lambda name: (STATIC / name).read_text(encoding="utf-8")
    e.globals["max"] = max
    return e


_ENV = None


def get_env() -> Environment:
    global _ENV
    if _ENV is None:
        _ENV = env()
    return _ENV


def _ensure_graph(rep: dict) -> None:
    """Достраивает граф для отчётов, собранных старыми версиями (в JSON нет ключа graph).

    Источник — сохранённые connections; имена и признаки local/ioc берём из
    local_hosts и top_external. Для новых отчётов graph уже построен в report.py.
    """
    if rep.get("graph") is not None:
        return
    names: dict[str, str] = {}
    locals_: set[str] = set()
    iocs: set[str] = set()
    for h in rep.get("local_hosts", []):
        ip = h.get("ip")
        if not ip:
            continue
        locals_.add(ip)
        if h.get("name"):
            names[ip] = h["name"]
    for e in rep.get("top_external", []):
        ip = e.get("ip")
        if not ip:
            continue
        if e.get("name"):
            names[ip] = e["name"]
        if e.get("ioc"):
            iocs.add(ip)
    nodes: dict[str, dict] = {}
    links = []
    for c in rep.get("connections", [])[:150]:
        src, dst = c.get("src"), c.get("dst")
        if not src or not dst:
            continue
        tot = (c.get("ob") or 0) + (c.get("rb") or 0)
        for ip in (src, dst):
            n = nodes.setdefault(ip, {"id": ip, "name": names.get(ip, ""), "local": ip in locals_, "ioc": ip in iocs, "bytes": 0})
            n["bytes"] += tot
        links.append({"source": src, "target": dst, "bytes": tot, "proto": c.get("proto", ""), "port": c.get("dp"), "ioc": bool(c.get("ioc"))})
    rep["graph"] = {"nodes": list(nodes.values()), "links": links}


def render_report(rep: dict, embedded: bool = False, job: dict | None = None, lang: str = "ru") -> str:
    _ensure_graph(rep)
    return get_env().get_template("report.html").render(r=rep, embedded=embedded, job=job or {}, lang=lang, L=i18n_bundle(lang))

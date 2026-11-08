"""Отрисовка HTML: фильтры Jinja и автономный отчёт."""
from __future__ import annotations

import json
import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, pass_context, select_autoescape

from .i18n import bundle as i18n_bundle
from . import mitre, quality

PKG = Path(__file__).parent
STATIC = PKG / "static"


def fmt_bytes(n, lang: str = "ru") -> str:
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "—"
    units = ("Б", "КБ", "МБ", "ГБ", "ТБ") if lang != "en" else ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if abs(n) < 1024 or unit == units[-1]:
            return f"{n:.0f} {unit}" if unit == units[0] else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_ts(ts, fmt: str = "%d.%m.%Y %H:%M:%S") -> str:
    if not ts:
        return "—"
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return "—"


def fmt_dur(sec, lang: str = "ru") -> str:
    try:
        sec = float(sec or 0)
    except (TypeError, ValueError):
        return "—"
    u = ("мс", "с", "мин", "ч", " д ") if lang != "en" else ("ms", "s", "min", "h", " d ")
    if sec < 1:
        return f"{sec * 1000:.0f} {u[0]}"
    if sec < 60:
        return f"{sec:.1f} {u[1]}"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d}{u[4]}{h} {u[3]}"
    if h:
        return f"{h} {u[3]} {m} {u[2]}"
    return f"{m} {u[2]} {s} {u[1]}"


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "—"


def fmt_bucket(sec: int, lang: str = "ru") -> str:
    if lang == "en":
        if sec < 60:
            return f"{sec} s"
        if sec < 3600:
            return f"{sec // 60} min"
        if sec < 86400:
            return f"{sec // 3600} h"
        return f"{sec // 86400} d"
    if sec < 60:
        return f"{sec} с"
    if sec < 3600:
        return f"{sec // 60} мин"
    if sec < 86400:
        return f"{sec // 3600} ч"
    return f"{sec // 86400} д"


def _fmt_l(L: dict, key: str, params: dict) -> str:
    """L[key].format(**params) с защитой от неизвестных ключей и параметров."""
    try:
        return L.get(key, key).format(**params)
    except (KeyError, IndexError, ValueError):
        return key


def loc_reason(L: dict, v) -> str:
    """Причина из report.json: dict {k, ...} -> локализованная строка; str (старые отчёты) -> как есть."""
    if not isinstance(v, dict):
        return str(v)
    params = {pk: pv for pk, pv in v.items() if pk not in ("k", "pts")}
    if "t" in params:  # тип IOC локализуем отдельно
        params["t"] = L.get("ioc_type_" + str(params["t"]), params["t"])
    text = _fmt_l(L, str(v.get("k", "")), params)
    return f"+{v['pts']} {text}" if v.get("pts") is not None else text


def loc_feed(L: dict, v) -> str:
    """Сообщение источника IOC: JSON-токен -> локализованная строка; иначе как есть."""
    if isinstance(v, str) and v.startswith("{"):
        try:
            d = json.loads(v)
        except ValueError:
            return v
        if isinstance(d, dict) and "k" in d:
            params = {pk: pv for pk, pv in d.items() if pk != "k"}
            if isinstance(params.get("hint"), str) and params["hint"].startswith("feed_err_"):
                params["hint"] = (" " + L.get(params["hint"], "")) if params["hint"] else ""
            return _fmt_l(L, str(d["k"]), params)
    return str(v)


def loc_ctx(L: dict, v) -> str:
    v = str(v)
    return L.get(v) or L.get("ctx_" + v, v)  # токены хранятся с префиксом ctx_ (новые) или без (старой сборки)


def loc_dir(L: dict, v) -> str:
    return L.get("dir_" + str(v), str(v))


def loc_sev(L: dict, v, fallback=None) -> str:
    return L.get("sev_" + str(v), fallback or str(v))


def loc_ioc(L: dict, v, fallback=None) -> str:
    return L.get("ioc_type_" + str(v), fallback or str(v))


# ---------------------------------------------------------------- уверенность в находках
# fact — прямое наблюдение в логах (совпадение с IOC, срабатывание сигнатуры,
# перехваченный файл/учётные данные, отказ валидации TLS); heuristic —
# статистическая или пороговая оценка (маячки, крупные выгрузки, нестандартные
# порты, подозрительные DNS-имена) — чаще даёт ложные срабатывания.
EVIDENCE = {"ioc": "fact", "alert": "fact", "file": "fact", "cleartext": "fact", "tls": "fact",
            "beacon": "heuristic", "upload": "heuristic", "unusual": "heuristic", "dns": "heuristic"}


def evidence_of_reason(v) -> str:
    """Причина вердикта/риска ({k: vr_*/hr_*}) -> 'fact' | 'heuristic' | '' (неизвестно/строка)."""
    if not isinstance(v, dict):
        return ""
    return EVIDENCE.get(str(v.get("k", "")).split("_", 1)[-1], "")


def ev_badge(L: dict, v) -> "Markup":
    """HTML-бейдж уверенности для причины вердикта/риска; пусто, если тип неизвестен."""
    from markupsafe import Markup, escape

    ev = evidence_of_reason(v)
    if not ev:
        return Markup("")
    cls = "ok" if ev == "fact" else "warn"
    return Markup('<span class="badge {c}" title="{t}">{s}</span>').format(
        c=cls, t=escape(L.get(f"ev_{ev}_hint", "")), s=escape(L.get(f"ev_{ev}", ev)))


def env() -> Environment:
    e = Environment(loader=FileSystemLoader(str(PKG / "templates")), autoescape=select_autoescape(["html"]),
                    trim_blocks=True, lstrip_blocks=True)
    e.filters.update(ts=fmt_ts, int=fmt_int)
    e.filters["bytes"] = pass_context(lambda ctx, v: fmt_bytes(v, ctx.get("lang", "ru")))
    e.filters["dur"] = pass_context(lambda ctx, v: fmt_dur(v, ctx.get("lang", "ru")))
    e.filters["bucket"] = pass_context(lambda ctx, v: fmt_bucket(v, ctx.get("lang", "ru")))
    e.filters["lctx"] = pass_context(lambda ctx, v: loc_ctx(ctx.get("L", {}), v))
    e.filters["ldir"] = pass_context(lambda ctx, v: loc_dir(ctx.get("L", {}), v))
    e.filters["lsev"] = pass_context(lambda ctx, v, fallback=None: loc_sev(ctx.get("L", {}), v, fallback))
    e.filters["lioc"] = pass_context(lambda ctx, v, fallback=None: loc_ioc(ctx.get("L", {}), v, fallback))
    e.filters["lreason"] = pass_context(lambda ctx, v: loc_reason(ctx.get("L", {}), v))
    e.filters["evbadge"] = pass_context(lambda ctx, v: ev_badge(ctx.get("L", {}), v))
    e.filters["lfeed"] = pass_context(lambda ctx, v: loc_feed(ctx.get("L", {}), v))
    e.globals["inline_css"] = lambda: (STATIC / "style.css").read_text(encoding="utf-8")
    e.globals["inline_js"] = lambda name: (STATIC / name).read_text(encoding="utf-8")
    e.globals["max"] = max
    e.globals["mitre_summary"] = mitre.mitre_summary
    e.globals["tls_is_weak"] = quality.tls_is_weak
    e.globals["tls_strong"] = quality.tls_strong
    e.globals["mitre_alert"] = mitre.alert_tags
    e.globals["mitre_tactics"] = mitre.TACTICS
    e.globals["mitre_techniques"] = mitre.TECHNIQUES
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


def render_report(rep: dict, embedded: bool = False, job: dict | None = None, lang: str = "ru",
                  elsewhere: dict | None = None, jobnames: dict | None = None) -> str:
    _ensure_graph(rep)
    return get_env().get_template("report.html").render(r=rep, embedded=embedded, job=job or {}, lang=lang,
                                                        L=i18n_bundle(lang),
                                                        elsewhere=elsewhere or {}, jobnames=jobnames or {})

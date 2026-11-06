"""Разметка аналитика: статусы находок по задаче и глобальный allowlist.

Статусы (new — без разметки, confirmed, false_positive, ignored) хранятся
в таблице marks, allowlist — в таблице allowlist (общий для всех задач).
При сборке/пересверке отчёта apply() проставляет находкам поля status и wl;
находки со статусами false_positive/ignored или из allowlist не участвуют
в скоринговом вердикте и в риске приоритетных хостов (см. report.py).

Ключи находок должны совпадать с тем, что рендерят шаблоны (report.html),
поэтому key_of() единый для apply() и для Jinja (через globals в render.py).
"""
from __future__ import annotations

STATUSES = ("new", "confirmed", "false_positive", "ignored")
KINDS = ("ioc", "alert", "file", "beacon", "upload", "cleartext", "unusual", "tls", "dns")
SKIP = {"false_positive", "ignored"}  # не дают очков в вердикте и риске хостов


def skipped(item: dict) -> bool:
    """True, если находка снята с учёта: в allowlist или ложная/проигнорированная."""
    return bool(item.get("wl")) or item.get("status") in SKIP


def key_of(kind: str, it: dict) -> str:
    """Стабильный ключ находки по её типу (должен совпадать в apply() и в шаблоне)."""
    if kind == "ioc":
        return it.get("value", "")
    if kind == "alert":
        return str(it.get("sid", ""))
    if kind == "file":
        return it.get("sha256") or it.get("filename", "")
    if kind == "beacon":
        return f'{it.get("src", "")}>{it.get("dst", "")}:{it.get("dp", "")}'
    if kind == "upload":
        return f'{it.get("src", "")}>{it.get("dst", "")}'
    if kind == "cleartext":
        return f'{it.get("proto", "")}|{it.get("src", "")}>{it.get("dst", "")}|{it.get("user") or ""}'
    if kind == "unusual":
        return f'{it.get("dst", "")}:{it.get("port", "")}/{it.get("proto", "")}'
    if kind == "tls":
        return f'{it.get("src", "")}>{it.get("dst", "")}|{it.get("sni") or ""}'
    if kind == "dns":
        return it.get("name", "")
    return ""


def apply(rep: dict, marks: dict | None, allow: dict | None) -> None:
    """Проставить status/wl всем находкам отчёта (на месте, без копий)."""
    if not marks and not allow:
        return
    marks = marks or {}
    allow = allow or {}

    def flag(kind: str, it: dict) -> None:
        k = key_of(kind, it)
        if not k:
            return
        m = marks.get((kind, k))
        if m:
            it["status"] = m["status"]
            if m.get("note"):
                it["status_note"] = m["note"]
        if (kind, k) in allow:
            it["wl"] = True

    for h in rep.get("ioc_hits") or []:
        flag("ioc", h)
    for a in rep.get("alerts") or []:
        flag("alert", a)
    for x in rep.get("files") or []:
        if x.get("ioc"):
            flag("file", x)
    f = rep.get("findings") or {}
    for coll, kind in (("beacons", "beacon"), ("large_uploads", "upload"), ("unusual_ports", "unusual"),
                       ("cleartext", "cleartext"), ("cleartext_auth", "cleartext")):
        for it in f.get(coll) or []:
            flag(kind, it)
    for t in (rep.get("tls") or {}).get("invalid") or []:
        flag("tls", t)
    for d in (rep.get("dns") or {}).get("suspicious") or []:
        flag("dns", d)

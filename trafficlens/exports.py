"""Экспорт находок отчёта в CSV.

Кодировка — UTF-8 с BOM (utf-8-sig): так Excel на Windows открывает файл
двойным кликом без ручного выбора кодировки, LibreOffice тоже понимает BOM.
Заголовки колонок — технические (англ.), значения причин/контекстов
локализуются через render.loc_* по языку запроса.
"""
from __future__ import annotations

import csv
import io
import time

from . import mitre
from .i18n import bundle as i18n_bundle
from .render import loc_ctx, loc_dir, loc_reason, loc_sev

KINDS = ("iocs", "files", "alerts", "hosts")


def _ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


def _status(it: dict, L: dict) -> str:
    st = it.get("status") or "new"
    return L.get(f"mark_{st}", st)


def _csv(rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")


def build_csv(rep: dict, what: str, lang: str = "ru") -> bytes | None:
    """Собрать CSV по разделу отчёта; None, если раздел неизвестен."""
    L = i18n_bundle(lang)
    if what == "iocs":
        rows = [["type", "value", "observed", "sources", "confidence", "count",
                 "first", "last", "hosts", "status", "allowlist"]]
        for h in rep.get("ioc_hits") or []:
            rows.append([
                h.get("type", ""), h.get("value", ""), ";".join(h.get("observed") or []),
                ";".join(sorted({e.get("source", "") for e in h.get("sources") or []})),
                h.get("max_conf", 0), h.get("count", 0),
                _ts(h.get("first")), _ts(h.get("last")),
                ";".join(h.get("hosts") or []), _status(h, L), "yes" if h.get("wl") else "",
            ])
        return _csv(rows)
    if what == "files":
        rows = [["ts", "proto", "sender", "receiver", "direction", "filename",
                 "mime", "size", "sha256", "md5", "ioc", "status", "allowlist"]]
        for f in rep.get("files") or []:
            rows.append([
                _ts(f.get("ts")), f.get("proto", ""), f.get("sender", ""), f.get("receiver", ""),
                loc_dir(L, f.get("direction")), f.get("filename", ""), f.get("mime", ""),
                f.get("size", 0), f.get("sha256", ""), f.get("md5", ""),
                "yes" if f.get("ioc") else "", _status(f, L), "yes" if f.get("wl") else "",
            ])
        return _csv(rows)
    if what == "alerts":
        rows = [["sid", "signature", "category", "severity", "mitre", "count",
                 "first", "last", "pairs", "status", "allowlist"]]
        for a in rep.get("alerts") or []:
            techs = [t for _, t in mitre.alert_tags(a.get("category", ""))]
            rows.append([
                a.get("sid", ""), a.get("signature", ""), a.get("category", ""),
                loc_sev(L, a.get("severity")), ";".join(techs), a.get("count", 0),
                _ts(a.get("first")), _ts(a.get("last")),
                ";".join(a.get("pairs") or []), _status(a, L), "yes" if a.get("wl") else "",
            ])
        return _csv(rows)
    if what == "hosts":
        rows = [["ip", "name", "mac", "score", "level", "reasons", "indicators", "external"]]
        for h in rep.get("priority_hosts") or []:
            rows.append([
                h.get("ip", ""), h.get("name", ""), h.get("mac", ""), h.get("score", 0),
                h.get("level", ""),
                "; ".join(loc_reason(L, r) for r in h.get("reasons") or []),
                ";".join(h.get("indicators") or []), ";".join(h.get("external") or []),
            ])
        return _csv(rows)
    return None


# ---------------------------------------------------------------- IOC для Graylog
EXPORT_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "ja3", "ja4")


def iocs_csv(db, types: set | None = None, min_conf: int = 0) -> bytes:
    """Одна строка на (тип, значение): источники через «|», описание, максимальная уверенность.

    Без BOM: файл читает не человек, а адаптер Graylog «DSV File from HTTP»
    (ключ — колонка value, значение — info или source).
    """
    want = [t for t in EXPORT_TYPES if not types or t in types]
    if types and "cidr" in types:
        want.append("cidr")
    if not want:
        want = list(EXPORT_TYPES)
    marks = ",".join("?" * len(want))
    with db.conn() as c:
        rows = c.execute(
            f"SELECT type, value, GROUP_CONCAT(source, '|') AS sources, MAX(confidence) AS conf, "
            f"MAX(CASE WHEN info != '' THEN info END) AS info FROM iocs WHERE type IN ({marks}) "
            f"GROUP BY type, value HAVING MAX(confidence) >= ? ORDER BY type, value",
            (*want, int(min_conf))).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["value", "type", "source", "info", "confidence"])
    for r in rows:
        w.writerow([r["value"], r["type"], r["sources"], (r["info"] or "").replace("\n", " ")[:300], r["conf"]])
    return buf.getvalue().encode("utf-8")

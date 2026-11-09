"""Источники IOC: abuse.ch, MISP, OpenCTI, собственные списки."""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
from pathlib import Path

import requests

from . import listfeeds
from .config import Config
from .db import DB
from .ioc_store import Indicator, save_source
from .ioc_types import detect

log = logging.getLogger("trafficlens.feeds")
UA = {"User-Agent": "TrafficLens/1.0"}
TIMEOUT = 90


class FeedError(Exception):
    pass


def _ind(value: str, hint: str | None = None, info: str = "", tags="", conf: int = 0, port: int | None = None):
    d = detect(value, hint)
    if not d:
        return None
    t, v, p = d
    if isinstance(tags, (list, tuple)):
        tags = ",".join(str(x) for x in tags if x)
    return Indicator(t, v, info or "", tags or "", int(conf or 0), port if port is not None else p)


# ------------------------------------------------------------------ abuse.ch
def _abusech_headers(key: str) -> dict:
    h = dict(UA)
    if key:
        h["Auth-Key"] = key
    return h


def fetch_urlhaus(key: str) -> list[Indicator]:
    if not key:
        raise FeedError("feed_err_need_key")
    r = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers=_abusech_headers(key), timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") not in ("ok", None):
        raise FeedError(f"URLhaus: {data.get('query_status')}")
    out = []
    for u in data.get("urls") or []:
        i = _ind(u.get("url", ""), "url", info=f"URLhaus: {u.get('threat') or ''} ({u.get('url_status') or ''})",
                 tags=u.get("tags") or [], conf=75)
        if i:
            out.append(i)
    return out


THREATFOX_TYPES = {"ip:port": None, "domain": "domain", "url": "url",
                   "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}


def fetch_threatfox(key: str, days: int = 7) -> list[Indicator]:
    if not key:
        raise FeedError("feed_err_need_key")
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": min(int(days), 7)},
                      headers=_abusech_headers(key), timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") not in ("ok", "no_result"):
        raise FeedError(f"ThreatFox: {data.get('query_status')}")
    out = []
    for e in data.get("data") or []:
        t = e.get("ioc_type", "")
        if t not in THREATFOX_TYPES:
            continue
        info = f"ThreatFox: {e.get('malware_printable') or e.get('malware') or ''} — {e.get('threat_type_desc') or e.get('threat_type') or ''}"
        i = _ind(e.get("ioc", ""), THREATFOX_TYPES[t], info=info, tags=e.get("tags") or [], conf=e.get("confidence_level") or 50)
        if i:
            out.append(i)
    return out


def fetch_feodo(key: str) -> list[Indicator]:
    r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=_abusech_headers(key), timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for e in r.json():
        i = _ind(e.get("ip_address", ""), info=f"Feodo Tracker: {e.get('malware') or 'botnet C2'} ({e.get('status') or ''})",
                 tags=["c2", (e.get("malware") or "").lower()], conf=90, port=e.get("port"))
        if i:
            out.append(i)
    return out


# ------------------------------------------------------------------ открытые списки без ключа
SPAMHAUS_DROP = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")
ET_COMPROMISED = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
TOR_EXITS = "https://check.torproject.org/torbulkexitlist"


def _plain_ips(text: str, info: str, tags, conf: int) -> list[Indicator]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            i = _ind(line, info=info, tags=tags, conf=conf)
            if i and i.type in ("ip", "cidr"):
                out.append(i)
    return out


def fetch_spamhaus_drop() -> list[Indicator]:
    """Spamhaus DROP / DROPv6: JSON Lines {"cidr": ..., "sblid": ...}; последняя строка — метаданные."""
    out: list[Indicator] = []
    for url in SPAMHAUS_DROP:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                cidr = e.get("cidr")
                if not cidr:
                    continue
                i = _ind(cidr, info=f"Spamhaus DROP {e.get('sblid') or ''}".strip(), tags=["drop"], conf=90)
            else:  # старый текстовый формат «cidr ; SBLxxxx»
                i = (_plain_ips(line, "Spamhaus DROP", ["drop"], 90) or [None])[0]
            if i:
                out.append(i)
    return out


def fetch_et_compromised() -> list[Indicator]:
    r = requests.get(ET_COMPROMISED, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return _plain_ips(r.text, "Emerging Threats: compromised host", ["compromised"], 60)


def fetch_tor_exits() -> list[Indicator]:
    r = requests.get(TOR_EXITS, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return _plain_ips(r.text, "Tor exit node", ["tor"], 20)


SSLBL_JA3 = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

# Классика из публичных материалов Salesforce JA3 / MITRE — на случай,
# если фид SSLBL недоступен (он заморожен в 2021, но хеши не протухают).
CURATED_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Tor client",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot",
    "51c64c77e60f3980eea90869b68c58a8": "Dridex",
    "74927e242d6c3febf8cb9cab10a7f889": "Dridex",
    "5d65ea3fb1d4aa7d826733d2f2cbbb1d": "Meterpreter (Linux)",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default beacon)",
}


def fetch_sslbl_ja3() -> list[Indicator]:
    """abuse.ch SSLBL: вредоносные отпечатки JA3 + курируемая классика."""
    out: list[Indicator] = []
    seen = set()
    try:
        r = requests.get(SSLBL_JA3, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        for row in csv.reader(io.StringIO(r.text)):
            if not row or row[0].startswith("#"):
                continue
            ja3, reason = row[0].strip().lower(), (row[3].strip() if len(row) > 3 else "")
            i = _ind(ja3, "ja3", info=f"SSLBL: {reason}", tags=["sslbl", "ja3"], conf=80)
            if i:
                seen.add(ja3)
                out.append(i)
    except Exception as e:  # noqa: BLE001 — фид мог умереть, работаем на курируемом наборе
        log.warning("sslbl ja3 download failed, curated only: %s", e)
    for ja3, name in CURATED_JA3.items():
        if ja3 in seen:
            continue
        i = _ind(ja3, "ja3", info=f"curated: {name}", tags=["ja3", "curated"], conf=75)
        if i:
            out.append(i)
    return out


def fetch_malwarebazaar(key: str) -> list[Indicator]:
    if not key:
        raise FeedError("feed_err_need_key")
    out: list[Indicator] = []
    r = requests.get(f"https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv", headers=UA, timeout=TIMEOUT)
    if r.ok and r.text.count("\n") > 5 and "<html" not in r.text[:500].lower():
        for row in csv.reader(io.StringIO(r.text)):
            if not row or row[0].lstrip().startswith("#") or len(row) < 9:
                continue
            row = [c.strip().strip('"') for c in row]
            info = f"MalwareBazaar: {row[8] if row[8] not in ('', 'n/a') else row[6]} ({row[5]})"
            for col, kind in ((1, "sha256"), (2, "md5"), (3, "sha1")):
                i = _ind(row[col], kind, info=info, conf=90)
                if i:
                    out.append(i)
        return out
    # запасной путь — API, последние 100 образцов
    r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "100"},
                      headers=_abusech_headers(key), timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") != "ok":
        raise FeedError(f"MalwareBazaar: {data.get('query_status')}")
    for e in data.get("data") or []:
        info = f"MalwareBazaar: {e.get('signature') or e.get('file_type') or ''} ({e.get('file_name') or ''})"
        for fld, kind in (("sha256_hash", "sha256"), ("md5_hash", "md5"), ("sha1_hash", "sha1")):
            i = _ind(e.get(fld) or "", kind, info=info, tags=e.get("tags") or [], conf=90)
            if i:
                out.append(i)
    return out


# ------------------------------------------------------------------ MISP
MISP_TYPES = {
    "ip-src": None, "ip-dst": None, "ip-src|port": None, "ip-dst|port": None,
    "domain": "domain", "hostname": "domain", "domain|ip": None,
    "url": "url", "uri": "url", "link": "url",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256",
    "ja3-fingerprint-md5": "ja3", "ja4-fingerprint": "ja4",
}


def _verify(v):
    if isinstance(v, str) and v.lower() in ("false", "no", "0"):
        return False
    if isinstance(v, str) and v.lower() in ("true", "yes", "1", ""):
        return True
    return v


def fetch_misp(cfg: dict) -> list[Indicator]:
    url, key = cfg.get("url", "").rstrip("/"), cfg.get("key", "")
    if not url or not key:
        raise FeedError("feed_err_misp")
    out: list[Indicator] = []
    page, limit = 1, 20000
    while True:
        body = {"returnFormat": "json", "type": list(MISP_TYPES), "publish_timestamp": f"{int(cfg.get('days', 30))}d",
                "limit": limit, "page": page, "includeEventTags": False, "deleted": False}
        if cfg.get("to_ids_only", True):
            body["to_ids"] = 1
        r = requests.post(f"{url}/attributes/restSearch", json=body, timeout=TIMEOUT * 2, verify=_verify(cfg.get("verify_tls", True)),
                          headers={**UA, "Authorization": key, "Accept": "application/json", "Content-Type": "application/json"})
        r.raise_for_status()
        attrs = (r.json().get("response") or {}).get("Attribute") or []
        for a in attrs:
            t, val = a.get("type", ""), a.get("value", "")
            info = f"MISP #{a.get('event_id')}: {(a.get('Event') or {}).get('info', '')}"[:300]
            port = None
            if "|" in t:
                left, _, right = val.partition("|")
                if t.startswith("filename|"):
                    val = right
                elif t.endswith("|port"):
                    val, port = left, int(right) if right.isdigit() else None
                elif t == "domain|ip":
                    for v2, h in ((left, "domain"), (right, None)):
                        i = _ind(v2, h, info=info, conf=80)
                        if i:
                            out.append(i)
                    continue
            i = _ind(val, MISP_TYPES.get(t), info=info, conf=80, port=port)
            if i:
                out.append(i)
        if len(attrs) < limit:
            break
        page += 1
    return out


# ------------------------------------------------------------------ OpenCTI
OPENCTI_QUERY = """
query Indicators($first: Int, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters, orderBy: created_at, orderMode: desc) {
    edges { node { name pattern pattern_type x_opencti_score valid_until revoked } }
    pageInfo { endCursor hasNextPage }
  }
}"""

STIX_RE = re.compile(r"\[?\s*([a-z0-9-]+):([a-z0-9_.'\-]+(?:\.'[^']+')?)\s*=\s*'((?:[^'\\]|\\.)*)'", re.I)
STIX_MAP = {"ipv4-addr": None, "ipv6-addr": None, "domain-name": "domain", "hostname": "domain", "url": "url"}


def parse_stix(pattern: str) -> list[tuple[str, str | None]]:
    """Вытащить пары (значение, тип-подсказка) из STIX-паттерна."""
    out = []
    for obj, prop, val in STIX_RE.findall(pattern or ""):
        obj, prop = obj.lower(), prop.lower()
        if obj in STIX_MAP and prop == "value":
            out.append((val, STIX_MAP[obj]))
        elif obj == "file" and prop.startswith("hashes."):
            kind = prop.split(".", 1)[1].strip("'").replace("-", "").lower()
            if kind in ("md5", "sha1", "sha256"):
                out.append((val, kind))
        elif obj == "network-traffic" and "ja3" in prop:
            out.append((val, "ja3"))
    return out


def fetch_opencti(cfg: dict) -> list[Indicator]:
    url, token = cfg.get("url", "").rstrip("/"), cfg.get("token", "")
    if not url or not token:
        raise FeedError("feed_err_opencti")
    out: list[Indicator] = []
    after, total = None, 0
    flt = {"mode": "and", "filterGroups": [], "filters": [{"key": ["pattern_type"], "values": ["stix"]}]}
    if int(cfg.get("min_score", 0)) > 0:
        flt["filters"].append({"key": ["x_opencti_score"], "values": [str(cfg["min_score"])], "operator": "gte"})
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    while True:
        r = requests.post(f"{url}/graphql", timeout=TIMEOUT * 2, verify=_verify(cfg.get("verify_tls", True)),
                          headers={**UA, "Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                          json={"query": OPENCTI_QUERY, "variables": {"first": 500, "after": after, "filters": flt}})
        r.raise_for_status()
        payload = r.json()
        if payload.get("errors"):
            raise FeedError("OpenCTI: " + "; ".join(e.get("message", "") for e in payload["errors"])[:300])
        block = payload["data"]["indicators"]
        for edge in block["edges"]:
            n = edge["node"]
            if n.get("revoked") or (n.get("valid_until") and n["valid_until"] < now):
                continue
            for val, hint in parse_stix(n.get("pattern", "")):
                i = _ind(val, hint, info=f"OpenCTI: {n.get('name', '')}"[:300], conf=n.get("x_opencti_score") or 50)
                if i:
                    out.append(i)
        total += len(block["edges"])
        if not block["pageInfo"]["hasNextPage"] or total >= int(cfg.get("max_indicators", 200000)):
            break
        after = block["pageInfo"]["endCursor"]
    return out


# ------------------------------------------------------------------ свои списки
def parse_custom_text(text: str, source_name: str = "") -> tuple[list[Indicator], list[str]]:
    """Формат строки: `[тип:]значение [# комментарий]`. Возвращает (индикаторы, ошибки)."""
    items, errors = [], []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        comment = ""
        if " #" in line:
            line, comment = line.split(" #", 1)
            line, comment = line.strip(), comment.strip()
        hint = None
        m = re.match(r"^(ip|cidr|domain|url|md5|sha1|sha256|ja3|ja4):(.+)$", line, re.I)
        if m and not line.lower().startswith(("http:", "https:")):
            hint, line = m.group(1).lower(), m.group(2).strip()
        i = _ind(line, hint if hint != "cidr" else None, info=comment or source_name, conf=100)
        if i:
            items.append(i)
        else:
            errors.append({"k": "parse_line", "n": n, "raw": raw.strip()[:80]})
    return items, errors


def load_custom(dir_: Path) -> tuple[list[Indicator], list[str]]:
    items, errors = [], []
    for p in sorted(dir_.glob("*.txt")):
        got, errs = parse_custom_text(p.read_text(encoding="utf-8", errors="replace"), f"Свой список: {p.stem}")
        items += got
        errors += [dict(e, raw=f"{p.name}: {e['raw']}") if isinstance(e, dict) else f"{p.name}: {e}" for e in errs]
    return items, errors


FROM_REPORTS = "from-reports.txt"


def add_job_iocs_to_custom(cfg: Config, job: dict, rep: dict) -> dict:
    """Экспорт находок задачи в пользовательский список `from-reports.txt` (кнопка в отчёте).

    Берутся IOC-хиты отчёта; размеченные как ложные/игнор и уже присутствующие
    в пользовательских списках пропускаются. Возвращает счётчики для тоста."""
    existing = {i.value for i in load_custom(cfg.custom_ioc_dir)[0]}
    path = cfg.custom_ioc_dir / FROM_REPORTS
    lines, seen = [], set()
    res = {"added": 0, "dup": 0, "skipped": 0, "file": FROM_REPORTS}
    for h in rep.get("ioc_hits") or []:
        v = (h.get("value") or "").strip()
        if not v or v in seen:
            continue
        seen.add(v)
        if (h.get("status") or "") in ("false_positive", "ignored"):
            res["skipped"] += 1
            continue
        if v in existing:
            res["dup"] += 1
            continue
        comment = f"{job.get('filename', '')} ({job.get('id', '')})".strip()
        lines.append(f"{v} # {comment}")
        existing.add(v)                      # защита от дублей внутри самой задачи
    if lines:
        need_nl = path.exists() and path.stat().st_size > 0 and \
            not path.read_text(encoding="utf-8", errors="replace").endswith("\n")
        with path.open("a", encoding="utf-8") as f:
            if need_nl:
                f.write("\n")
            f.write("\n".join(lines) + "\n")
    res["added"] = len(lines)
    return res


# ------------------------------------------------------------------ обновление всего
def update_all(cfg: Config, db: DB, only: str | None = None) -> dict[str, str]:
    ic = cfg["iocs"]
    ab = ic["abusech"]
    key = ab.get("auth_key", "")
    plan = []  # (name, enabled, fn, mode)
    plan.append(("custom", True, lambda: load_custom(cfg.custom_ioc_dir), "replace"))
    if ab.get("enabled"):
        plan += [
            ("abusech-urlhaus", ab.get("urlhaus"), lambda: fetch_urlhaus(key), "accumulate"),
            ("abusech-threatfox", ab.get("threatfox"), lambda: fetch_threatfox(key, ab.get("threatfox_days", 7)), "accumulate"),
            ("abusech-feodo", ab.get("feodo"), lambda: fetch_feodo(key), "replace"),
            ("abusech-malwarebazaar", ab.get("malwarebazaar"), lambda: fetch_malwarebazaar(key), "accumulate"),
        ]
    for lf in listfeeds.all_feeds(cfg):
        plan.append((listfeeds.source_name(lf["id"]), lf["enabled"], (lambda f=lf: listfeeds.fetch(f)), "replace"))
    pub = ic.get("public") or {}
    plan += [
        ("spamhaus-drop", pub.get("spamhaus_drop"), fetch_spamhaus_drop, "replace"),
        ("et-compromised", pub.get("et_compromised"), fetch_et_compromised, "replace"),
        ("tor-exits", pub.get("tor_exits"), fetch_tor_exits, "replace"),
        ("sslbl-ja3", pub.get("sslbl_ja3"), fetch_sslbl_ja3, "replace"),
    ]
    if ic["misp"].get("enabled"):
        plan.append(("misp", True, lambda: fetch_misp(ic["misp"]), "replace"))
    if ic["opencti"].get("enabled"):
        plan.append(("opencti", True, lambda: fetch_opencti(ic["opencti"]), "replace"))

    result = {}
    for name, enabled, fn, mode in plan:
        if not enabled or (only and only != name):
            continue
        try:
            got = fn()
            errs_n = 0
            if isinstance(got, tuple):
                got, errs = got
                errs_n = len(errs)
            n = save_source(db, name, got, mode=mode, max_age_days=int(ic.get("max_age_days", 90)))
            msg = json.dumps({"k": "feed_ok_errs" if errs_n else "feed_ok", "got": len(got), "db": n, "errs": errs_n},
                             ensure_ascii=False)
            db.set_feed(name, True, n, msg)
            result[name] = "ok: " + msg
            log.info("feed %s: %s", name, msg)
        except Exception as e:  # noqa: BLE001 — статус источника показывается в UI
            msg = _short_err(e)
            prev = db.feeds().get(name, {})
            db.set_feed(name, False, prev.get("count", 0) or 0, msg)
            result[name] = "error: " + msg
            log.warning("feed %s failed: %s", name, msg)
    return result


def _short_err(e: Exception) -> str:
    """Компактный JSON-токен ошибки (локализуется в UI) — либо сырое описание."""
    if isinstance(e, FeedError) and str(e).startswith("feed_err_"):
        return json.dumps({"k": str(e)}, ensure_ascii=False)
    if isinstance(e, requests.HTTPError) and e.response is not None:
        code = e.response.status_code
        return json.dumps({"k": "feed_err_http", "code": code,
                           "hint": f"feed_err_http_{code}" if code in (401, 403) else ""}, ensure_ascii=False)
    if isinstance(e, requests.ConnectionError):
        return '{"k": "feed_err_conn"}'
    if isinstance(e, requests.Timeout):
        return '{"k": "feed_err_timeout"}'
    return json.dumps({"k": "feed_err_other", "msg": str(e)[:300] or e.__class__.__name__}, ensure_ascii=False)

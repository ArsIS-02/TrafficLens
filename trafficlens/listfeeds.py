"""Открытые списки угроз (TXT/CSV по URL): готовые пресеты + свои URL из веб-интерфейса.

Пресеты — проверенные бесплатные источники без ключа. Включение/выключение и
свои списки хранятся в <data>/ioc-lists.json; секция iocs.lists конфигурации
может переопределить включение пресета ({id: {enabled: false}}).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re

import requests

from .config import Config
from .ioc_store import Indicator
from .ioc_types import detect

TIMEOUT = 90
UA = {"User-Agent": "TrafficLens/1.0"}
MAX_PER_FEED = 500_000

# kind: c2 — инфраструктура C2 и раздачи вредоносов (исходящие обращения к ней — сильный сигнал);
#       phishing — фишинговые URL; attackers — сканеры и брутфорсеры (в домашней сети за NAT
#       это в основном входящий шум, поэтому по умолчанию выключены).
PRESETS: list[dict] = [
    {"id": "c2intel-ip", "name": "C2IntelFeeds — C2 IP (30 дней)", "name_en": "C2IntelFeeds — C2 IPs (30 days)", "kind": "c2", "type": "ip", "conf": 80, "on": True,
     "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
     "site": "https://github.com/drb-ra/C2IntelFeeds"},
    {"id": "c2intel-domain", "name": "C2IntelFeeds — C2-домены (30 дней)", "name_en": "C2IntelFeeds — C2 domains (30 days)", "kind": "c2", "type": "domain", "conf": 70, "on": True,
     "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
     "site": "https://github.com/drb-ra/C2IntelFeeds"},
    {"id": "threatview-c2", "name": "Threatview — C2 Hunt (Cobalt Strike и др.)", "name_en": "Threatview — C2 Hunt (Cobalt Strike etc.)", "kind": "c2", "type": None, "conf": 80, "on": True,
     "url": "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt", "site": "https://threatview.io/"},
    {"id": "threatview-ip", "name": "Threatview — IP (high confidence)", "name_en": "Threatview — IPs (high confidence)", "kind": "c2", "type": "ip", "conf": 70, "on": True,
     "url": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt", "site": "https://threatview.io/"},
    {"id": "threatview-domain", "name": "Threatview — домены (high confidence)", "name_en": "Threatview — domains (high confidence)", "kind": "c2", "type": "domain", "conf": 70, "on": True,
     "url": "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt", "site": "https://threatview.io/"},
    {"id": "threatview-url", "name": "Threatview — URL (high confidence)", "name_en": "Threatview — URLs (high confidence)", "kind": "c2", "type": "url", "conf": 70, "on": True,
     "url": "https://threatview.io/Downloads/URL-High-Confidence-Feed.txt", "site": "https://threatview.io/"},
    {"id": "threatview-md5", "name": "Threatview — MD5 вредоносных файлов", "name_en": "Threatview — MD5 of malicious files", "kind": "c2", "type": "md5", "conf": 70, "on": True,
     "url": "https://threatview.io/Downloads/MD5-HASH-ALL.txt", "site": "https://threatview.io/"},
    {"id": "threatview-sha", "name": "Threatview — SHA вредоносных файлов", "name_en": "Threatview — SHA of malicious files", "kind": "c2", "type": None, "conf": 70, "on": True,
     "url": "https://threatview.io/Downloads/SHA-HASH-FEED.txt", "site": "https://threatview.io/"},
    {"id": "digitalside-ip", "name": "DigitalSide — IP", "name_en": "DigitalSide — IPs", "kind": "c2", "type": "ip", "conf": 60, "on": True,
     "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt", "site": "https://osint.digitalside.it/"},
    {"id": "digitalside-domain", "name": "DigitalSide — домены", "name_en": "DigitalSide — domains", "kind": "c2", "type": "domain", "conf": 60, "on": True,
     "url": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "site": "https://osint.digitalside.it/"},
    {"id": "digitalside-url", "name": "DigitalSide — URL", "name_en": "DigitalSide — URLs", "kind": "c2", "type": "url", "conf": 60, "on": True,
     "url": "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt", "site": "https://osint.digitalside.it/"},
    {"id": "openphish", "name": "OpenPhish Community — фишинговые URL", "name_en": "OpenPhish Community — phishing URLs", "kind": "phishing", "type": "url", "conf": 70, "on": True,
     "url": "https://openphish.com/feed.txt", "site": "https://openphish.com/"},
    {"id": "ipsum-3", "name": "IPsum (уровень 3+) — сканеры и атакующие", "name_en": "IPsum (level 3+) — scanners and attackers", "kind": "attackers", "type": "ip", "conf": 40, "on": False,
     "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "site": "https://github.com/stamparm/ipsum"},
    {"id": "blocklist-de", "name": "blocklist.de — атакующие (48 ч)", "name_en": "blocklist.de — attackers (48 h)", "kind": "attackers", "type": "ip", "conf": 40, "on": False,
     "url": "https://lists.blocklist.de/lists/all.txt", "site": "https://www.blocklist.de/"},
    {"id": "cins-army", "name": "CINS Army — плохая репутация", "name_en": "CINS Army — bad reputation", "kind": "attackers", "type": "ip", "conf": 40, "on": False,
     "url": "https://cinsscore.com/list/ci-badguys.txt", "site": "https://cinsscore.com/"},
    {"id": "greensnow", "name": "GreenSnow — атакующие", "name_en": "GreenSnow — attackers", "kind": "attackers", "type": "ip", "conf": 40, "on": False,
     "url": "https://blocklist.greensnow.co/greensnow.txt", "site": "https://greensnow.co/"},
]
_PRESET_IDS = {p["id"] for p in PRESETS}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,39}$")
TYPES = (None, "ip", "domain", "url", "md5", "sha1", "sha256")


def _store_path(cfg: Config):
    return cfg.data / "ioc-lists.json"


def load_state(cfg: Config) -> dict:
    try:
        d = json.loads(_store_path(cfg).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    d.setdefault("enabled", {})
    d.setdefault("custom", [])
    return d


def save_state(cfg: Config, state: dict) -> None:
    p = _store_path(cfg)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(p)


def all_feeds(cfg: Config) -> list[dict]:
    """Пресеты + свои списки с итоговым признаком enabled. Порядок: пресеты, затем свои."""
    st = load_state(cfg)
    over = (cfg.get("iocs") or {}).get("lists") or {}
    out = []
    for p in PRESETS:
        f = dict(p, custom=False)
        f["enabled"] = bool(st["enabled"].get(p["id"], p["on"]))
        if isinstance(over.get(p["id"]), dict) and "enabled" in over[p["id"]]:
            f["enabled"] = bool(over[p["id"]]["enabled"])
            f["locked"] = True          # задано в конфиге — переключатель в UI не действует
        out.append(f)
    for c in st["custom"]:
        if c.get("id") and c.get("url"):
            out.append({"kind": "custom", "type": None, "conf": 60, "site": "", **c, "custom": True,
                        "enabled": bool(st["enabled"].get(c["id"], True))})
    return out


def source_name(feed_id: str) -> str:
    return f"list-{feed_id}"


def set_enabled(cfg: Config, feed_id: str, enabled: bool) -> None:
    st = load_state(cfg)
    st["enabled"][feed_id] = bool(enabled)
    save_state(cfg, st)


def add_custom(cfg: Config, name: str, url: str, type_: str | None, conf: int) -> dict:
    st = load_state(cfg)
    base = re.sub(r"[^a-z0-9]+", "-", (name or url).lower()).strip("-")[:30] or "list"
    fid, n = f"my-{base}", 2
    taken = _PRESET_IDS | {c["id"] for c in st["custom"]}
    while fid in taken:
        fid, n = f"my-{base}-{n}", n + 1
    item = {"id": fid, "name": name or url, "url": url, "type": type_ or None, "conf": max(1, min(100, int(conf or 60)))}
    st["custom"].append(item)
    save_state(cfg, st)
    return item


def delete_custom(cfg: Config, feed_id: str) -> bool:
    st = load_state(cfg)
    before = len(st["custom"])
    st["custom"] = [c for c in st["custom"] if c.get("id") != feed_id]
    st["enabled"].pop(feed_id, None)
    save_state(cfg, st)
    return len(st["custom"]) != before


# ------------------------------------------------------------------ разбор
_FAMILY = {"ip": ("ip", "cidr"), "domain": ("domain",), "url": ("url",), "md5": ("md5",), "sha1": ("sha1",), "sha256": ("sha256",)}


def _bad_net(t: str, v: str) -> bool:
    """Не принимаем частные/служебные адреса и слишком широкие сети — защита от «битых» списков."""
    if t not in ("ip", "cidr"):
        return False
    try:
        n = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return True
    if n.prefixlen < (8 if n.version == 4 else 16):
        return True
    a = n.network_address
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified


def parse(text: str, feed: dict) -> list[Indicator]:
    """Строки TXT или CSV: в каждой строке берём первое поле, похожее на индикатор нужного типа.

    Комментарии (#, ;, //) пропускаются; остаток строки CSV (например, «Possible Cobalt Strike C2»)
    идёт в описание индикатора.
    """
    want = _FAMILY.get(feed.get("type") or "")
    info_base = feed.get("name") or feed.get("id", "")
    conf = int(feed.get("conf") or 60)
    out: list[Indicator] = []
    seen: set = set()
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line[0] in "#;" or line.startswith("//"):
            continue
        if "," in line or "\t" in line:
            try:
                fields = next(csv.reader(io.StringIO(line), delimiter="\t" if "\t" in line and "," not in line else ","))
            except (csv.Error, StopIteration):
                fields = [line]
        else:
            fields = line.split()
        hit, rest = None, []
        for fld in fields:
            fld = fld.strip().strip('"')
            if not fld:
                continue
            if hit is not None:
                rest.append(fld)
                continue
            d = detect(fld, None)
            if d and (want is None or d[0] in want) and not _bad_net(d[0], d[1]):
                hit = d
        if not hit:
            continue
        t, v, port = hit
        if (t, v) in seen:
            continue
        seen.add((t, v))
        extra = " ".join(x for x in rest if not x.isdigit())[:120]
        out.append(Indicator(t, v, f"{info_base}: {extra}" if extra else info_base, feed.get("kind", ""), conf, port))
        if len(out) >= MAX_PER_FEED:
            break
    return out


def fetch(feed: dict) -> list[Indicator]:
    r = requests.get(feed["url"], headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return parse(r.text, feed)

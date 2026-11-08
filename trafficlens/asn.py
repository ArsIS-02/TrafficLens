"""Офлайн-база ASN: iptoasn.com (свободный TSV, без ключей и учёток).

Скачанный ip2asn-combined.tsv.gz лежит в `<данные>/asn.tsv.gz` (v4+v6,
~250 тыс. диапазонов). Поиск — бинарный по началам диапазонов, база грузится
в память один раз и перечитывается только при смене файла (кеш по mtime).
Обновление — кнопкой на странице «Индикаторы и правила» (POST /api/asn/update).
"""
from __future__ import annotations

import bisect
import gzip
import ipaddress
from pathlib import Path

import requests

from .config import Config

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
UA = {"User-Agent": "TrafficLens ASN (https://github.com/ArsIS-02/TrafficLens)"}
TIMEOUT = 90

_cache: dict = {}  # (path, mtime) -> (starts, rows); rows[i] = (end, asn, cc, name)


def db_path(cfg: Config) -> Path:
    return cfg.data / "asn.tsv.gz"


def status(cfg: Config) -> dict:
    """Состояние базы для страницы «Индикаторы и правила»."""
    p = db_path(cfg)
    if not p.exists():
        return {"present": False}
    try:
        starts, _ = _load(cfg)
        return {"present": True, "ranges": len(starts), "updated": p.stat().st_mtime,
                "size": p.stat().st_size}
    except Exception:  # noqa: BLE001 — битый файл считаем отсутствующим
        return {"present": False}


def update(cfg: Config) -> dict:
    """Скачать свежую базу (атомарно, через временный файл)."""
    p = db_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(URL, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    tmp = p.with_suffix(".tsv.tmp")
    tmp.write_bytes(r.content)
    tmp.replace(p)
    _cache.clear()
    starts, _ = _load(cfg)
    return {"ranges": len(starts), "size": p.stat().st_size, "updated": p.stat().st_mtime}


def _load(cfg: Config) -> tuple[list[int], list[tuple[int, int, str, str]]]:
    p = db_path(cfg)
    key = (str(p), p.stat().st_mtime)
    if key in _cache:
        return _cache[key]
    starts, rows = [], []
    with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                a = int(ipaddress.ip_address(parts[0]))
                b = int(ipaddress.ip_address(parts[1]))
            except ValueError:
                continue
            asn = int(parts[2]) if parts[2].isdigit() else 0
            starts.append(a)
            rows.append((b, asn, parts[3], parts[4][:100]))
    order = sorted(range(len(starts)), key=starts.__getitem__)  # v4 < v6 численно, файл и так отсортирован
    starts = [starts[i] for i in order]
    rows = [rows[i] for i in order]
    _cache.clear()
    _cache[key] = (starts, rows)
    return starts, rows


def lookup(cfg: Config, ip: str) -> dict | None:
    """{asn, cc, name} для адреса или None (нет базы / адрес вне диапазонов / AS 0)."""
    p = db_path(cfg)
    if not p.exists():
        return None
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return None
    try:
        starts, rows = _load(cfg)
    except (OSError, EOFError):
        return None
    i = bisect.bisect_right(starts, n) - 1
    if i < 0:
        return None
    end, asn, cc, name = rows[i]
    if n > end or not asn:
        return None
    return {"asn": asn, "cc": cc, "name": name}


def enrich(cfg: Config, rows: list[dict]) -> None:
    """Проставить asn/as_cc/as_name строкам с полем ip (на месте, без копий)."""
    if not db_path(cfg).exists():
        return
    for r in rows:
        info = lookup(cfg, r.get("ip") or "")
        if info:
            r["asn"], r["as_cc"], r["as_name"] = info["asn"], info["cc"], info["name"]

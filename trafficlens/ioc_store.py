"""Хранилище IOC и быстрый индекс для сопоставления."""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from .db import DB
from .ioc_types import parent_domains


@dataclass
class Indicator:
    type: str
    value: str
    info: str = ""
    tags: str = ""
    confidence: int = 0
    port: int | None = None


def save_source(db: DB, source: str, items: list[Indicator], mode: str = "replace", max_age_days: int = 90) -> int:
    """Записать индикаторы источника.

    replace    — источник отдаёт полный снимок: всё, чего нет в снимке, удаляется.
    accumulate — источник отдаёт «свежие» записи: копим, удаляем старше max_age_days.
    """
    now = time.time()
    with db.conn() as c:
        c.execute("BEGIN IMMEDIATE")
        c.executemany(
            "INSERT INTO iocs(type, value, source, info, tags, confidence, port, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(type, value, source) DO UPDATE SET info=excluded.info, tags=excluded.tags, "
            "confidence=excluded.confidence, port=excluded.port, last_seen=excluded.last_seen",
            [(i.type, i.value, source, i.info[:300], i.tags[:200], i.confidence, i.port, now, now) for i in items],
        )
        if mode == "replace":
            c.execute("DELETE FROM iocs WHERE source=? AND last_seen < ?", (source, now))
        else:
            c.execute("DELETE FROM iocs WHERE source=? AND last_seen < ?", (source, now - max_age_days * 86400))
        n = c.execute("SELECT COUNT(*) FROM iocs WHERE source=?", (source,)).fetchone()[0]
    return n


def stats(db: DB) -> dict:
    with db.conn() as c:
        by_source = {}
        for r in c.execute("SELECT source, type, COUNT(*) n FROM iocs GROUP BY source, type"):
            by_source.setdefault(r["source"], {})[r["type"]] = r["n"]
        total = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    return {"total": total, "by_source": by_source}


def lookup(db: DB, q: str) -> list[dict]:
    from .ioc_types import detect
    det = detect(q)
    values = {q.strip().lower()}
    if det:
        values.add(det[1])
        if det[0] == "domain":
            values.update(parent_domains(det[1]))
    with db.conn() as c:
        marks = ",".join("?" * len(values))
        rows = c.execute(f"SELECT * FROM iocs WHERE value IN ({marks}) ORDER BY source", tuple(values)).fetchall()
    return [dict(r) for r in rows]


@dataclass
class Match:
    type: str
    value: str          # значение индикатора из базы
    observed: str       # что увидели в трафике
    entries: list[dict] = field(default_factory=list)


class IOCIndex:
    """Загруженный в память снимок IOC. Строится один раз на задачу анализа."""

    def __init__(self, db: DB | None = None):
        self.by_type: dict[str, dict[str, list[dict]]] = {}
        self.nets: list[tuple[ipaddress._BaseNetwork, list[dict]]] = []
        self.count = 0
        if db is not None:
            self._load(db)

    def _load(self, db: DB) -> None:
        nets: dict[str, list[dict]] = {}
        with db.conn() as c:
            for r in c.execute("SELECT type, value, source, info, tags, confidence, port FROM iocs"):
                e = {"source": r["source"], "info": r["info"], "tags": r["tags"],
                     "confidence": r["confidence"], "port": r["port"]}
                if r["type"] == "cidr":
                    nets.setdefault(r["value"], []).append(e)
                else:
                    self.by_type.setdefault(r["type"], {}).setdefault(r["value"], []).append(e)
                self.count += 1
        for k, v in nets.items():
            try:
                self.nets.append((ipaddress.ip_network(k, strict=False), v))
            except ValueError:
                pass

    def add(self, ind: Indicator, source: str = "test") -> None:
        e = {"source": source, "info": ind.info, "tags": ind.tags, "confidence": ind.confidence, "port": ind.port}
        if ind.type == "cidr":
            self.nets.append((ipaddress.ip_network(ind.value, strict=False), [e]))
        else:
            self.by_type.setdefault(ind.type, {}).setdefault(ind.value, []).append(e)
        self.count += 1

    # --- проверки ---
    def ip(self, ip: str) -> Match | None:
        if not ip:
            return None
        hit = self.by_type.get("ip", {}).get(ip)
        if hit:
            return Match("ip", ip, ip, hit)
        if self.nets:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, entries in self.nets:
                if a.version == net.version and a in net:
                    return Match("cidr", str(net), ip, entries)
        return None

    def domain(self, name: str) -> Match | None:
        if not name:
            return None
        name = name.strip(".").lower()
        table = self.by_type.get("domain")
        if not table:
            return None
        for d in parent_domains(name):
            hit = table.get(d)
            if hit:
                return Match("domain", d, name, hit)
        return None

    def url(self, normalized: str) -> Match | None:
        table = self.by_type.get("url")
        if not table or not normalized:
            return None
        hit = table.get(normalized)
        if not hit and normalized.endswith("/"):
            hit = table.get(normalized.rstrip("/"))
        elif not hit:
            hit = table.get(normalized + "/")
        return Match("url", normalized, normalized, hit) if hit else None

    def hash(self, kind: str, value: str) -> Match | None:
        if not value:
            return None
        v = value.lower()
        hit = self.by_type.get(kind, {}).get(v)
        return Match(kind, v, v, hit) if hit else None

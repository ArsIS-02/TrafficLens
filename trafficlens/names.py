"""Имена локальных хостов: свой файл hosts.yaml и обратные DNS-записи (PTR).

Порядок при показе имени локального адреса:
  1. <data>/config/hosts.yaml — то, что задал администратор (Маки, Windows, роутер вне домена);
  2. имя из самой записи — DHCP, DNS-ответы, TLS SNI;
  3. PTR из DNS хоста (во FreeIPA обратная зона ведётся для машин домена).

PTR спрашиваются параллельно с коротким таймаутом и кешируются в памяти процесса
(отрицательный ответ тоже), поэтому сборка отчёта не ждёт медленный DNS.
"""
from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

import yaml

_cache: dict[str, tuple[float, str]] = {}
_lock = threading.Lock()
TTL_OK, TTL_MISS = 3600.0, 600.0


def _ncfg(cfg) -> dict:
    return (cfg.get("names") or {}) if isinstance(cfg, dict) else {}


def hosts_file(cfg) -> Path | None:
    nc = _ncfg(cfg)
    if nc.get("hosts_file"):
        return Path(nc["hosts_file"])
    data = cfg.get("data_dir") if isinstance(cfg, dict) else None
    return Path(data) / "config" / "hosts.yaml" if data else None


def load_hosts(cfg) -> dict[str, str]:
    """{ip: имя}. Принимает словарь «ip: имя» или список {ip, name}."""
    p = hosts_file(cfg)
    if not p or not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[str, str] = {}
    if isinstance(data, dict):
        data = data.get("hosts", data)
    if isinstance(data, dict):
        out = {str(k).strip(): str(v).strip() for k, v in data.items() if v}
    elif isinstance(data, list):
        for e in data:
            if isinstance(e, dict) and e.get("ip") and e.get("name"):
                out[str(e["ip"]).strip()] = str(e["name"]).strip()
    return out


def _ptr(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    return name.rstrip(".")


def resolve_ptr(cfg, ips: list[str]) -> dict[str, str]:
    nc = _ncfg(cfg)
    if not nc.get("ptr", True) or not ips:
        return {}
    now = time.time()
    out, todo = {}, []
    with _lock:
        for ip in ips:
            c = _cache.get(ip)
            if c and c[0] > now:
                if c[1]:
                    out[ip] = c[1]
            else:
                todo.append(ip)
    todo = todo[: int(nc.get("max_lookups", 256))]
    if todo:
        ex = ThreadPoolExecutor(max_workers=min(16, len(todo)))
        futs = {ex.submit(_ptr, ip): ip for ip in todo}
        done, _ = wait(futs, timeout=float(nc.get("ptr_timeout", 3.0)))
        with _lock:
            for f in done:
                ip, name = futs[f], f.result()
                _cache[ip] = (now + (TTL_OK if name else TTL_MISS), name)
                if name:
                    out[ip] = name
        ex.shutdown(wait=False, cancel_futures=True)
    if nc.get("strip_domain"):
        out = {ip: n.split(".", 1)[0] for ip, n in out.items()}
    return out


def clear_cache() -> None:
    with _lock:
        _cache.clear()

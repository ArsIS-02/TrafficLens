"""Определение и нормализация типов индикаторов."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

TYPES = ("ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "ja3", "ja4")
TYPE_LABELS = {
    "ip": "IP-адрес", "cidr": "Подсеть", "domain": "Домен", "url": "URL",
    "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "ja3": "JA3", "ja4": "JA4",
}

_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_JA4 = re.compile(r"^[tqd][0-9a-z]{9}_[0-9a-f]{12}_[0-9a-f]{12}$")


def norm_domain(v: str) -> str:
    v = v.strip().strip(".").lower()
    if v.startswith("*."):
        v = v[2:]
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    return v


def norm_url(v: str) -> str:
    """URL -> host[:port]/path?query без схемы, хост в нижнем регистре, без порта по умолчанию."""
    v = v.strip()
    if "://" not in v:
        v = "http://" + v
    try:
        p = urlsplit(v)
    except ValueError:
        return v.lower()
    host = (p.hostname or "").lower()
    port = p.port if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)) else None
    path = p.path or "/"
    out = host + (f":{port}" if port else "") + path
    if p.query:
        out += "?" + p.query
    return out


def split_ip_port(v: str) -> tuple[str, int | None]:
    v = v.strip()
    if v.startswith("[") and "]:" in v:          # [ipv6]:port
        host, port = v[1:].split("]:", 1)
        return host, int(port) if port.isdigit() else None
    if v.count(":") == 1:                           # ipv4:port
        host, port = v.split(":")
        if port.isdigit():
            return host, int(port)
    return v, None


def detect(value: str, hint: str | None = None) -> tuple[str, str, int | None] | None:
    """Вернуть (type, normalized_value, port) или None, если индикатор не распознан."""
    v = value.strip()
    if not v:
        return None
    if hint:
        hint = hint.lower()
        if hint in ("ja3", "ja3s"):
            return ("ja3", v.lower(), None) if len(v) == 32 and _HEX.match(v.lower()) else None
        if hint == "ja4":
            return ("ja4", v.lower(), None)
        if hint in ("md5", "sha1", "sha256"):
            return (hint, v.lower(), None) if _HEX.match(v.lower()) else None
        if hint == "url":
            return ("url", norm_url(v), None)
        if hint in ("domain", "hostname", "fqdn"):
            d = norm_domain(v)
            return ("domain", d, None) if _DOMAIN.match(d) else None
        if hint in ("ip", "ipv4", "ipv6", "cidr"):
            pass  # распознаём ниже
    low = v.lower()
    if "://" in v:
        return ("url", norm_url(v), None)
    if _HEX.match(low):
        t = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(low))
        return (t, low, None) if t else None
    if _JA4.match(low):
        return ("ja4", low, None)
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.num_addresses == 1:
                return ("ip", str(net.network_address), None)
            return ("cidr", str(net), None)
        except ValueError:
            # host/path без схемы — URL
            host = v.split("/", 1)[0]
            if _DOMAIN.match(norm_domain(host.split(":")[0])):
                return ("url", norm_url(v), None)
            return None
    host, port = split_ip_port(v)
    try:
        ip = ipaddress.ip_address(host)
        return ("ip", str(ip), port)
    except ValueError:
        pass
    d = norm_domain(v)
    if _DOMAIN.match(d):
        return ("domain", d, None)
    return None


def parent_domains(d: str):
    """sub.a.example.com -> sub.a.example.com, a.example.com, example.com"""
    parts = d.split(".")
    for i in range(0, max(1, len(parts) - 1)):
        yield ".".join(parts[i:])

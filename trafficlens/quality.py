"""Качество сигналов: что считать доказательством, а что шумом.

Используется при сборке отчёта (вердикт, риск хостов) и при рендере
(MITRE, цепочка) — поэтому правила применяются и к отчётам старых версий,
где флагов weak / service ещё нет.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

# Статусы проверки сертификата, которые почти всегда говорят о хранилище
# корней или неполной цепочке, а не об атаке: старые записи, удалённые из
# Mozilla-хранилища корни, сервер не отдал промежуточный сертификат.
TLS_WEAK_STATUSES = (
    "unable to get local issuer certificate",
    "unable to get issuer certificate",
    "unable to get issuer certificate locally",
    "unable to verify the first certificate",
    "self signed certificate in certificate chain",
    "certificate chain too long",
)

# Сигнатуры-шум по умолчанию: битые контрольные суммы при checksum offload
# на машине захвата. -k none их не глушит — decoder-events проверяет суммы явно.
ALERT_NOISE_PATTERNS = ("invalid checksum",)

# Служебные «файлы» TLS-инфраструктуры: проверка отзыва и сертификаты.
SERVICE_MIMES = {
    "application/ocsp-request", "application/ocsp-response",
    "application/pkix-cert", "application/pkix-crl", "application/x-x509-ca-cert",
    "application/x-x509-user-cert", "application/x-pkcs7-crl", "application/pkcs7-mime",
}

# Тип по расширению — когда libmagic не распознал содержимое (или файл обрезан).
EXT_TYPES = {
    ".iso": "application/x-iso9660-image", ".img": "application/octet-stream (disk image)",
    ".exe": "application/x-dosexec", ".dll": "application/x-dosexec", ".msi": "application/x-msi",
    ".zip": "application/zip", ".7z": "application/x-7z-compressed", ".rar": "application/vnd.rar",
    ".gz": "application/gzip", ".tar": "application/x-tar", ".xz": "application/x-xz",
    ".pdf": "application/pdf", ".doc": "application/msword", ".xls": "application/vnd.ms-excel",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".js": "text/javascript", ".ps1": "text/x-powershell", ".sh": "text/x-shellscript",
    ".apk": "application/vnd.android.package-archive", ".dmg": "application/x-apple-diskimage",
    ".deb": "application/vnd.debian.binary-package", ".rpm": "application/x-rpm",
}

# Резолверы DNS-over-HTTPS / DNS-over-TLS: по SNI и по адресу (порт 443).
DOH_SNI = {
    "dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com",
    "family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
    "dns11.quad9.net", "doh.opendns.com", "dns.adguard-dns.com", "dns.adguard.com",
    "doh.cleanbrowsing.org", "dns.nextdns.io", "common.dot.dns.yandex.net", "doh.dns.sb",
    "chrome.cloudflare-dns.com", "dns.alidns.com", "doh.pub",
}
DOH_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9",
}


def _norm(s: str) -> str:
    return re.sub(r"[\s\-_]+", " ", (s or "").strip().lower())


def _vcfg(cfg) -> dict:
    return (cfg.get("verdict") or {}) if isinstance(cfg, dict) else {}


def tls_weak_statuses(cfg=None) -> set[str]:
    custom = _vcfg(cfg).get("tls_weak_statuses")
    return {_norm(s) for s in (custom if custom is not None else TLS_WEAK_STATUSES)}


def tls_is_weak(status: str, cfg=None) -> bool:
    return _norm(status) in tls_weak_statuses(cfg)


def tls_strong(invalid: list[dict], cfg=None) -> list[dict]:
    """Сильные TLS-находки: без «слабых» статусов, по одной на SNI (или адрес)."""
    weak = tls_weak_statuses(cfg)
    seen, out = set(), []
    for t in invalid or []:
        if t.get("weak") is True or _norm(t.get("status", "")) in weak:
            continue
        key = (t.get("src", ""), t.get("sni") or t.get("dst", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def alert_noise_patterns(cfg=None) -> list[str]:
    sc = (cfg.get("suricata") or {}) if isinstance(cfg, dict) else {}
    pats = sc.get("suppress_signatures")
    return [p.lower() for p in (pats if pats is not None else ALERT_NOISE_PATTERNS) if p]


def alert_is_noise(signature: str, cfg=None) -> bool:
    s = (signature or "").lower()
    return any(p in s for p in alert_noise_patterns(cfg))


def file_is_service(mime: str, url: str = "") -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    if m in SERVICE_MIMES:
        return True
    u = (url or "").lower()
    return "://ocsp" in u or ".crl" in u.rsplit("?", 1)[0][-8:]


def guess_type(filename: str) -> str:
    if not filename:
        return ""
    return EXT_TYPES.get(PurePosixPath(filename.lower()).suffix, "")


def doh_kind(dst: str, port: int, sni: str = "") -> str:
    """'DoT' / 'DoH' / '' для соединения."""
    if port == 853:
        return "DoT"
    if port == 443 and ((sni or "").lower() in DOH_SNI or dst in DOH_IPS):
        return "DoH"
    return ""

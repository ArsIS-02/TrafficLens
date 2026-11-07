"""Конфигурация TrafficLens: YAML-файл в каталоге данных + переопределения из окружения."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

DEFAULTS: dict = {
    "data_dir": "/data",
    "listen": "0.0.0.0",
    "port": 8080,
    # Пароль для входа в веб-UI. Пусто — без авторизации (например, когда доступ закрыт Caddy).
    "auth": {
        "username": "admin",
        "password_hash": "",
        "cookie_secure": False,"password": ""},
    "max_upload_mb": 4096,
    "workers": 1,
    # Сети, которые считаются «своими». Всё остальное — внешнее.
    "local_nets": [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
        "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
    ],
    "zeek": {
        "bin": "",               # пусто — искать автоматически
        "extract_files": True,
        "extract_max_mb": 50,
        "timeout_min": 120,
    },
    "suricata": {
        "enabled": True,
        "bin": "",
        "config": "/etc/suricata/suricata.yaml",
        "rules_update_hours": 24,
        "timeout_min": 120,
        # правила, которые suricata-update отключает (disable.conf): checksum offload даёт тысячи ложных алертов
        "disable_rules": ["re:invalid checksum"],
        # сигнатуры, которые отчёт сворачивает в «шум» (подстрока, без учёта регистра) — и для старых задач
        "suppress_signatures": ["invalid checksum"],
    },
    "iocs": {
        "update_hours": 6,
        "max_age_days": 90,      # для накопительных фидов (URLhaus, ThreatFox, MalwareBazaar)
        "custom_dir": "",        # пусто — <data_dir>/ioc/custom
        "abusech": {
            "enabled": True,
            "auth_key": "",      # бесплатный ключ: https://auth.abuse.ch/
            "urlhaus": True,
            "threatfox": True,
            "threatfox_days": 7,
            "feodo": True,
            "malwarebazaar": True,
        },
        # Открытые списки без ключа.
        "public": {
            "spamhaus_drop": True,   # Spamhaus DROP: угнанные/«чёрные» сети, CIDR
            "et_compromised": True,  # Emerging Threats: скомпрометированные IP
            "tor_exits": False,      # выходные узлы Tor — контекст, а не компрометация
        },
        "misp": {
            "enabled": False,
            "url": "",
            "key": "",
            "verify_tls": True,  # True / False / путь к CA (например, CA FreeIPA)
            "days": 30,
            "to_ids_only": True,
        },
        "opencti": {
            "enabled": False,
            "url": "",
            "token": "",
            "verify_tls": True,
            "min_score": 0,
            "max_indicators": 200000,
        },
    },
    "capture": {
        "watch_spool": True,     # подхватывать PCAP, которые пишет capture-контейнер
        "retention_days": 7,     # legacy: используется, если retention.days не задан
    },
    # Хранение задач (upload + capture).
    "retention": {
        "days": None,            # None — брать capture.retention_days; 0 — не удалять по возрасту
        "max_total_gb": 0,       # квота на каталог задач; 0 — без квоты
        "keep_verdicts": ["critical"],
        "dry_run": False,
    },
    # Скоринговый вердикт (report.verdict).
    "verdict": {
        "confidence_scale": True,   # вес IOC-hit умножается на confidence/100
        # потолок вклада категории в score (report.DEFAULT_CAPS); null — без потолка
        "caps": {},
        # без находок этих категорий итог не выше «подозрительно»
        "critical_requires": ["ioc_hit", "alert_sev_1", "file_ioc"],
        "weights": {"ioc_hit": 40, "alert_sev_1": 40, "alert_sev_2": 15,
                    "file_ioc": 25, "beacon": 15, "large_upload": 10,
                    "cleartext_auth": 20, "tls_invalid": 10, "dns_suspicious": 5},
        "thresholds": {"suspicious": 30, "critical": 80},
    },
    "heuristics": {
        "beacon_min_conns": 12,
        "beacon_max_cv": 0.15,
        "beacon_ignore_ports": [53, 123, 137, 138, 5353, 67, 68],
        "large_upload_mb": 20,
        "long_conn_hours": 1,
        "dns_entropy": 3.8,
        "dns_min_label": 14,
    },
    "report": {
        "max_rows": 500,
    },
}

ENV_MAP = {
    "TL_USERNAME": ("auth", "username"),
    "TL_PASSWORD": ("auth", "password"),
    "TL_ABUSECH_KEY": ("iocs", "abusech", "auth_key"),
    "TL_MISP_URL": ("iocs", "misp", "url"),
    "TL_MISP_KEY": ("iocs", "misp", "key"),
    "TL_OPENCTI_URL": ("iocs", "opencti", "url"),
    "TL_OPENCTI_TOKEN": ("iocs", "opencti", "token"),
    "TL_PORT": ("port",),
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config(dict):
    """dict с удобным доступом к путям."""

    @property
    def data(self) -> Path:
        return Path(self["data_dir"])

    @property
    def jobs_dir(self) -> Path:
        return self.data / "jobs"

    @property
    def spool_dir(self) -> Path:
        return self.data / "spool"

    @property
    def custom_ioc_dir(self) -> Path:
        return Path(self["iocs"]["custom_dir"] or (self.data / "ioc" / "custom"))

    @property
    def rules_dir(self) -> Path:
        return self.data / "suricata"

    @property
    def db_path(self) -> Path:
        return self.data / "trafficlens.db"

    @property
    def config_path(self) -> Path:
        return self.data / "config" / "trafficlens.yaml"


def load(data_dir: str | None = None) -> Config:
    data_dir = data_dir or os.environ.get("TL_DATA_DIR") or DEFAULTS["data_dir"]
    cfg_file = Path(os.environ.get("TL_CONFIG") or Path(data_dir) / "config" / "trafficlens.yaml")
    user = {}
    if cfg_file.exists():
        user = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
    merged = _merge(DEFAULTS, user)
    merged["data_dir"] = data_dir
    for env, path in ENV_MAP.items():
        val = os.environ.get(env)
        if val:
            node = merged
            for p in path[:-1]:
                node = node[p]
            node[path[-1]] = int(val) if path[-1] == "port" else val
    # ключи заданы — фиды включаем, если пользователь явно не выключил
    if merged["iocs"]["misp"]["url"] and merged["iocs"]["misp"]["key"] and "enabled" not in (user.get("iocs", {}).get("misp", {})):
        merged["iocs"]["misp"]["enabled"] = True
    if merged["iocs"]["opencti"]["url"] and merged["iocs"]["opencti"]["token"] and "enabled" not in (user.get("iocs", {}).get("opencti", {})):
        merged["iocs"]["opencti"]["enabled"] = True
    cfg = Config(merged)
    for d in (cfg.jobs_dir, cfg.spool_dir / "ready", cfg.custom_ioc_dir, cfg.rules_dir, cfg.config_path.parent):
        d.mkdir(parents=True, exist_ok=True)
    tmp = os.environ.get("TMPDIR")
    if tmp:  # загрузки больших PCAP буферизуются сюда — на том же томе, что и данные
        Path(tmp).mkdir(parents=True, exist_ok=True)
    return cfg

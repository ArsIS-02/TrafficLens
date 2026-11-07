"""Цепочка компрометации: находки отчёта, разложенные по этапам атаки.

Строится по report.json (как mitre.py), поэтому работает и для отчётов,
собранных старыми версиями. Этапы упорядочены по логике kill chain — от
разведки к воздействию; внутри этапа доказательства идут по времени.
Дополнительно считаются хосты, замеченные на двух и более этапах, — с них
имеет смысл начинать расследование.
"""
from __future__ import annotations

from . import quality
from .mitre import TACTICS, alert_tags

# Порядок этапов цепочки: ключ -> тактика ATT&CK. Пустые этапы показываются
# в интерфейсе серыми: важно видеть, каких звеньев в дампе нет.
STAGES: list[tuple[str, str]] = [
    ("recon", "TA0007"),      # Discovery
    ("initial", "TA0001"),    # Initial Access
    ("execution", "TA0002"),  # Execution
    ("privesc", "TA0004"),    # Privilege Escalation
    ("creds", "TA0006"),      # Credential Access
    ("c2", "TA0011"),         # Command and Control
    ("exfil", "TA0010"),      # Exfiltration
    ("impact", "TA0040"),     # Impact
]
_TACTIC_STAGE = {tactic: key for key, tactic in STAGES}
_HASH_TYPES = {"md5", "sha1", "sha256"}
MAX_TICKETS = 20  # текстовых цепочек на страницу — по самым значимым IOC-хитам


def _pair_hosts(pairs: list[str]) -> list[str]:
    """IP из строк вида '1.2.3.4:80 → 5.6.7.8:443' (без портов, без дублей)."""
    out: list[str] = []
    for p in pairs or []:
        left, _, right = p.partition(" → ")
        for side in (left, right):
            ip = side.rsplit(":", 1)[0].strip()
            if ip and ip not in out:
                out.append(ip)
    return out


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ticket_chains(rep: dict) -> list[dict]:
    """Текстовые цепочки для тикета по значимым IOC-хитам:
    хост → индикатор → адрес:порт → файл → хэш → источники IOC."""
    names: dict[str, str] = {}
    for coll in ("local_hosts", "top_external"):
        for h in rep.get(coll) or []:
            if h.get("ip"):
                names[h["ip"]] = h.get("name", "")
    local_ips = {h.get("ip") for h in rep.get("local_hosts") or []}
    prio = {h.get("ip") for h in rep.get("priority_hosts") or []}
    resolvers = {r.get("ip") for r in (rep.get("dns") or {}).get("resolvers") or []}
    beacons = (rep.get("findings") or {}).get("beacons") or []
    files = rep.get("files") or []

    def host_label(ip: str) -> str:
        return f"{names[ip]} ({ip})" if names.get(ip) else ip

    def port_for(ip: str) -> str:
        for b in beacons:  # порт маячка к этому адресу — самое показательное
            if b.get("dst") == ip and b.get("dp"):
                return str(b["dp"])
        return ""

    def file_near(ips: set[str]):
        return next((x for x in files if x.get("ioc") and ({x.get("sender"), x.get("receiver")} & ips)), None)

    out = []
    for h in (rep.get("ioc_hits") or [])[:MAX_TICKETS]:
        val, typ = h.get("value", ""), h.get("type", "")
        hosts_all = h.get("hosts") or []
        # локальные хосты, кроме DNS-резолверов (это транзит, а не участники), приоритетные — первыми
        hosts = sorted((ip for ip in hosts_all if ip in local_ips and ip not in resolvers),
                       key=lambda ip: (ip not in prio, ip)) or hosts_all[:2]
        ioc_port = next((str(e["port"]) for e in (h.get("sources") or []) if e.get("port")), "")
        srcs = sorted({e.get("source", "") for e in (h.get("sources") or []) if e.get("source")})

        parts: list[str] = []
        if hosts:
            parts.append(", ".join(host_label(ip) for ip in hosts[:3]))
        if typ in _HASH_TYPES:
            fl = next((x for x in files if val in (x.get("sha256"), x.get("sha1"), x.get("md5"))), None)
            if fl and fl.get("filename"):
                parts.append(fl["filename"])
            parts.append(f"{typ}:{val[:16]}…")
        elif typ == "ja3":
            parts.append(f"ja3:{val[:16]}…")
            fl = file_near(set(hosts_all))
            if fl:
                parts.append(fl.get("filename") or (fl.get("sha256") or "")[:16] + "…")
        else:
            port = port_for(val) or ioc_port
            parts.append(f"{val}:{port}" if typ == "ip" and port else val)
            # цели: наблюдаемые адреса (без поддоменов самого индикатора) + внешние IP из контекстов
            raw: list[str] = []
            for o in h.get("observed") or []:
                if o != val and not o.endswith("." + val) and o not in raw:
                    raw.append(o)
            for ip in hosts_all:
                if ip not in local_ips and ip != val and _is_ip(ip) and ip not in raw:
                    raw.append(ip)
            tgts = []
            for t in raw[:3]:
                p = port_for(t)
                tgts.append(f"{t}:{p}" if p else t)
            if tgts:
                parts.append(", ".join(tgts))
            fl = file_near(set(raw) | set(hosts_all))
            if fl:
                parts.append(fl.get("filename") or (fl.get("sha256") or "")[:16] + "…")
        if srcs:
            parts.append(", ".join(srcs))
        out.append({"text": " → ".join(p for p in parts if p),
                    "value": val, "conf": h.get("max_conf") or 0, "count": h.get("count") or 0})
    return out


def build(rep: dict) -> dict:
    """{stages: [...], hosts: [...], covered: int} по данным отчёта."""
    stages: dict[str, dict] = {
        key: {"key": key, "tactic": tactic, "tactic_name": TACTICS[tactic],
              "events": [], "hosts": [], "techs": {}, "first": 0.0, "last": 0.0}
        for key, tactic in STAGES
    }

    def add(stage_key: str, ts: float, kind: str, title: str, detail: str = "",
            hosts=(), ioc: bool = False, tech: str = "") -> None:
        st = stages[stage_key]
        st["events"].append({"ts": ts or 0, "kind": kind, "title": title,
                            "detail": detail, "hosts": list(hosts), "ioc": ioc})
        for h in hosts:
            if h and h not in st["hosts"]:
                st["hosts"].append(h)
        if tech:
            st["techs"][tech] = st["techs"].get(tech, 0) + 1

    # ---- сигнатуры Suricata: категория -> тактика/техника (mitre.alert_tags)
    for a in rep.get("alerts") or []:
        if quality.alert_is_noise(a.get("signature", "")):
            continue
        hosts = _pair_hosts(a.get("pairs"))
        for tactic, tech in alert_tags(a.get("category", "")):
            stage = _TACTIC_STAGE.get(tactic)
            if stage:
                add(stage, a.get("first", 0), "alert", a.get("signature", ""),
                    f'{a.get("category", "")} · sev{a.get("severity", 3)} · ×{a.get("count", 1)}',
                    hosts, tech=tech)

    f = rep.get("findings") or {}
    for b in f.get("beacons") or []:
        add("c2", b.get("first", 0), "beacon", f'{b.get("dst", "")}:{b.get("dp", "")}',
            f'×{b.get("count", 0)} · {b.get("interval", 0):.1f}s',
            [b.get("src", ""), b.get("dst", "")], ioc=bool(b.get("ioc")), tech="T1071")
    for u in f.get("large_uploads") or []:
        add("exfil", u.get("first", 0), "upload", u.get("dst", ""), str(u.get("bytes") or 0),
            [u.get("src", ""), u.get("dst", "")], ioc=bool(u.get("ioc")), tech="T1041")
    for u in f.get("unusual_ports") or []:
        add("c2", 0, "unusual", f'{u.get("dst", "")}:{u.get("port", "")}',
            f'{u.get("service", "")}/{u.get("proto", "")} · ×{u.get("count", 0)}',
            [u.get("dst", "")] + list(u.get("clients") or []), tech="T1571")
    for c in (f.get("cleartext_auth") or []) + (f.get("cleartext") or []):
        detail = f'user {c["user"]} · ' if c.get("user") else ""
        add("creds", c.get("ts", 0), "cleartext", c.get("proto", ""),
            f'{detail}→ {c.get("dst", "")}', [c.get("src", ""), c.get("dst", "")], tech="T1040")
    beacon_src = {b.get("src") for b in (f.get("beacons") or [])}
    for t in quality.tls_strong((rep.get("tls") or {}).get("invalid") or []):
        add("c2", t.get("ts", 0), "tls_bad", t.get("sni", "") or t.get("dst", ""),
            t.get("status", ""), [t.get("src", ""), t.get("dst", "")], ioc=False,
            tech="T1573" if t.get("src") in beacon_src else "")
    for d in (rep.get("dns") or {}).get("suspicious") or []:
        add("c2", 0, "dns_sus", d.get("name", ""), f'{d.get("reason", "")} · ×{d.get("count", 0)}',
            d.get("clients") or [], ioc=True, tech="T1071.004")
    for x in rep.get("files") or []:
        if x.get("ioc"):
            add("c2", x.get("ts", 0), "file", x.get("filename") or (x.get("sha256") or "")[:16],
                x.get("mime", ""), [x.get("sender", ""), x.get("receiver", "")], ioc=True, tech="T1105")
    for h in rep.get("ioc_hits") or []:
        add("c2", 0, "ioc", h.get("value", ""), h.get("type_label") or h.get("type", ""),
            h.get("hosts") or [], ioc=True, tech="T1071")

    # ---- итоги по этапам и хосты, замеченные на нескольких этапах
    host_stages: dict[str, list[str]] = {}
    for st in stages.values():
        st["events"].sort(key=lambda e: (not e["ts"], e["ts"]))
        tss = [e["ts"] for e in st["events"] if e["ts"]]
        st["first"], st["last"] = (min(tss), max(tss)) if tss else (0.0, 0.0)
        st["count"] = len(st["events"])
        st["techs"] = sorted(st["techs"], key=lambda t: -st["techs"][t])
        for h in st["hosts"]:
            host_stages.setdefault(h, []).append(st["key"])

    multi = [{"ip": ip, "stages": sorted(keys, key=lambda k: [s for s, _ in STAGES].index(k))}
             for ip, keys in host_stages.items() if len(keys) >= 2]
    multi.sort(key=lambda x: (-len(x["stages"]), x["ip"]))

    return {"stages": list(stages.values()),
            "covered": sum(1 for st in stages.values() if st["events"]),
            "hosts": multi, "tickets": _ticket_chains(rep)}

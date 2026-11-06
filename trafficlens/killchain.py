"""Цепочка компрометации: находки отчёта, разложенные по этапам атаки.

Строится по report.json (как mitre.py), поэтому работает и для отчётов,
собранных старыми версиями. Этапы упорядочены по логике kill chain — от
разведки к воздействию; внутри этапа доказательства идут по времени.
Дополнительно считаются хосты, замеченные на двух и более этапах, — с них
имеет смысл начинать расследование.
"""
from __future__ import annotations

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
MAX_ITEMS = 50  # доказательств на этап; остальное — в основных вкладках отчёта


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


def build(rep: dict) -> dict:
    """{stages: [...], hosts: [...], covered: int} по данным отчёта."""
    stages: dict[str, dict] = {
        key: {"key": key, "tactic": tactic, "tactic_name": TACTICS[tactic],
              "events": [], "hosts": [], "techs": {}, "first": 0.0, "last": 0.0, "truncated": False}
        for key, tactic in STAGES
    }

    def add(stage_key: str, ts: float, kind: str, title: str, detail: str = "",
            hosts=(), ioc: bool = False, tech: str = "") -> None:
        st = stages[stage_key]
        if len(st["events"]) >= MAX_ITEMS:
            st["truncated"] = True
            return
        st["events"].append({"ts": ts or 0, "kind": kind, "title": title,
                            "detail": detail, "hosts": list(hosts), "ioc": ioc})
        for h in hosts:
            if h and h not in st["hosts"]:
                st["hosts"].append(h)
        if tech:
            st["techs"][tech] = st["techs"].get(tech, 0) + 1

    # ---- сигнатуры Suricata: категория -> тактика/техника (mitre.alert_tags)
    for a in rep.get("alerts") or []:
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
    for t in (rep.get("tls") or {}).get("invalid") or []:
        add("c2", t.get("ts", 0), "tls_bad", t.get("sni", "") or t.get("dst", ""),
            t.get("status", ""), [t.get("src", ""), t.get("dst", "")], ioc=True, tech="T1573")
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
        st["count"] = len(st["events"]) + (1 if st["truncated"] else 0)
        st["techs"] = sorted(st["techs"], key=lambda t: -st["techs"][t])
        for h in st["hosts"]:
            host_stages.setdefault(h, []).append(st["key"])

    multi = [{"ip": ip, "stages": sorted(keys, key=lambda k: [s for s, _ in STAGES].index(k))}
             for ip, keys in host_stages.items() if len(keys) >= 2]
    multi.sort(key=lambda x: (-len(x["stages"]), x["ip"]))

    return {"stages": list(stages.values()),
            "covered": sum(1 for st in stages.values() if st["events"]),
            "hosts": multi}

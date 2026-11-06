"""Карточка хоста: все данные задачи по одному IP — таймлайн, контакты, IOC, файлы.

Источники — те же логи Zeek/Suricata в каталоге задачи (полная детализация)
и report.json (приоритет, IOC-контексты, имена). Никаких новых сборщиков
данных: карточка — это другой вид на уже разобранный дамп.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import report as report_mod
from .config import Config
from .db import DB  # noqa: F401  (тип для аннотаций)

MAX_EVENTS = 2000
MAX_CONTACTS = 200


def _names(rep: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for coll in ("local_hosts", "top_external"):
        for h in rep.get(coll, []):
            if h.get("ip") and h.get("name"):
                out[h["ip"]] = h["name"]
    return out


def build(cfg: Config, job: dict, ip: str) -> dict | None:
    from .pipeline import job_dir

    jd = job_dir(cfg, job["id"])
    if not jd.exists():
        return None
    rep: dict = {}
    rp = jd / "report.json"
    if rp.exists():
        try:
            rep = json.loads(rp.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            rep = {}
    names = _names(rep)
    ioc_ips = {o for h in rep.get("ioc_hits", []) for o in h.get("observed", [])}
    ioc_vals = {h.get("value", "") for h in rep.get("ioc_hits", [])}

    def is_ioc_peer(peer: str) -> bool:
        return peer in ioc_ips

    events: list[dict] = []
    zdir, sdir = jd / "zeek", jd / "suricata"

    # ---------- протокольные события из логов Zeek
    for r in report_mod.read_log(zdir / "dns.log"):
        if r.get("id.orig_h") != ip:
            continue
        q = (r.get("query") or "").strip(".")
        answers = [str(a).strip(".") for a in (r.get("answers") or []) if a][:5]
        events.append({"ts": r.get("ts", 0), "kind": "dns", "q": q, "rcode": r.get("rcode_name") or "",
                       "answers": answers, "ioc": q.lower() in ioc_vals or any(a in ioc_ips for a in answers)})

    for r in report_mod.read_log(zdir / "ssl.log"):
        if ip not in (r.get("id.orig_h"), r.get("id.resp_h")):
            continue
        peer = r.get("id.resp_h") if r.get("id.orig_h") == ip else r.get("id.orig_h")
        sni = r.get("server_name") or ""
        vs = r.get("validation_status") or ""
        events.append({"ts": r.get("ts", 0), "kind": "tls", "peer": peer, "dp": r.get("id.resp_p"),
                       "sni": sni, "version": r.get("version") or "", "validation": vs,
                       "ioc": is_ioc_peer(peer) or sni.lower() in ioc_vals,
                       "bad": bool(vs and vs != "ok")})

    for r in report_mod.read_log(zdir / "http.log"):
        if ip not in (r.get("id.orig_h"), r.get("id.resp_h")):
            continue
        peer = r.get("id.resp_h") if r.get("id.orig_h") == ip else r.get("id.orig_h")
        host = (r.get("host") or "").lower()
        events.append({"ts": r.get("ts", 0), "kind": "http", "peer": peer, "method": r.get("method", ""),
                       "host": host, "uri": (r.get("uri") or "/")[:200], "status": r.get("status_code"),
                       "ioc": is_ioc_peer(peer) or host in ioc_vals})

    for r in report_mod.read_log(zdir / "files.log"):
        if "id.orig_h" in r:
            o, p = r.get("id.orig_h", ""), r.get("id.resp_h", "")
            sender, receiver = (o, p) if r.get("is_orig") else (p, o)
        else:
            sender = (r.get("tx_hosts") or [""])[0]
            receiver = (r.get("rx_hosts") or [""])[0]
        if ip not in (sender, receiver):
            continue
        ioc = any(r.get(k, "") in ioc_vals for k in ("sha256", "sha1", "md5"))
        events.append({"ts": r.get("ts", 0), "kind": "file", "filename": r.get("filename") or "",
                       "size": r.get("seen_bytes") or r.get("total_bytes") or 0,
                       "peer": receiver if sender == ip else sender,
                       "direction": "upload" if sender == ip else "download",
                       "sha256": r.get("sha256", ""), "ioc": ioc})

    # ---------- алерты Suricata
    for r in report_mod.read_log(sdir / "eve.json"):
        if r.get("event_type") != "alert":
            continue
        if ip not in (r.get("src_ip"), r.get("dest_ip")):
            continue
        a = r.get("alert") or {}
        events.append({"ts": report_mod.suri_ts(r.get("timestamp", "")), "kind": "alert",
                       "signature": a.get("signature", ""), "category": a.get("category", ""),
                       "severity": a.get("severity", 3),
                       "peer": r.get("dest_ip") if r.get("src_ip") == ip else r.get("src_ip"),
                       "ioc": True})

    for r in report_mod.read_log(zdir / "notice.log"):
        if ip not in (r.get("src") or r.get("id.orig_h", ""), r.get("dst") or r.get("id.resp_h", "")):
            continue
        events.append({"ts": r.get("ts", 0), "kind": "notice", "note": r.get("note", ""), "msg": (r.get("msg") or "")[:200]})

    # ---------- находки из отчёта (маячки, выгрузки и т.п.)
    f = rep.get("findings") or {}
    for b in f.get("beacons") or []:
        if ip in (b.get("src"), b.get("dst")):
            events.append({"ts": b.get("first", 0), "kind": "beacon", "peer": b.get("dst") if b.get("src") == ip else b.get("src"),
                           "dp": b.get("dp"), "interval": b.get("interval"), "count": b.get("count"), "ioc": bool(b.get("ioc"))})
    for u in f.get("large_uploads") or []:
        if ip in (u.get("src"), u.get("dst")):
            events.append({"ts": u.get("first", 0), "kind": "upload", "peer": u.get("dst") if u.get("src") == ip else u.get("src"),
                           "bytes": u.get("bytes"), "ioc": bool(u.get("ioc"))})
    for c in f.get("long_conns") or []:
        if ip in (c.get("src"), c.get("dst")):
            events.append({"ts": c.get("ts", 0), "kind": "long", "peer": c.get("dst") if c.get("src") == ip else c.get("src"),
                           "dp": c.get("dp"), "dur": c.get("dur")})
    for u in f.get("unusual_ports") or []:
        if u.get("dst") == ip or ip in (u.get("clients") or []):
            events.append({"ts": 0, "kind": "unusual", "peer": u.get("dst"), "service": u.get("service"),
                           "proto": u.get("proto"), "port": u.get("port"), "count": u.get("count")})
    for c in (f.get("cleartext_auth") or []) + (f.get("cleartext") or []):
        if ip in (c.get("src"), c.get("dst")):
            events.append({"ts": c.get("ts", 0), "kind": "cleartext", "proto": c.get("proto", ""),
                           "user": c.get("user", ""), "peer": c.get("dst") if c.get("src") == ip else c.get("src")})
    for t in (rep.get("tls") or {}).get("invalid") or []:
        if ip in (t.get("src"), t.get("dst")):
            events.append({"ts": t.get("ts", 0), "kind": "tls_bad", "peer": t.get("dst") if t.get("src") == ip else t.get("src"),
                           "sni": t.get("sni", ""), "validation": t.get("status", ""), "ioc": True})
    for d in (rep.get("dns") or {}).get("suspicious") or []:
        if ip in (d.get("clients") or []):
            events.append({"ts": 0, "kind": "dns_sus", "q": d.get("name", ""), "reason": d.get("reason"), "ioc": True})

    events = [e for e in events if e.get("kind")]
    events.sort(key=lambda e: e.get("ts") or 0)
    truncated = len(events) > MAX_EVENTS
    events = events[:MAX_EVENTS]

    # ---------- контакты и счётчики из conn.log
    contacts: dict[str, dict] = {}
    totals = {"conns": 0, "out": 0, "in": 0}
    for r in report_mod.read_log(zdir / "conn.log"):
        src, dst = r.get("id.orig_h", ""), r.get("id.resp_h", "")
        if ip not in (src, dst):
            continue
        peer = dst if src == ip else src
        ob = r.get("orig_ip_bytes") or r.get("orig_bytes") or 0
        rb = r.get("resp_ip_bytes") or r.get("resp_bytes") or 0
        out_b, in_b = (ob, rb) if src == ip else (rb, ob)
        totals["conns"] += 1
        totals["out"] += out_b
        totals["in"] += in_b
        c = contacts.get(peer)
        if c is None:
            c = contacts[peer] = {"ip": peer, "conns": 0, "out": 0, "in": 0, "ports": Counter()}
        c["conns"] += 1
        c["out"] += out_b
        c["in"] += in_b
        c["ports"][f"{r.get('proto')}/{r.get('id.resp_p')}"] += 1
    contact_list = sorted(
        ({"ip": c["ip"], "name": names.get(c["ip"], ""), "conns": c["conns"], "out": c["out"], "in": c["in"],
          "ports": [p for p, _ in c["ports"].most_common(5)], "ioc": is_ioc_peer(c["ip"])}
         for c in contacts.values()),
        key=lambda x: (not x["ioc"], -(x["out"] + x["in"])))[:MAX_CONTACTS]

    # ---------- срезы отчёта по хосту
    ioc_hits = [h for h in rep.get("ioc_hits", []) if ip in (h.get("hosts") or [])]
    files = [x for x in rep.get("files", []) if ip in (x.get("sender"), x.get("receiver"))]
    risk = next((h for h in rep.get("priority_hosts", []) if h.get("ip") == ip), None)
    loc = report_mod.Locality(cfg["local_nets"])
    meta = rep.get("meta", {})
    info = next((h for h in rep.get("local_hosts", []) if h.get("ip") == ip), {})

    return {
        "ip": ip, "local": loc.is_local(ip), "name": names.get(ip, ""), "mac": info.get("mac", ""),
        "risk": risk, "totals": totals, "events": events, "truncated": truncated,
        "contacts": contact_list, "ioc_hits": ioc_hits, "files": files,
        "period": meta.get("period", {}), "job_status": job.get("status"),
    }

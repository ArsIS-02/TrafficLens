"""Сборка отчёта из логов Zeek / Suricata и сопоставление с IOC."""
from __future__ import annotations

import hashlib
import heapq
import ipaddress
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from . import runner as runner_mod
from .ioc_store import IOCIndex, Match
from .ioc_types import TYPE_LABELS, norm_url

STD_PORTS = {
    "http": {80, 8080, 8000, 8008, 8081, 8888, 3128, 591},
    "ssl": {443, 8443, 993, 995, 465, 636, 853, 5061, 9443, 6443, 989, 990, 5986, 8883, 4443},
    "ssh": {22},
    "dns": {53, 5353, 5355},
    "ftp": {21},
    "smtp": {25, 587, 465, 2525},
    "rdp": {3389},
    "smb": {445, 139},
    "irc": set(),          # любой IRC — подозрительно
    "socks": {1080},
}
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP", 512: "rexec", 513: "rlogin", 1433: "MSSQL", 5900: "VNC"}
SEV_LABEL = {1: "высокая", 2: "средняя", 3: "низкая", 4: "инфо"}


# ---------------------------------------------------------------- чтение логов
def read_log(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line[0] != "{":
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def suri_ts(s: str) -> float:
    try:
        if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return 0.0


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Locality:
    def __init__(self, nets: list[str]):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets]

        @lru_cache(maxsize=65536)
        def is_local(ip: str) -> bool:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if a.is_multicast or a.is_unspecified or (a.version == 4 and str(a) == "255.255.255.255"):
                return True
            return any(a.version == n.version and a in n for n in self.nets)

        self.is_local = is_local


# ---------------------------------------------------------------- IOC-попадания
def suricata_meta(cfg: dict, sdir: Path) -> dict:
    """Статус сигнатурного анализа: отключён, нет правил, нет eve.json или ок."""
    enabled = bool(cfg.get("suricata", {}).get("enabled", True))
    rs = runner_mod.rules_status(cfg)
    ran = (sdir / "eve.json").exists()
    if not enabled:
        status, warning = "disabled", "Suricata отключена в конфигурации"
    elif not rs["available"]:
        status, warning = "no_rules", "Нет правил Suricata — сигнатурный анализ будет пустым"
    elif not ran:
        status, warning = "no_eve", "Suricata не оставила eve.json — сигнатурный анализ не выполнен"
    else:
        status, warning = "ok", ""
    return {"enabled": enabled, "ran": ran, "status": status, "warning": warning, **rs}


class Hits:
    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}

    def add(self, m: Match | None, ctx: str, ts: float, src: str = "", dst: str = "", port: int | None = None, detail: str = ""):
        if not m:
            return
        key = (m.type, m.value)
        h = self.items.get(key)
        if h is None:
            h = self.items[key] = {
                "type": m.type, "type_label": TYPE_LABELS.get(m.type, m.type), "value": m.value,
                "observed": set(), "contexts": Counter(), "sources": m.entries, "count": 0,
                "first": ts, "last": ts, "hosts": set(), "port_match": False, "examples": [],
            }
        h["count"] += 1
        h["contexts"][ctx] += 1
        h["observed"].add(m.observed)
        if ts:
            h["first"] = min(h["first"] or ts, ts)
            h["last"] = max(h["last"] or ts, ts)
        for x in (src, dst):
            if x:
                h["hosts"].add(x)
        if port and any(e.get("port") == port for e in m.entries):
            h["port_match"] = True
        if len(h["examples"]) < 5:
            h["examples"].append({"ts": ts, "ctx": ctx, "src": src, "dst": dst, "port": port, "detail": detail})

    def export(self) -> list[dict]:
        out = []
        for h in self.items.values():
            d = dict(h)
            d["observed"] = sorted(h["observed"])[:20]
            d["contexts"] = dict(h["contexts"])
            d["hosts"] = sorted(h["hosts"])[:30]
            d["max_conf"] = max((e.get("confidence") or 0) for e in h["sources"]) if h["sources"] else 0
            out.append(d)
        out.sort(key=lambda x: (-x["max_conf"], -x["count"]))
        return out


# ---------------------------------------------------------------- построение
def build(job_dir: Path, index: IOCIndex, cfg: dict, meta: dict | None = None) -> dict:
    zdir, sdir = job_dir / "zeek", job_dir / "suricata"
    loc = Locality(cfg["local_nets"])
    heur = cfg["heuristics"]
    max_rows = int(cfg.get("report", {}).get("max_rows", 500))
    hits = Hits()
    is_local = loc.is_local

    # --- карты имён: ip -> домен (DNS/SNI), ip -> hostname/MAC (DHCP)
    ip_names: dict[str, Counter] = defaultdict(Counter)
    host_info: dict[str, dict] = defaultdict(dict)

    # ======================= DNS
    dns_q = Counter()
    dns_clients: dict[str, set] = defaultdict(set)
    dns_rcode: dict[str, Counter] = defaultdict(Counter)
    nx = Counter()
    nx_clients: dict[str, set] = defaultdict(set)
    resolvers = Counter()
    qtypes = Counter()
    txt_by_base = Counter()
    suspicious_dns: dict[str, dict] = {}
    dns_total = 0
    for r in read_log(zdir / "dns.log"):
        dns_total += 1
        q = (r.get("query") or "").strip(".").lower()
        ts, src, dst = r.get("ts", 0), r.get("id.orig_h", ""), r.get("id.resp_h", "")
        resolvers[dst] += 1
        qt = r.get("qtype_name") or "-"
        qtypes[qt] += 1
        if not q:
            continue
        dns_q[q] += 1
        if len(dns_clients[q]) < 50:
            dns_clients[q].add(src)
        rc = r.get("rcode_name") or ("-" if r.get("rcode") is None else str(r.get("rcode")))
        dns_rcode[q][rc] += 1
        if rc == "NXDOMAIN":
            nx[q] += 1
            if len(nx_clients[q]) < 20:
                nx_clients[q].add(src)
        hits.add(index.domain(q), "ctx_dns_query", ts, src, dst, detail=qt)
        for a in r.get("answers") or []:
            a = str(a).strip(".").lower()
            try:
                ipaddress.ip_address(a)
                ip_names[a][q] += 1
                hits.add(index.ip(a), "ctx_dns_answer", ts, src, a, detail=q)
            except ValueError:
                hits.add(index.domain(a), "ctx_dns_cname", ts, src, dst, detail=q)
        # эвристики имени
        if q.endswith((".arpa", ".local", ".lan", ".home", ".internal")) or q.startswith("_"):
            continue
        parts = q.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 else q
        if qt == "TXT":
            txt_by_base[base] += 1
        labels = parts[:-2] if len(parts) > 2 else parts[:1]
        longest = max(labels, key=len) if labels else ""
        reason = None
        if len(q) > 100:
            reason = {"k": "dns_long", "n": len(q)}
        elif len(longest) >= int(heur["dns_min_label"]) and entropy(longest) >= float(heur["dns_entropy"]):
            reason = {"k": "dns_entropy", "label": longest[:30], "e": f"{entropy(longest):.2f}"}
        if reason:
            s = suspicious_dns.setdefault(q, {"name": q, "reason": reason, "count": 0, "clients": set()})
            s["count"] += 1
            s["clients"].add(src)
    for base, n in txt_by_base.items():
        if n >= 20:
            suspicious_dns[f"*.{base}"] = {"name": f"*.{base}", "reason": {"k": "dns_txt", "n": n}, "count": n, "clients": set()}

    # ======================= DHCP
    for r in read_log(zdir / "dhcp.log"):
        ip = r.get("assigned_addr") or r.get("client_addr")
        if ip:
            if r.get("host_name"):
                host_info[ip]["hostname"] = r["host_name"]
            if r.get("mac"):
                host_info[ip]["mac"] = r["mac"]

    # ======================= HTTP
    fuid_url: dict[str, str] = {}
    fuid_name: dict[str, str] = {}
    http_rows = []
    http_hosts = Counter()
    uas = Counter()
    http_total = 0
    cleartext_auth = []
    for r in read_log(zdir / "http.log"):
        http_total += 1
        ts, src, dst = r.get("ts", 0), r.get("id.orig_h", ""), r.get("id.resp_h", "")
        host = (r.get("host") or dst or "").lower()
        uri = r.get("uri") or "/"
        port = r.get("id.resp_p")
        hostport = host if port in (80, None) or ":" in host else f"{host}:{port}"
        url_n = norm_url("http://" + hostport + uri)
        http_hosts[host] += 1
        if r.get("user_agent"):
            uas[r["user_agent"]] += 1
        m_host = index.domain(host.split(":")[0]) or index.ip(host.split(":")[0])
        hits.add(m_host, "ctx_http_host", ts, src, dst, port, detail=r.get("method", ""))
        m_url = index.url(url_n)
        hits.add(m_url, "ctx_http_url", ts, src, dst, port, detail=r.get("method", ""))
        for f in (r.get("resp_fuids") or []) + (r.get("orig_fuids") or []):
            fuid_url[f] = "http://" + hostport + uri
            last = uri.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            if last:
                fuid_name.setdefault(f, last)
        if r.get("username") or r.get("password"):
            cleartext_auth.append({"ts": ts, "proto": "HTTP Basic", "src": src, "dst": dst, "user": r.get("username") or "?"})
        if len(http_rows) < max_rows:
            http_rows.append({
                "ts": ts, "src": src, "dst": dst, "port": port, "method": r.get("method", ""), "host": host,
                "uri": uri[:300], "status": r.get("status_code"), "ua": (r.get("user_agent") or "")[:200],
                "req_len": r.get("request_body_len", 0), "resp_len": r.get("response_body_len", 0),
                "mime": ",".join(r.get("resp_mime_types") or []), "ioc": bool(m_host or m_url),
            })

    # ======================= SMB / FTP имена файлов
    for r in read_log(zdir / "smb_files.log"):
        if r.get("fuid") and r.get("name"):
            fuid_name[r["fuid"]] = r["name"]
    ftp_users = []
    for r in read_log(zdir / "ftp.log"):
        if r.get("fuid") and r.get("arg"):
            fuid_name[r["fuid"]] = r["arg"].rsplit("/", 1)[-1]
        if r.get("user") and r.get("user") != "<unknown>" and len(ftp_users) < 50:
            ftp_users.append({"ts": r.get("ts"), "proto": "FTP", "src": r.get("id.orig_h"), "dst": r.get("id.resp_h"), "user": r.get("user")})
    cleartext_auth += ftp_users

    # ======================= TLS
    sni_stats: dict[str, dict] = {}
    tls_versions = Counter()
    invalid_certs = []
    tls_total = 0
    for r in read_log(zdir / "ssl.log"):
        tls_total += 1
        ts, src, dst = r.get("ts", 0), r.get("id.orig_h", ""), r.get("id.resp_h", "")
        sni = (r.get("server_name") or "").lower()
        ver = r.get("version") or "?"
        tls_versions[ver] += 1
        if sni:
            ip_names[dst][sni] += 1
            hits.add(index.domain(sni), "ctx_tls_sni", ts, src, dst, r.get("id.resp_p"))
        key = sni or f"[{dst}]"
        s = sni_stats.setdefault(key, {"sni": key, "count": 0, "dst": set(), "versions": Counter(), "validation": Counter(), "ja3": set(), "ja4": set()})
        s["count"] += 1
        if len(s["dst"]) < 10:
            s["dst"].add(dst)
        s["versions"][ver] += 1
        vs = r.get("validation_status")
        if vs:
            s["validation"][vs] += 1
            if vs != "ok" and not is_local(dst) and len(invalid_certs) < max_rows:
                invalid_certs.append({"ts": ts, "src": src, "dst": dst, "sni": sni, "status": vs})

    # ======================= Suricata
    alerts: dict[int, dict] = {}
    suri_ok = (sdir / "eve.json").exists()
    for r in read_log(sdir / "eve.json"):
        et = r.get("event_type")
        if et == "alert":
            a = r.get("alert") or {}
            sid = a.get("signature_id", 0)
            ts = suri_ts(r.get("timestamp", ""))
            e = alerts.setdefault(sid, {"sid": sid, "signature": a.get("signature", ""), "category": a.get("category", ""),
                                        "severity": a.get("severity", 3), "count": 0, "first": ts, "last": ts, "pairs": Counter()})
            e["count"] += 1
            e["first"], e["last"] = min(e["first"], ts), max(e["last"], ts)
            e["pairs"][f"{r.get('src_ip')}:{r.get('src_port', '')} → {r.get('dest_ip')}:{r.get('dest_port', '')}"] += 1
        elif et == "tls":
            t = r.get("tls") or {}
            ts = suri_ts(r.get("timestamp", ""))
            sni = (t.get("sni") or "").lower()
            key = sni or f"[{r.get('dest_ip')}]"
            ja3 = (t.get("ja3") or {}).get("hash") if isinstance(t.get("ja3"), dict) else None
            ja4 = t.get("ja4") if isinstance(t.get("ja4"), str) else None
            s = sni_stats.get(key)
            if ja3:
                hits.add(index.hash("ja3", ja3), "ctx_tls_ja3", ts, r.get("src_ip", ""), r.get("dest_ip", ""), r.get("dest_port"), detail=sni)
                if s is not None and len(s["ja3"]) < 5:
                    s["ja3"].add(ja3)
            if ja4:
                hits.add(index.hash("ja4", ja4), "ctx_tls_ja4", ts, r.get("src_ip", ""), r.get("dest_ip", ""), r.get("dest_port"), detail=sni)
                if s is not None and len(s["ja4"]) < 5:
                    s["ja4"].add(ja4)

    # ======================= Файлы
    files = []
    files_total = 0
    extract_dir = zdir / "extract_files"
    for r in read_log(zdir / "files.log"):
        files_total += 1
        fuid = r.get("fuid", "")
        ts = r.get("ts", 0)
        if "id.orig_h" in r:
            o, p = r.get("id.orig_h", ""), r.get("id.resp_h", "")
            sender, receiver = (o, p) if r.get("is_orig") else (p, o)
        else:  # Zeek < 5
            sender = (r.get("tx_hosts") or [""])[0]
            receiver = (r.get("rx_hosts") or [""])[0]
        sl, rl = is_local(sender), is_local(receiver)
        direction = "internal" if sl and rl else "download" if rl else "upload" if sl else "external"
        ioc = []
        for kind in ("sha256", "sha1", "md5"):
            m = index.hash(kind, r.get(kind) or "")
            if m:
                hits.add(m, f"ctx_file_{kind}", ts, sender, receiver, detail=r.get("filename") or fuid_name.get(fuid, ""))
                ioc.extend(m.entries)
                break
        extracted = r.get("extracted")
        files.append({
            "ts": ts, "fuid": fuid, "proto": r.get("source", ""), "sender": sender, "receiver": receiver,
            "direction": direction, "filename": r.get("filename") or fuid_name.get(fuid, ""),
            "mime": r.get("mime_type") or "", "size": r.get("seen_bytes") or r.get("total_bytes") or 0,
            "total": r.get("total_bytes"), "missing": r.get("missing_bytes", 0),
            "md5": r.get("md5", ""), "sha1": r.get("sha1", ""), "sha256": r.get("sha256", ""),
            "extracted": extracted if extracted and (extract_dir / extracted).exists() else "",
            "url": fuid_url.get(fuid, ""), "ioc": ioc,
        })
    files.sort(key=lambda f: (not f["ioc"], f["ts"]))
    files_shown = files[:max_rows]

    # ======================= Соединения
    conns_total = 0
    bytes_total = 0
    pkts_total = 0
    t_min, t_max = None, None
    per_sec_c = Counter()
    per_sec_b = Counter()
    talkers: dict[str, list] = defaultdict(lambda: [0, 0, 0])   # out, in, conns
    ext: dict[str, dict] = {}
    services = defaultdict(lambda: [0, 0])
    ports = defaultdict(lambda: [0, 0])
    top_conn: list = []
    beacons_ts: dict[tuple, list] = {}
    upload_sum: dict[tuple, list] = defaultdict(lambda: [0, 0, 0.0, 0.0])
    long_conns = []
    unusual = Counter()
    cleartext = Counter()
    ignore_ports = set(heur.get("beacon_ignore_ports", []))
    long_sec = float(heur["long_conn_hours"]) * 3600
    seq = 0
    for r in read_log(zdir / "conn.log"):
        conns_total += 1
        ts = r.get("ts", 0.0)
        src, dst = r.get("id.orig_h", ""), r.get("id.resp_h", "")
        sp, dp = r.get("id.orig_p", 0), r.get("id.resp_p", 0)
        proto = r.get("proto", "")
        svc = r.get("service") or ""
        ob = r.get("orig_ip_bytes") or r.get("orig_bytes") or 0
        rb = r.get("resp_ip_bytes") or r.get("resp_bytes") or 0
        pk = (r.get("orig_pkts") or 0) + (r.get("resp_pkts") or 0)
        dur = r.get("duration") or 0.0
        tot = ob + rb
        bytes_total += tot
        pkts_total += pk
        end = ts + dur
        t_min = ts if t_min is None else min(t_min, ts)
        t_max = end if t_max is None else max(t_max, end)
        sec = int(ts)
        per_sec_c[sec] += 1
        per_sec_b[sec] += tot
        talkers[src][0] += ob
        talkers[src][1] += rb
        talkers[src][2] += 1
        talkers[dst][0] += rb
        talkers[dst][1] += ob
        talkers[dst][2] += 1
        if r.get("orig_l2_addr") and is_local(src):
            host_info[src].setdefault("mac", r["orig_l2_addr"])
        sl, dl = is_local(src), is_local(dst)
        m_dst = index.ip(dst)
        m_src = index.ip(src)
        hits.add(m_dst, "ctx_conn_dst", ts, src, dst, dp, detail=f"{proto}/{dp} {svc}")
        hits.add(m_src, "ctx_conn_src", ts, src, dst, dp, detail=f"{proto}/{dp} {svc}")
        if not dl:
            e = ext.get(dst)
            if e is None:
                e = ext[dst] = {"ip": dst, "bytes": 0, "conns": 0, "ports": Counter(), "services": Counter(), "clients": set()}
            e["bytes"] += tot
            e["conns"] += 1
            e["ports"][f"{proto}/{dp}"] += 1
            if svc:
                e["services"][svc] += 1
            if len(e["clients"]) < 20:
                e["clients"].add(src)
        for s in (svc.split(",") if svc else ["—"]):
            services[s][0] += 1
            services[s][1] += tot
        ports[(proto, dp)][0] += 1
        ports[(proto, dp)][1] += tot
        seq += 1
        row = (tot, seq, {"ts": ts, "uid": r.get("uid", ""), "src": src, "sp": sp, "dst": dst, "dp": dp, "proto": proto,
                          "svc": svc, "dur": dur, "ob": ob, "rb": rb, "state": r.get("conn_state", ""),
                          "ioc": bool(m_dst or m_src)})
        if len(top_conn) < max_rows:
            heapq.heappush(top_conn, row)
        elif tot > top_conn[0][0]:
            heapq.heapreplace(top_conn, row)
        # эвристики
        if sl and not dl and dp not in ignore_ports:
            k = (src, dst, dp, proto)
            lst = beacons_ts.get(k)
            if lst is None:
                if len(beacons_ts) < 200000:
                    beacons_ts[k] = [ts]
            elif len(lst) < 5000:
                lst.append(ts)
            u = upload_sum[(src, dst)]
            u[0] += r.get("orig_bytes") or 0
            u[1] += 1
            u[2] = ts if not u[2] else min(u[2], ts)
            u[3] = max(u[3], end)
        if dur >= long_sec and len(long_conns) < max_rows:
            long_conns.append({"ts": ts, "src": src, "dst": dst, "dp": dp, "proto": proto, "svc": svc, "dur": dur, "bytes": tot})
        if svc:
            for s in svc.split(","):
                std = STD_PORTS.get(s)
                if std is not None and dp not in std:
                    unusual[(s, proto, dp, dst)] += 1
        elif proto == "tcp" and dp in CLEARTEXT_PORTS and r.get("conn_state") in ("SF", "S1", "S2", "S3", "RSTO", "RSTR"):
            cleartext[(CLEARTEXT_PORTS[dp], src, dst, dp)] += 1
        if svc and any(s in ("ftp", "telnet", "pop3", "imap") for s in svc.split(",")):
            cleartext[(svc.upper(), src, dst, dp)] += 1

    # ---- таймлайн
    timeline = {"bucket": 0, "start": 0, "conns": [], "bytes": []}
    if per_sec_c:
        lo, hi = min(per_sec_c), max(per_sec_c)
        span = max(1, hi - lo + 1)
        nice = [1, 5, 10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
        bucket = next((b for b in nice if span / b <= 120), 86400)
        n = span // bucket + 1
        cc, bb = [0] * n, [0] * n
        for s_, v in per_sec_c.items():
            cc[(s_ - lo) // bucket] += v
        for s_, v in per_sec_b.items():
            bb[(s_ - lo) // bucket] += v
        timeline = {"bucket": bucket, "start": lo, "conns": cc, "bytes": bb}

    def name_of(ip: str) -> str:
        c = ip_names.get(ip)
        if c:
            return c.most_common(1)[0][0]
        return host_info.get(ip, {}).get("hostname", "")

    ioc_ips = {o for h in hits.items.values() for o in h["observed"]}

    top_talkers = sorted(
        ({"ip": ip, "local": is_local(ip), "name": name_of(ip), "out": v[0], "in": v[1], "conns": v[2],
          "mac": host_info.get(ip, {}).get("mac", ""), "ioc": ip in ioc_ips} for ip, v in talkers.items() if ip),
        key=lambda x: -(x["out"] + x["in"]))[:50]
    top_external = sorted(
        ({"ip": e["ip"], "name": name_of(e["ip"]), "bytes": e["bytes"], "conns": e["conns"],
          "ports": [p for p, _ in e["ports"].most_common(5)], "services": [s for s, _ in e["services"].most_common(3)],
          "clients": sorted(e["clients"])[:5], "ioc": e["ip"] in ioc_ips} for e in ext.values()),
        key=lambda x: (not x["ioc"], -x["bytes"]))[:max_rows]
    local_hosts = sorted(
        ({"ip": ip, "name": name_of(ip), "mac": host_info.get(ip, {}).get("mac", ""), "out": v[0], "in": v[1], "conns": v[2]}
         for ip, v in talkers.items() if ip and is_local(ip) and not _is_mcast(ip)),
        key=lambda x: -(x["out"] + x["in"]))[:200]

    # ---- маячки
    beacons = []
    for (src, dst, dp, proto), lst in beacons_ts.items():
        if len(lst) < int(heur["beacon_min_conns"]):
            continue
        lst.sort()
        iv = [b - a for a, b in zip(lst, lst[1:]) if b - a > 0.5]
        if len(iv) < int(heur["beacon_min_conns"]) - 1:
            continue
        mean = statistics.fmean(iv)
        if mean < 2:
            continue
        cv = statistics.pstdev(iv) / mean if mean else 9
        if cv <= float(heur["beacon_max_cv"]):
            beacons.append({"src": src, "dst": dst, "name": name_of(dst), "dp": dp, "proto": proto, "count": len(lst),
                            "interval": mean, "cv": cv, "first": lst[0], "last": lst[-1], "ioc": dst in ioc_ips})
    beacons.sort(key=lambda b: (not b["ioc"], b["cv"]))

    large_uploads = sorted(
        ({"src": k[0], "dst": k[1], "name": name_of(k[1]), "bytes": v[0], "conns": v[1], "first": v[2], "last": v[3],
          "ioc": k[1] in ioc_ips}
         for k, v in upload_sum.items() if v[0] >= float(heur["large_upload_mb"]) * 1024 * 1024),
        key=lambda x: -x["bytes"])[:max_rows]

    unusual_ports = [{"service": s, "proto": p, "port": port, "dst": d, "name": name_of(d), "count": n}
                     for (s, p, port, d), n in unusual.most_common(max_rows)]
    cleartext_list = [{"proto": p, "src": s, "dst": d, "port": port, "count": n} for (p, s, d, port), n in cleartext.most_common(100)]

    # ---- Zeek notice / weird
    notices = Counter()
    notice_ex = {}
    for r in read_log(zdir / "notice.log"):
        k = (r.get("note", ""), r.get("msg", ""))
        notices[k] += 1
        notice_ex.setdefault(k, {"src": r.get("src") or r.get("id.orig_h", ""), "dst": r.get("dst") or r.get("id.resp_h", ""), "ts": r.get("ts")})
    weird = Counter(r.get("name", "") for r in read_log(zdir / "weird.log"))

    # ---- сборка
    hits_list = hits.export()
    for h in hits_list:
        h["names"] = sorted({name_of(x) for x in h["observed"] if name_of(x)})[:5]
    alerts_list = sorted(alerts.values(), key=lambda a: (a["severity"], -a["count"]))
    alert_pairs = {a["sid"]: list(a["pairs"].items()) for a in alerts_list}  # все направления для скоринга хостов
    for a in alerts_list:
        a["pairs"] = [p for p, _ in a["pairs"].most_common(5)]
        a["sev_label"] = SEV_LABEL.get(a["severity"], str(a["severity"]))

    sni_list = []
    for s in sorted(sni_stats.values(), key=lambda x: -x["count"])[:max_rows]:
        sni_list.append({"sni": s["sni"], "count": s["count"], "dst": sorted(s["dst"]), "versions": dict(s["versions"]),
                         "validation": dict(s["validation"]), "ja3": sorted(s["ja3"]), "ja4": sorted(s["ja4"])})

    suspicious_dns_list = sorted(
        ({"name": s["name"], "reason": s["reason"], "count": s["count"], "clients": sorted(s["clients"])[:5]} for s in suspicious_dns.values()),
        key=lambda x: -x["count"])[:max_rows]

    # ---- приоритетные хосты: с кого начинать расследование
    weights, thr, scale = _verdict_config(cfg)
    host_risk: dict[str, dict] = {}

    def risk_add(ip: str, points: float, reason: str, indicator: str = "", external: str = "") -> dict | None:
        if not ip or not is_local(ip) or _is_mcast(ip) or not points:
            return None
        e = host_risk.setdefault(ip, {"score": 0.0, "reasons": [], "indicators": set(), "external": set(),
                                      "ioc": 0, "alerts": 0, "files": 0, "beacons": 0, "uploads": 0,
                                      "cleartext": 0, "tls": 0, "dns": 0})
        e["score"] += float(points)
        if reason and reason not in e["reasons"]:
            e["reasons"].append(reason)
        if indicator:
            e["indicators"].add(indicator)
        if external and not is_local(external) and not _is_mcast(external):
            e["external"].add(external)
        return e

    for h in hits_list:
        conf = float(h.get("max_conf") or 0)
        pts = float(weights["ioc_hit"]) * (conf / 100.0 if scale else 1.0)
        ext_hit = next((o for o in h.get("observed", []) if not is_local(o)), "")
        for ip in h.get("hosts", []):
            e = risk_add(ip, pts, {"k": "hr_ioc", "v": h.get("value"), "t": h.get("type")}, h.get("value", ""), ext_hit)
            if e:
                e["ioc"] += 1
    for a in alerts_list:
        sev_pts = float(weights.get(f"alert_sev_{a.get('severity')}", 0))
        if not sev_pts:
            continue
        name = a.get("signature") or f"sid {a.get('sid')}"
        for pair, n in alert_pairs.get(a["sid"], []):
            left, _, right = pair.partition(" → ")
            src, dst = left.rsplit(":", 1)[0], right.rsplit(":", 1)[0]
            for ip, other in ((src, dst), (dst, src)):
                e = risk_add(ip, sev_pts, f"Suricata sev{a.get('severity')} {name}", "", other)
                if e:
                    e["alerts"] += n
    for fl in files:
        if not fl.get("ioc"):
            continue
        ext_host = fl["receiver"] if is_local(fl["sender"]) else fl["sender"]
        for ip in (fl["sender"], fl["receiver"]):
            e = risk_add(ip, float(weights["file_ioc"]), {"k": "hr_file", "name": fl.get("filename") or fl.get("sha256") or fl.get("fuid")},
                         fl.get("sha256") or fl.get("filename", ""), ext_host)
            if e:
                e["files"] += 1
    for b in beacons:
        e = risk_add(b["src"], float(weights["beacon"]), {"k": "hr_beacon", "dst": b["dst"], "dp": b["dp"]}, "", b["dst"])
        if e:
            e["beacons"] += 1
    for u in large_uploads:
        e = risk_add(u["src"], float(weights["large_upload"]), {"k": "hr_upload", "dst": u["dst"]}, "", u["dst"])
        if e:
            e["uploads"] += 1
    for c in cleartext_auth[:100]:
        e = risk_add(c.get("src", ""), float(weights["cleartext_auth"]),
                     {"k": "hr_cleartext", "proto": c.get("proto"), "user": c.get("user") or "?"}, "", c.get("dst", ""))
        if e:
            e["cleartext"] += 1
    for t in invalid_certs:
        e = risk_add(t.get("src", ""), float(weights["tls_invalid"]),
                     {"k": "hr_tls", "target": t.get("sni") or t.get("dst")}, t.get("sni", ""), t.get("dst", ""))
        if e:
            e["tls"] += 1
    for d in suspicious_dns_list:
        for ip in d.get("clients", []):
            e = risk_add(ip, float(weights["dns_suspicious"]), {"k": "hr_dns", "name": d["name"]}, d["name"], "")
            if e:
                e["dns"] += 1

    priority_hosts = []
    for ip, e in host_risk.items():
        level = "high" if e["score"] >= thr["critical"] else "medium" if e["score"] >= thr["suspicious"] else "low"
        priority_hosts.append({
            "ip": ip, "name": name_of(ip), "mac": host_info.get(ip, {}).get("mac", ""),
            "score": round(e["score"], 1), "level": level,
            "reasons": e["reasons"][:6], "indicators": sorted(e["indicators"])[:5], "external": sorted(e["external"])[:5],
            "counts": {k: e[k] for k in ("ioc", "alerts", "files", "beacons", "uploads", "cleartext", "tls", "dns") if e[k]},
        })
    priority_hosts.sort(key=lambda x: -x["score"])

    # ---- граф сетевых обращений: строим по крупнейшим соединениям, чтобы не перегружать отчёт
    graph_links = []
    graph_nodes: dict[str, dict] = {}
    for tot, _seq, c in sorted(top_conn, key=lambda x: -x[0])[:150]:
        src, dst = c["src"], c["dst"]
        if not src or not dst:
            continue
        for ip in (src, dst):
            g = graph_nodes.setdefault(ip, {"id": ip, "name": name_of(ip), "local": is_local(ip), "ioc": ip in ioc_ips, "bytes": 0})
            g["bytes"] += tot
        graph_links.append({"source": src, "target": dst, "bytes": tot, "proto": c["proto"], "port": c["dp"], "ioc": bool(c["ioc"])})
    graph = {"nodes": list(graph_nodes.values()), "links": graph_links}

    totals = {
        "conns": conns_total, "bytes": bytes_total, "pkts": pkts_total,
        "hosts_local": len(local_hosts), "hosts_external": len(ext),
        "dns": dns_total, "http": http_total, "tls": tls_total, "files": files_total,
        "alerts": sum(a["count"] for a in alerts_list), "alert_sigs": len(alerts_list),
        "ioc_hits": len(hits_list), "notices": sum(notices.values()),
    }
    report = {
        "meta": {**(meta or {}), "generated": time.time(), "ioc_count": index.count,
                 "suricata": suricata_meta(cfg, sdir), "suricata_ran": suri_ok,
                 "period": {"start": t_min or 0, "end": t_max or 0, "duration": (t_max - t_min) if t_min else 0}},
        "totals": totals,
        "ioc_hits": hits_list,
        "alerts": alerts_list,
        "files": files_shown,
        "timeline": timeline,
        "top_talkers": top_talkers,
        "top_external": top_external,
        "local_hosts": local_hosts,
        "priority_hosts": priority_hosts,
        "services": sorted(({"service": k, "conns": v[0], "bytes": v[1]} for k, v in services.items()), key=lambda x: -x["conns"])[:40],
        "ports": sorted(({"proto": k[0], "port": k[1], "conns": v[0], "bytes": v[1]} for k, v in ports.items()), key=lambda x: -x["conns"])[:60],
        "connections": [row for _, _, row in sorted(top_conn, key=lambda x: -x[0])],
        "graph": graph,
        "dns": {
            "top": [{"name": q, "count": n, "clients": len(dns_clients[q]), "rcode": dict(dns_rcode[q])} for q, n in dns_q.most_common(max_rows)],
            "nxdomain": [{"name": q, "count": n, "clients": sorted(nx_clients[q])[:5]} for q, n in nx.most_common(200)],
            "suspicious": suspicious_dns_list,
            "resolvers": [{"ip": ip, "count": n, "local": is_local(ip), "name": name_of(ip)} for ip, n in resolvers.most_common(20)],
            "qtypes": dict(qtypes.most_common(15)),
        },
        "http": {"requests": http_rows, "hosts": [{"host": h, "count": n} for h, n in http_hosts.most_common(50)],
                 "user_agents": [{"ua": u, "count": n} for u, n in uas.most_common(40)]},
        "tls": {"sni": sni_list, "invalid": invalid_certs, "versions": dict(tls_versions)},
        "notices": [{"note": k[0], "msg": k[1], "count": n, **notice_ex[k]} for k, n in notices.most_common(100)],
        "weird": [{"name": k, "count": n} for k, n in weird.most_common(40)],
        "findings": {"beacons": beacons[:200], "large_uploads": large_uploads, "long_conns": sorted(long_conns, key=lambda x: -x["dur"]),
                     "unusual_ports": unusual_ports, "cleartext": cleartext_list, "cleartext_auth": cleartext_auth[:100]},
    }
    report["verdict"] = verdict(report, cfg=cfg)
    return report


def _is_mcast(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_multicast or str(a) == "255.255.255.255" or a.is_unspecified
    except ValueError:
        return True


def _verdict_config(cfg=None) -> tuple[dict, dict, bool]:
    """Веса, пороги и режим confidence для скорингового вердикта."""
    vcfg = (cfg.get("verdict") or {}) if isinstance(cfg, dict) else {}
    weights = {"ioc_hit": 40, "alert_sev_1": 40, "alert_sev_2": 15,
               "file_ioc": 25, "beacon": 15, "large_upload": 10,
               "cleartext_auth": 20, "tls_invalid": 10, "dns_suspicious": 5}
    weights.update(vcfg.get("weights") or {})
    thr = {"suspicious": 30, "critical": 80}
    thr.update(vcfg.get("thresholds") or {})
    scale = bool(vcfg.get("confidence_scale", True))
    return weights, thr, scale


def _verdict_scored(rep: dict, cfg=None) -> dict:
    """Скоринговый вердикт: сумма взвешенных находок + объяснение."""
    weights, thr, scale = _verdict_config(cfg)

    score = 0.0
    reasons: list[dict] = []

    def add(pts: float, key: str, **params):
        nonlocal score
        if pts:
            score += pts
            reasons.append({"pts": round(pts), "k": key, **params})

    for h in rep.get("ioc_hits") or []:
        conf = float(h.get("max_conf") or 0)
        pts = float(weights["ioc_hit"]) * (conf / 100.0 if scale else 1.0)
        add(pts, "vr_ioc", v=h.get("value"), t=h.get("type"), conf=f"{conf:.0f}")
    for a in rep.get("alerts") or []:
        name = a.get("signature") or a.get("name") or f"sid {a.get('sid')}"
        add(float(weights.get(f"alert_sev_{a.get('severity')}", 0)), "vr_alert", sev=a.get("severity"), name=name)
    for f_ in rep.get("files") or []:
        if f_.get("ioc"):
            name = f_.get("filename") or f_.get("name") or f_.get("sha256") or f_.get("fuid") or ""
            add(float(weights["file_ioc"]), "vr_file", name=name)
    findings = rep.get("findings") or {}
    for b in findings.get("beacons") or []:
        target = f"{b.get('dst')}:{b.get('dp')}" if b.get("dst") else ""
        add(float(weights["beacon"]), "vr_beacon", src=b.get("src") or "", target=target)
    for u in findings.get("large_uploads") or []:
        target = f"{u.get('src') or ''} → {u.get('dst') or ''}".strip()
        add(float(weights["large_upload"]), "vr_upload", target=target)
    for c in findings.get("cleartext_auth") or []:
        target = f"{c.get('src') or ''} → {c.get('dst') or ''}".strip(" →")
        user = f" ({c.get('user')})" if c.get("user") else ""
        add(float(weights["cleartext_auth"]), "vr_cleartext", user=user, target=target)
    for t in (rep.get("tls") or {}).get("invalid") or []:
        target = t.get("sni") or t.get("dst") or ""
        add(float(weights["tls_invalid"]), "vr_tls", target=target)
    for d in (rep.get("dns") or {}).get("suspicious") or []:
        add(float(weights["dns_suspicious"]), "vr_dns", name=d.get("name") or d.get("q") or "")

    level = "critical" if score >= thr["critical"] else "suspicious" if score >= thr["suspicious"] else "clean"
    labels = {"critical": "Обнаружены признаки компрометации",
              "suspicious": "Есть подозрительная активность",
              "clean": "Явных признаков компрометации не найдено"}
    return {"level": level, "label": labels[level], "score": round(score, 1),
            "reasons": reasons[:30], "weights": weights, "thresholds": thr}


def verdict(*args, **kwargs):
    """Диспетчер: report-dict на входе -> скоринг; иначе прокси в legacy."""
    rep = kwargs.get("rep")
    cfg = kwargs.pop("cfg", None)
    for a in args:
        if isinstance(a, dict):
            if rep is None and "ioc_hits" in a and "alerts" in a:
                rep = a
            elif cfg is None and "auth" in a and "suricata" in a:
                cfg = a
    if rep is not None:
        return _verdict_scored(rep, cfg)
    return _verdict_legacy(*args, **kwargs)


def _verdict_legacy(rep: dict) -> dict:
    reasons_c, reasons_s = [], []
    n_ioc = len(rep["ioc_hits"])
    if n_ioc:
        reasons_c.append(f"обращения к индикаторам компрометации: {n_ioc}")
    high = [a for a in rep["alerts"] if a["severity"] == 1]
    mid = [a for a in rep["alerts"] if a["severity"] == 2]
    if high:
        reasons_c.append(f"сигнатуры Suricata высокой важности: {len(high)}")
    if mid:
        reasons_s.append(f"сигнатуры Suricata средней важности: {len(mid)}")
    f = rep["findings"]
    if f["beacons"]:
        reasons_s.append(f"периодические соединения (маячки): {len(f['beacons'])}")
    if f["large_uploads"]:
        reasons_s.append(f"крупные выгрузки наружу: {len(f['large_uploads'])}")
    if rep["dns"]["suspicious"]:
        reasons_s.append(f"подозрительные DNS-имена: {len(rep['dns']['suspicious'])}")
    if rep["tls"]["invalid"]:
        reasons_s.append(f"TLS с невалидным сертификатом: {len(rep['tls']['invalid'])}")
    if f["cleartext_auth"]:
        reasons_s.append(f"учётные данные в открытом виде: {len(f['cleartext_auth'])}")
    if any(fl["ioc"] for fl in rep["files"]):
        reasons_c.append("переданы файлы из базы вредоносных")
    if reasons_c:
        return {"level": "critical", "label": "Обнаружены признаки компрометации", "reasons": reasons_c + reasons_s}
    if reasons_s:
        return {"level": "suspicious", "label": "Есть подозрительная активность", "reasons": reasons_s}
    return {"level": "clean", "label": "Явных признаков компрометации не найдено", "reasons": []}


def summary(rep: dict) -> dict:
    """Короткая сводка для списка задач."""
    t = rep["totals"]
    return {"verdict": rep["verdict"]["level"], "verdict_label": rep["verdict"]["label"], "conns": t["conns"],
            "bytes": t["bytes"], "ioc_hits": t["ioc_hits"], "alerts": t["alerts"], "files": t["files"],
            "start": rep["meta"]["period"]["start"], "end": rep["meta"]["period"]["end"]}

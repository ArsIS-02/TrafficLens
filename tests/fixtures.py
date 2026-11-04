"""Эталонные логи Zeek (JSON) и Suricata (eve.json) для проверки разбора без запуска движков.

Сценарий: рабочая станция 192.168.1.50 в домашней сети.
  * DNS-резолв evil-c2.example -> 203.0.113.66 (IOC) и маячок на 203.0.113.66:8443 каждые 60 с;
  * HTTP-загрузка http://198.51.100.23/payload.exe — файл EICAR (SHA256 в IOC);
  * DGA-подобный NXDOMAIN, выгрузка 40 МБ наружу, SSL на 4444, вход по FTP;
  * Suricata: сигнатура высокой важности и TLS с JA3.
"""
from __future__ import annotations

import json
from pathlib import Path

T0 = 1793768400.0  # 2026-11-04 10:00:00 +05
WS = "192.168.1.50"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
JA3 = "e7d705a3286e19ea42f587b344ee6865"

CUSTOM_IOCS = f"""# тестовый список
203.0.113.66 # C2 тестовый
evil-c2.example # домен C2
http://198.51.100.23/payload.exe # раздача вредоноса
{EICAR_SHA256} # EICAR
ja3:{JA3} # тестовый JA3
это не индикатор
"""


def _w(p: Path, rows: list[dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def conn(ts, src, sp, dst, dp, proto="tcp", svc=None, dur=0.5, ob=500, rb=1500, state="SF", uid="C"):
    r = {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst, "id.resp_p": dp, "proto": proto,
         "duration": dur, "orig_bytes": ob, "resp_bytes": rb, "conn_state": state, "local_orig": True, "local_resp": False,
         "missed_bytes": 0, "history": "ShADadFf", "orig_pkts": 6, "orig_ip_bytes": ob + 300, "resp_pkts": 6,
         "resp_ip_bytes": rb + 300, "orig_l2_addr": "aa:bb:cc:00:11:22"}
    if svc:
        r["service"] = svc
    return r


def make_job(job_dir: Path) -> Path:
    z = job_dir / "zeek"
    s = job_dir / "suricata"
    conns, dns = [], []
    # фон: 40 обращений к example.com по TLS и DNS к роутеру
    for i in range(40):
        ts = T0 + i * 37
        conns.append(conn(ts, WS, 50000 + i, "93.184.216.34", 443, svc="ssl", ob=900, rb=40000, uid=f"Cbg{i}"))
        conns.append(conn(ts - 0.1, WS, 40000 + i, "192.168.1.1", 53, proto="udp", svc="dns", ob=60, rb=120, uid=f"Cdn{i}"))
        dns.append({"ts": ts - 0.1, "uid": f"Cdn{i}", "id.orig_h": WS, "id.orig_p": 40000 + i, "id.resp_h": "192.168.1.1",
                    "id.resp_p": 53, "proto": "udp", "query": "example.com", "qtype_name": "A", "rcode_name": "NOERROR",
                    "answers": ["93.184.216.34"], "TTLs": [300.0], "rejected": False})
    # маячок на C2 каждые 60 с
    for i in range(15):
        ts = T0 + 30 + i * 60 + (0.3 if i % 2 else -0.2)
        conns.append(conn(ts, WS, 51000 + i, "203.0.113.66", 8443, svc="ssl", ob=700, rb=900, uid=f"Cc2{i}"))
    dns.append({"ts": T0 + 29, "uid": "Cevil", "id.orig_h": WS, "id.orig_p": 41000, "id.resp_h": "192.168.1.1", "id.resp_p": 53,
                "proto": "udp", "query": "api.evil-c2.example", "qtype_name": "A", "rcode_name": "NOERROR",
                "answers": ["203.0.113.66"], "TTLs": [60.0], "rejected": False})
    dns.append({"ts": T0 + 100, "uid": "Cdga", "id.orig_h": WS, "id.orig_p": 41001, "id.resp_h": "8.8.8.8", "id.resp_p": 53,
                "proto": "udp", "query": "xk3j9qz7vbn2lm4pw8.biz", "qtype_name": "A", "rcode_name": "NXDOMAIN", "rejected": False})
    # HTTP-загрузка вредоноса
    conns.append(conn(T0 + 200, WS, 52000, "198.51.100.23", 80, svc="http", ob=400, rb=70000, uid="Chttp1"))
    http = [
        {"ts": T0 + 200, "uid": "Chttp1", "id.orig_h": WS, "id.orig_p": 52000, "id.resp_h": "198.51.100.23", "id.resp_p": 80,
         "trans_depth": 1, "method": "GET", "host": "198.51.100.23", "uri": "/payload.exe", "version": "1.1",
         "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "request_body_len": 0, "response_body_len": 68,
         "status_code": 200, "status_msg": "OK", "resp_fuids": ["FEICAR1"], "resp_mime_types": ["application/x-dosexec"]},
        {"ts": T0 + 210, "uid": "Chttp2", "id.orig_h": WS, "id.orig_p": 52001, "id.resp_h": "93.184.216.34", "id.resp_p": 80,
         "trans_depth": 1, "method": "GET", "host": "example.com", "uri": "/logo.png", "version": "1.1",
         "user_agent": "curl/8.5.0", "request_body_len": 0, "response_body_len": 2048, "status_code": 200,
         "resp_fuids": ["FPNG1"], "resp_mime_types": ["image/png"]},
    ]
    conns.append(conn(T0 + 210, WS, 52001, "93.184.216.34", 80, svc="http", ob=300, rb=2500, uid="Chttp2"))
    files = [
        {"ts": T0 + 200.1, "fuid": "FEICAR1", "uid": "Chttp1", "id.orig_h": WS, "id.orig_p": 52000, "id.resp_h": "198.51.100.23",
         "id.resp_p": 80, "source": "HTTP", "depth": 0, "analyzers": ["MD5", "SHA1", "SHA256", "EXTRACT"],
         "mime_type": "application/x-dosexec", "duration": 0.0, "is_orig": False, "seen_bytes": 68, "total_bytes": 68,
         "missing_bytes": 0, "overflow_bytes": 0, "timedout": False, "md5": EICAR_MD5,
         "sha1": "3395856ce81f2b7382dee72602f798b642f14140", "sha256": EICAR_SHA256, "extracted": "HTTP-FEICAR1",
         "extracted_cutoff": False},
        {"ts": T0 + 210.1, "fuid": "FPNG1", "uid": "Chttp2", "id.orig_h": WS, "id.orig_p": 52001, "id.resp_h": "93.184.216.34",
         "id.resp_p": 80, "source": "HTTP", "depth": 0, "analyzers": ["MD5", "SHA1", "SHA256"], "mime_type": "image/png",
         "is_orig": False, "seen_bytes": 2048, "total_bytes": 2048, "missing_bytes": 0, "md5": "0" * 32,
         "sha1": "1" * 40, "sha256": "2" * 64},
        # Zeek < 5: старый формат с tx_hosts/rx_hosts и выгрузкой по SMB
        {"ts": T0 + 400, "fuid": "FSMB1", "tx_hosts": [WS], "rx_hosts": ["192.168.1.20"], "conn_uids": ["Csmb"],
         "source": "SMB", "mime_type": "application/pdf", "seen_bytes": 120000, "total_bytes": 120000, "missing_bytes": 0,
         "md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64},
    ]
    smb_files = [{"ts": T0 + 400, "uid": "Csmb", "fuid": "FSMB1", "action": "SMB::FILE_WRITE", "name": "Отчёт Q3.pdf", "size": 120000}]
    (z / "extract_files").mkdir(parents=True, exist_ok=True)
    (z / "extract_files" / "HTTP-FEICAR1").write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    # выгрузка 40 МБ, SSL на 4444, FTP
    conns.append(conn(T0 + 500, WS, 53000, "198.51.100.200", 443, svc="ssl", dur=120, ob=40 * 1024 * 1024, rb=20000, uid="Cup"))
    conns.append(conn(T0 + 600, WS, 53001, "198.51.100.77", 4444, svc="ssl", dur=4000, ob=5000, rb=5000, uid="Codd"))
    conns.append(conn(T0 + 700, WS, 53002, "198.51.100.90", 21, svc="ftp", ob=300, rb=600, uid="Cftp"))
    ftp = [{"ts": T0 + 701, "uid": "Cftp", "id.orig_h": WS, "id.orig_p": 53002, "id.resp_h": "198.51.100.90", "id.resp_p": 21,
            "user": "backup", "password": "<hidden>", "command": "RETR", "arg": "ftp://198.51.100.90/db.sql"}]
    ssl = [
        {"ts": T0 + 1, "uid": "Cbg0", "id.orig_h": WS, "id.orig_p": 50000, "id.resp_h": "93.184.216.34", "id.resp_p": 443,
         "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "example.com", "established": True,
         "validation_status": "ok"},
        {"ts": T0 + 30, "uid": "Cc20", "id.orig_h": WS, "id.orig_p": 51000, "id.resp_h": "203.0.113.66", "id.resp_p": 8443,
         "version": "TLSv12", "server_name": "api.evil-c2.example", "established": True, "validation_status": "self signed certificate"},
    ]
    notice = [{"ts": T0 + 30, "uid": "Cc20", "id.orig_h": WS, "id.resp_h": "203.0.113.66", "note": "SSL::Invalid_Server_Cert",
               "msg": "SSL certificate validation failed with (self signed certificate)", "src": WS, "dst": "203.0.113.66"}]
    weird = [{"ts": T0 + 5, "name": "truncated_tcp_payload"}, {"ts": T0 + 6, "name": "truncated_tcp_payload"}]
    dhcp = [{"ts": T0, "uids": ["Cdh"], "client_addr": WS, "server_addr": "192.168.1.1", "mac": "aa:bb:cc:00:11:22",
             "host_name": "WS-01", "assigned_addr": WS, "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"]}]
    for name, rows in (("conn", conns), ("dns", dns), ("http", http), ("files", files), ("smb_files", smb_files),
                       ("ftp", ftp), ("ssl", ssl), ("notice", notice), ("weird", weird), ("dhcp", dhcp)):
        _w(z / f"{name}.log", rows)
    eve = [
        {"timestamp": "2026-11-04T10:03:20.123456+0500", "event_type": "alert", "src_ip": "198.51.100.23", "src_port": 80,
         "dest_ip": WS, "dest_port": 52000, "proto": "TCP",
         "alert": {"action": "allowed", "gid": 1, "signature_id": 2014819, "rev": 3,
                   "signature": "ET INFO Packed Executable Download", "category": "Misc activity", "severity": 1}},
        {"timestamp": "2026-11-04T10:03:20.200000+0500", "event_type": "alert", "src_ip": "198.51.100.23", "src_port": 80,
         "dest_ip": WS, "dest_port": 52000, "proto": "TCP",
         "alert": {"signature_id": 2014819, "signature": "ET INFO Packed Executable Download", "category": "Misc activity", "severity": 1}},
        {"timestamp": "2026-11-04T10:00:30.000000+0500", "event_type": "tls", "src_ip": WS, "src_port": 51000,
         "dest_ip": "203.0.113.66", "dest_port": 8443, "proto": "TCP",
         "tls": {"sni": "api.evil-c2.example", "version": "TLS 1.2", "ja3": {"hash": JA3, "string": "771,..."},
                 "ja4": "t12d1909h2_d83cc789557e_7af1ed941c26"}},
        {"timestamp": "2026-11-04T10:00:00.000000+0500", "event_type": "stats", "stats": {}},
    ]
    _w(s / "eve.json", eve)
    return job_dir

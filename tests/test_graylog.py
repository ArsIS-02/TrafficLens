"""Интеграция с Graylog (GELF, выгрузка IOC) и имена хостов (hosts.yaml, PTR)."""
import csv
import io
import json
import socket
import sys
import time
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, gelf, ioc_store, names, pipeline, report, retro, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402

H = {"X-Requested-With": "TrafficLens"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    cfg["retro"]["enabled"] = False
    cfg["names"]["ptr"] = False
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    return cfg, db


@pytest.fixture()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(2)
    yield s
    s.close()


def _recv_all(sock) -> list[dict]:
    """Принять все GELF-сообщения (с распаковкой и сборкой чанков)."""
    out, chunks = [], {}
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return out
        sock.settimeout(0.3)
        if data[:2] == b"\x1e\x0f":
            mid, n, total = data[2:10], data[10], data[11]
            chunks.setdefault(mid, {})[n] = data[12:]
            if len(chunks[mid]) == total:
                data = b"".join(chunks.pop(mid)[i] for i in range(total))
            else:
                continue
        out.append(json.loads(zlib.decompress(data)))


def _job(cfg, db, tmp_path):
    pcap = tmp_path / "w.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "w.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    db.update_job(jid, status="done", finished=time.time())
    return jid


def test_gelf_job_events_and_dedup(env, tmp_path, udp):
    cfg, db = env
    cfg["gelf"].update(enabled=True, host="127.0.0.1", port=udp.getsockname()[1], base_url="https://tl.example")
    jid = _job(cfg, db, tmp_path)
    pipeline.rematch(cfg, db, jid)
    msgs = _recv_all(udp)
    ev = [m["_tl_event"] for m in msgs]
    assert ev.count("verdict") == 1 and ev.count("ioc_hit") == 5
    v = next(m for m in msgs if m["_tl_event"] == "verdict")
    assert v["_tl_level"] == "critical" and v["level"] == 2 and v["_tl_source"] == "trafficlens"
    assert v["_tl_report"] == f"https://tl.example/jobs/{jid}" and "192.168.1.50" in v["_tl_hosts"]
    assert "WS-01" in v["_tl_host_names"]                              # имя из DHCP фикстуры
    ioc = next(m for m in msgs if m.get("_tl_ioc_value") == "203.0.113.66")
    assert ioc["_tl_ioc_type"] == "ip" and ioc["_tl_ioc_source"] == "custom" and ioc["_tl_report"].endswith("#ioc")
    assert db.kv_get("gelf_status")["ok"]

    pipeline.rematch(cfg, db, jid)                     # повторная пересборка — ничего нового
    assert _recv_all(udp) == []

    (cfg.custom_ioc_dir / "later.txt").write_text("198.51.100.200 # exfil\n")
    time.sleep(0.01)
    feeds.update_all(cfg, db, only="custom")
    retro.run(cfg, db)
    msgs = _recv_all(udp)
    assert [m["_tl_event"] for m in msgs] == ["retro_hit", "ioc_hit"]
    assert msgs[0]["_tl_ioc_value"] == "198.51.100.200" and msgs[0]["_tl_seen_ts"]


def test_gelf_min_level_and_chunks(env, tmp_path, udp):
    cfg, db = env
    cfg["gelf"].update(enabled=True, host="127.0.0.1", port=udp.getsockname()[1], min_level="critical", send_ioc_hits=False)
    with gelf.Sender(cfg) as s:
        s.send("big", {"blob": "x" * 20000 + bytes(range(256)).hex() * 200})
    big = _recv_all(udp)
    assert len(big) == 1 and len(big[0]["_blob"]) > 20000
    rep = {"verdict": {"level": "suspicious", "score": 40}, "ioc_hits": [], "meta": {}}
    assert gelf.notify_job(cfg, db, {"id": "j1", "filename": "f"}, rep) == 0
    rep["verdict"]["level"] = "critical"
    assert gelf.notify_job(cfg, db, {"id": "j1", "filename": "f"}, rep) == 1


def test_gelf_errors_do_not_break(env, tmp_path, monkeypatch):
    cfg, db = env
    cfg["gelf"].update(enabled=True, host="no-such-host.invalid", port=12201)
    jid = _job(cfg, db, tmp_path)
    pipeline.rematch(cfg, db, jid)                     # не падает
    assert db.kv_get("gelf_status")["ok"] is False
    cfg["gelf"]["enabled"] = False
    assert gelf.test_message(cfg, db) == (False, "gelf_err_disabled")


def test_export_csv(env):
    cfg, db = env
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()
    assert c.get("/export/iocs.csv").status_code == 404           # токен не задан — выгрузка выключена
    cfg["export"]["token"] = "s3cr3t"
    c = create_app(cfg, start_workers=False).test_client()
    assert c.get("/export/iocs.csv?token=bad").status_code == 403
    r = c.get("/export/iocs.csv?token=s3cr3t")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(r.text)))
    vals = {x["value"]: x for x in rows}
    assert {"203.0.113.66", "evil-c2.example", fx.EICAR_SHA256} <= set(vals)
    assert vals["203.0.113.66"]["info"] == "C2 тестовый" and vals["203.0.113.66"]["source"] == "custom"
    r = c.get("/export/iocs.csv?types=domain", headers={"X-TrafficLens-Token": "s3cr3t"})
    assert [x["type"] for x in csv.DictReader(io.StringIO(r.text))] == ["domain"]
    assert not r.data.startswith(b"\xef\xbb\xbf")
    assert c.get("/export/iocs.csv?token=s3cr3t&min_conf=101").text.strip() == "value,type,source,info,confidence"
    raw = c.get("/export/iocs.csv?token=s3cr3t&header=0&types=ip").text.splitlines()
    assert raw and not raw[0].startswith("value,") and all(len(next(csv.reader([ln]))) == 5 for ln in raw)
    assert all(next(csv.reader([ln]))[3] for ln in raw)               # значение для Graylog не пустое


def test_names_hosts_file_and_ptr(env, tmp_path, monkeypatch):
    cfg, db = env
    (cfg.config_path.parent / "hosts.yaml").write_text("192.168.1.50: WS-Manual\n192.168.1.20: nas\n", encoding="utf-8")
    assert names.load_hosts(cfg) == {"192.168.1.50": "WS-Manual", "192.168.1.20": "nas"}
    jd = fx.make_job(tmp_path / "j")
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    lh = {h["ip"]: h for h in rep["local_hosts"]}
    assert lh[fx.WS]["name"] == "WS-Manual"                       # hosts.yaml важнее DHCP

    (cfg.config_path.parent / "hosts.yaml").unlink()
    cfg["names"]["ptr"] = True
    names.clear_cache()
    calls = []
    monkeypatch.setattr(names, "_ptr", lambda ip: calls.append(ip) or ("gw.corp.example" if ip == "192.168.1.1" else ""))
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    lh = {h["ip"]: h for h in rep["local_hosts"]}
    assert lh["192.168.1.1"]["name"] == "gw.corp.example"
    assert lh[fx.WS]["name"] == "WS-01"                            # DHCP-имя — PTR не спрашивали
    assert fx.WS not in calls
    n = len(calls)
    report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert len(calls) == n                                         # кеш, повторно не спрашиваем
    cfg["names"]["strip_domain"] = True
    names.clear_cache()
    assert names.resolve_ptr(cfg, ["192.168.1.1"]) == {"192.168.1.1": "gw"}


def test_iocs_page_graylog_panel(env):
    cfg, db = env
    from trafficlens.web import create_app
    cfg["gelf"].update(enabled=True, host="127.0.0.1", port=9)
    c = create_app(cfg, start_workers=False).test_client()
    r = c.get("/iocs")
    assert "graylog-panel" in r.text and "udp://127.0.0.1:9" in r.text
    assert c.post("/api/gelf/test", headers=H).json["ok"]

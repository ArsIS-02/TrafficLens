"""Ретропроверка новых IOC по прошлым задачам и открытые списки угроз."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, listfeeds, pipeline, retro, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402

H = {"X-Requested-With": "TrafficLens"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    cfg["retro"]["enabled"] = False          # в тестах ретропроверку запускаем явно
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    return cfg, db


def _done_job(cfg, db, tmp_path, name="w.pcap"):
    pcap = tmp_path / name
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, name, "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done", finished=time.time())
    return jid


def _add_custom(cfg, db, text):
    (cfg.custom_ioc_dir / "later.txt").write_text(text, encoding="utf-8")
    time.sleep(0.01)
    feeds.update_all(cfg, db, only="custom")


def test_observables(env, tmp_path):
    cfg, db = env
    jd = fx.make_job(tmp_path / "j")
    o = retro.extract(jd)["obs"]
    assert "203.0.113.66" in o["ip"] and "198.51.100.200" in o["ip"]
    assert "api.evil-c2.example" in o["domain"] and "example.com" in o["domain"]
    assert "198.51.100.23/payload.exe" in o["url"]
    assert fx.EICAR_SHA256 in o["sha256"] and fx.JA3 in o["ja3"]
    assert o["ip"]["203.0.113.66"] > 0
    d = retro.ensure(jd)
    assert (jd / retro.OBS_FILE).exists() and retro.ensure(jd)["built"] == d["built"]   # кеш


def test_retro_finds_only_new(env, tmp_path):
    cfg, db = env
    jid = _done_job(cfg, db, tmp_path)
    st = retro.run(cfg, db)                       # первый проход: все IOC «новые», но уже есть в отчёте
    assert st["new_iocs"] == 5 and st["hits"] == 0

    _add_custom(cfg, db, "198.51.100.200 # exfil host from incident\nexample.com\n45.33.32.156\n")
    st = retro.run(cfg, db)
    assert st["new_iocs"] == 3 and st["jobs"] == 1 and st["jobs_hit"] == 1 and st["hits"] == 2
    hits = {(h["ioc_type"], h["ioc_value"]): h for h in db.retro_hits(job_id=jid)}
    assert set(hits) == {("ip", "198.51.100.200"), ("domain", "example.com")}
    assert hits[("ip", "198.51.100.200")]["info"] == "exfil host from incident" and hits[("ip", "198.51.100.200")]["seen_ts"]
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text())
    assert any(h["value"] == "198.51.100.200" for h in rep["ioc_hits"])   # отчёт пересобран
    assert db.retro_unacked_jobs() == {jid: 2}

    assert retro.run(cfg, db)["new_iocs"] == 0                             # повтор — нечего проверять
    assert retro.run(cfg, db, full=True)["hits"] == 0                      # полный — без дублей
    db.retro_ack()
    assert db.retro_unacked_jobs() == {}


def test_retro_horizon_and_cidr(env, tmp_path):
    cfg, db = env
    old = _done_job(cfg, db, tmp_path, "old.pcap")
    db.update_job(old, finished=time.time() - 90 * 86400)
    new = _done_job(cfg, db, tmp_path, "new.pcap")
    retro.run(cfg, db)
    _add_custom(cfg, db, "198.51.100.0/24\n")
    st = retro.run(cfg, db)
    assert st["jobs"] == 1 and {h["job_id"] for h in db.retro_hits()} == {new}
    assert all(h["ioc_type"] == "cidr" for h in db.retro_hits())


def test_list_feeds_state_and_update(env, monkeypatch):
    cfg, db = env
    fl = {f["id"]: f for f in listfeeds.all_feeds(cfg)}
    assert fl["c2intel-ip"]["enabled"] and not fl["blocklist-de"]["enabled"]
    listfeeds.set_enabled(cfg, "c2intel-ip", False)
    assert not {f["id"]: f for f in listfeeds.all_feeds(cfg)}["c2intel-ip"]["enabled"]
    cfg["iocs"]["lists"] = {"blocklist-de": {"enabled": True}}
    bl = {f["id"]: f for f in listfeeds.all_feeds(cfg)}["blocklist-de"]
    assert bl["enabled"] and bl["locked"]
    item = listfeeds.add_custom(cfg, "Мой список", "https://lists.example/bad.txt", "domain", 90)
    assert item["id"].startswith("my-") and listfeeds.all_feeds(cfg)[-1]["custom"]

    class R:
        def __init__(self, text):
            self.text = text

        def raise_for_status(self):
            pass

    monkeypatch.setattr(listfeeds.requests, "get", lambda url, **kw: R("bad.example\nhttp://x.example/a\n10.1.2.3\n"))
    res = feeds.update_all(cfg, db, only=listfeeds.source_name(item["id"]))
    assert list(res) == [listfeeds.source_name(item["id"])] and res[listfeeds.source_name(item["id"])].startswith("ok")
    from trafficlens import ioc_store
    assert ioc_store.stats(db)["by_source"][listfeeds.source_name(item["id"])] == {"domain": 1}
    assert listfeeds.delete_custom(cfg, item["id"])


def test_list_parse_csv_and_guards():
    f = {"id": "c", "name": "C2", "type": "ip", "conf": 80, "kind": "c2"}
    got = listfeeds.parse("#ip,ioc\n45.33.32.156,Possible Cobaltstrike C2 IP\n10.0.0.1,lan\n0.0.0.0/0\n1.0.0.0/4\n"
                          "91.92.240.0/24\n45.33.32.156,dup\nevil.example\n185.220.101.4:443\n", f)
    assert [(i.type, i.value, i.port) for i in got] == [("ip", "45.33.32.156", None), ("cidr", "91.92.240.0/24", None),
                                                       ("ip", "185.220.101.4", 443)]
    assert got[0].info == "C2: Possible Cobaltstrike C2 IP" and got[0].confidence == 80
    auto = listfeeds.parse("evil.example\nhttp://bad.example/x\n" + fx.EICAR_MD5 + "\n// c\n", {"id": "a", "name": "A"})
    assert [i.type for i in auto] == ["domain", "url", "md5"]


def test_web_retro_and_lists(env, tmp_path, monkeypatch):
    cfg, db = env
    from trafficlens.web import create_app
    jid = _done_job(cfg, db, tmp_path)
    retro.run(cfg, db)
    _add_custom(cfg, db, "198.51.100.200 # exfil\n")
    retro.run(cfg, db)
    c = create_app(cfg, start_workers=False).test_client()
    r = c.get("/")
    assert "198.51.100.200" in r.text and "retro-panel" in r.text and f'href="/jobs/{jid}#ioc"' in r.text
    r = c.get(f"/jobs/{jid}")
    assert "retro-banner" in r.text and "exfil" in r.text
    r = c.get("/iocs")
    assert "lists-panel" in r.text and "C2IntelFeeds" in r.text and "retro-panel" in r.text
    assert c.post("/api/retro/ack", json={"job": jid}, headers=H).json["ok"]
    assert "retro-panel" not in c.get("/").text

    monkeypatch.setattr(listfeeds.requests, "get", lambda url, **kw: (_ for _ in ()).throw(OSError("offline")))
    assert c.post("/api/iocs/lists/toggle", json={"id": "nope", "enabled": True}, headers=H).status_code == 404
    assert c.post("/api/iocs/lists/toggle", json={"id": "openphish", "enabled": False}, headers=H).json["ok"]
    assert not {f["id"]: f for f in listfeeds.all_feeds(cfg)}["openphish"]["enabled"]
    assert c.post("/api/iocs/lists", json={"url": "ftp://x"}, headers=H).status_code == 400
    r = c.post("/api/iocs/lists", json={"url": "https://lists.example/c2.txt", "name": "My C2", "type": "ip"}, headers=H)
    assert r.json["ok"]
    assert c.post("/api/iocs/lists/delete", json={"id": r.json["id"]}, headers=H).json["ok"]
    assert c.post("/api/retro/run", json={"full": True}, headers=H).json["ok"]

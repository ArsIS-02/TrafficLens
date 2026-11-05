import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, ioc_store, pipeline, report  # noqa: E402
from trafficlens.db import DB  # noqa: E402
from trafficlens.ioc_types import detect, norm_url  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    return cfg, db


def test_detect_types():
    assert detect("203.0.113.66") == ("ip", "203.0.113.66", None)
    assert detect("203.0.113.66:8443") == ("ip", "203.0.113.66", 8443)
    assert detect("[2001:db8::1]:443") == ("ip", "2001:db8::1", 443)
    assert detect("198.51.100.0/24")[0] == "cidr"
    assert detect("Evil-C2.Example.")[1] == "evil-c2.example"
    assert detect("HTTP://Bad.Example:80/a?b=1") == ("url", "bad.example/a?b=1", None)
    assert detect(fx.EICAR_MD5)[0] == "md5"
    assert detect(fx.EICAR_SHA256)[0] == "sha256"
    assert detect("ja3hash", "ja3") is None
    assert detect(fx.JA3, "ja3")[0] == "ja3"
    assert detect("not an ioc") is None
    assert norm_url("https://x.example:443/") == "x.example/"


def test_custom_parse_and_store(env):
    cfg, db = env
    items, errors = feeds.parse_custom_text(fx.CUSTOM_IOCS)
    assert len(items) == 5 and len(errors) == 1
    st = ioc_store.stats(db)
    assert st["by_source"]["custom"] == {"ip": 1, "domain": 1, "url": 1, "sha256": 1, "ja3": 1}
    assert db.feeds()["custom"]["ok"] == 1
    # replace-семантика: удалённое из списка уходит из базы
    (cfg.custom_ioc_dir / "investigation.txt").write_text("203.0.113.66\n", encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    assert ioc_store.stats(db)["total"] == 1
    assert ioc_store.lookup(db, "sub.evil-c2.example") == []


def test_lookup_parent_domain(env):
    cfg, db = env
    res = ioc_store.lookup(db, "deep.api.evil-c2.example")
    assert res and res[0]["value"] == "evil-c2.example"


def test_report_build(env, tmp_path):
    cfg, db = env
    jd = fx.make_job(tmp_path / "job")
    idx = ioc_store.IOCIndex(db)
    rep = report.build(jd, idx, cfg, {"filename": "t.pcap"})
    json.dumps(rep, default=list)  # сериализуемость

    hits = {(h["type"], h["value"]): h for h in rep["ioc_hits"]}
    assert ("ip", "203.0.113.66") in hits
    ip_hit = hits[("ip", "203.0.113.66")]
    assert "Соединение (получатель)" in ip_hit["contexts"] and "DNS-ответ" in ip_hit["contexts"]
    assert ip_hit["count"] >= 16
    assert ("domain", "evil-c2.example") in hits
    assert {"DNS-запрос", "TLS SNI"} <= set(hits[("domain", "evil-c2.example")]["contexts"])
    assert ("url", "198.51.100.23/payload.exe") in hits
    assert ("sha256", fx.EICAR_SHA256) in hits
    assert ("ja3", fx.JA3) in hits

    assert rep["verdict"]["level"] == "critical"
    t = rep["totals"]
    assert t["files"] == 3 and t["alerts"] == 2 and t["alert_sigs"] == 1

    f0 = rep["files"][0]  # файлы с IOC — первыми
    assert f0["sha256"] == fx.EICAR_SHA256 and f0["direction"] == "загрузка в сеть"
    assert f0["filename"] == "payload.exe" and f0["extracted"] == "HTTP-FEICAR1"
    smb = next(f for f in rep["files"] if f["fuid"] == "FSMB1")
    assert smb["filename"] == "Отчёт Q3.pdf" and smb["direction"] == "внутри сети"

    b = rep["findings"]["beacons"]
    assert b and b[0]["dst"] == "203.0.113.66" and 55 < b[0]["interval"] < 65 and b[0]["ioc"]
    assert any(u["dst"] == "198.51.100.200" for u in rep["findings"]["large_uploads"])
    assert any(u["port"] == 4444 for u in rep["findings"]["unusual_ports"])
    assert any(c["user"] == "backup" for c in rep["findings"]["cleartext_auth"])
    assert any(c["dur"] >= 3600 for c in rep["findings"]["long_conns"])
    assert any("DGA" in d["reason"] for d in rep["dns"]["suspicious"])
    assert rep["dns"]["nxdomain"][0]["name"] == "xk3j9qz7vbn2lm4pw8.biz"
    assert any(r["ip"] == "8.8.8.8" and not r["local"] for r in rep["dns"]["resolvers"])
    assert rep["tls"]["invalid"][0]["sni"] == "api.evil-c2.example"
    ext = {e["ip"]: e for e in rep["top_external"]}
    assert ext["203.0.113.66"]["name"] == "api.evil-c2.example" and ext["203.0.113.66"]["ioc"]
    lh = {h["ip"]: h for h in rep["local_hosts"]}
    assert lh[fx.WS]["name"] == "WS-01" and lh[fx.WS]["mac"] == "aa:bb:cc:00:11:22"
    assert sum(rep["timeline"]["conns"]) == t["conns"]
    assert rep["notices"][0]["note"] == "SSL::Invalid_Server_Cert"


def test_clean_report(env, tmp_path):
    cfg, db = env
    jd = tmp_path / "clean"
    (jd / "zeek").mkdir(parents=True)
    rows = [fx.conn(fx.T0 + i, fx.WS, 50000 + i, "93.184.216.34", 443, svc="ssl") for i in range(5)]
    (jd / "zeek" / "conn.log").write_text("".join(json.dumps(r) + "\n" for r in rows))
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["verdict"]["level"] == "clean" and rep["totals"]["conns"] == 5
    assert rep["meta"]["suricata"]["status"] == "no_rules"
    assert "Нет правил Suricata" in rep["meta"]["suricata"]["warning"]


def test_empty_logs(env, tmp_path):
    cfg, db = env
    jd = tmp_path / "empty"
    (jd / "zeek").mkdir(parents=True)
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["totals"]["conns"] == 0 and rep["timeline"]["conns"] == []
    from trafficlens.render import render_report
    assert "Явных признаков" in render_report(rep)


def test_suricata_status_report(env, tmp_path, monkeypatch):
    cfg, db = env
    jd = tmp_path / "suri-status"
    (jd / "zeek").mkdir(parents=True)
    (jd / "suricata").mkdir(parents=True)
    (jd / "suricata" / "eve.json").write_text("{}\n", encoding="utf-8")

    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["meta"]["suricata"]["status"] == "no_rules"
    assert rep["meta"]["suricata"]["available"] is False

    baked = tmp_path / "baked.rules"
    baked.write_text('# comment\nalert ip any any -> any any (msg:"t"; sid:1;)\n', encoding="utf-8")
    from trafficlens import runner
    monkeypatch.setattr(runner, "BAKED_RULES", baked)
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["meta"]["suricata"]["status"] == "ok"
    assert rep["meta"]["suricata"]["source"] == "baked"
    assert rep["meta"]["suricata"]["count"] == 1


def test_suricata_ts():
    assert abs(report.suri_ts("2026-11-04T10:00:00.000000+0500") - fx.T0) < 1


def test_stix_parse():
    p = ("[ipv4-addr:value = '203.0.113.5'] OR [domain-name:value = 'bad.example'] OR "
         "[file:hashes.'SHA-256' = '%s'] OR [url:value = 'http://x.example/a']" % fx.EICAR_SHA256)
    got = feeds.parse_stix(p)
    assert ("203.0.113.5", None) in got and ("bad.example", "domain") in got
    assert (fx.EICAR_SHA256, "sha256") in got and ("http://x.example/a", "url") in got


def test_feeds_parsing(monkeypatch):
    """abuse.ch / MISP / OpenCTI — разбор ответов без сети."""
    class R:
        def __init__(self, data=None, text="", ok=True, status=200):
            self._d, self.text, self.ok, self.status_code = data, text, ok, status
        def json(self):
            return self._d
        def raise_for_status(self):
            if not self.ok:
                import requests
                raise requests.HTTPError(response=self)

    calls = []

    def fake_post(url, **kw):
        calls.append((url, kw.get("headers", {}).get("Auth-Key") or kw.get("headers", {}).get("Authorization")))
        if "threatfox" in url:
            return R({"query_status": "ok", "data": [
                {"ioc": "203.0.113.9:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 100, "tags": None},
                {"ioc": "bad.example", "ioc_type": "domain", "malware_printable": "X", "confidence_level": 50, "tags": ["a"]},
                {"ioc": fx.EICAR_SHA256, "ioc_type": "sha256_hash", "malware_printable": "X"}]})
        if "urlhaus" in url:
            return R({"query_status": "ok", "urls": [{"url": "http://1.2.3.4/x.sh", "threat": "malware_download", "url_status": "online", "tags": ["elf"]}]})
        if "attributes/restSearch" in url:
            return R({"response": {"Attribute": [
                {"type": "ip-dst|port", "value": "198.51.100.1|8080", "event_id": "7", "Event": {"info": "Кампания"}},
                {"type": "filename|sha256", "value": "a.exe|" + fx.EICAR_SHA256, "event_id": "7"},
                {"type": "domain|ip", "value": "c2.example|198.51.100.2", "event_id": "8"},
                {"type": "hostname", "value": "h.example", "event_id": "8"}]}})
        if "graphql" in url:
            return R({"data": {"indicators": {"edges": [
                {"node": {"name": "C2", "pattern": "[ipv4-addr:value = '203.0.113.77']", "x_opencti_score": 80, "valid_until": "2099-01-01T00:00:00Z", "revoked": False}},
                {"node": {"name": "old", "pattern": "[domain-name:value = 'old.example']", "valid_until": "2000-01-01T00:00:00Z", "revoked": False}}],
                "pageInfo": {"endCursor": None, "hasNextPage": False}}}})
        if "mb-api" in url:
            return R({"query_status": "ok", "data": []})
        raise AssertionError(url)

    def fake_get(url, **kw):
        if "feodo" in url:
            return R([{"ip_address": "198.51.100.66", "port": 447, "status": "online", "malware": "QakBot"}])
        if "mb-api" in url:
            return R(text='# header\n# "first_seen_utc","sha256_hash",...\n' + "\n".join(
                f'"2026-11-03 10:00:0{i}","{"%064x" % i}","{"%032x" % i}","{"%040x" % i}","rep","f{i}.exe","exe","application/x-dosexec","AgentTesla","n/a"'
                for i in range(1, 8)))
        raise AssertionError(url)

    monkeypatch.setattr(feeds.requests, "post", fake_post)
    monkeypatch.setattr(feeds.requests, "get", fake_get)
    tf = feeds.fetch_threatfox("KEY")
    assert {(i.type, i.value, i.port) for i in tf} == {("ip", "203.0.113.9", 443), ("domain", "bad.example", None), ("sha256", fx.EICAR_SHA256, None)}
    assert feeds.fetch_urlhaus("KEY")[0].value == "1.2.3.4/x.sh"
    assert feeds.fetch_feodo("")[0].port == 447
    mb = feeds.fetch_malwarebazaar("KEY")
    assert len(mb) == 21 and "AgentTesla" in mb[0].info
    misp = feeds.fetch_misp({"url": "https://misp", "key": "k", "days": 30})
    assert {(i.type, i.value) for i in misp} == {("ip", "198.51.100.1"), ("sha256", fx.EICAR_SHA256), ("domain", "c2.example"), ("ip", "198.51.100.2"), ("domain", "h.example")}
    octi = feeds.fetch_opencti({"url": "https://octi", "token": "t"})
    assert [(i.type, i.value) for i in octi] == [("ip", "203.0.113.77")]
    with pytest.raises(feeds.FeedError):
        feeds.fetch_threatfox("")
    assert ("https://threatfox-api.abuse.ch/api/v1/", "KEY") in calls


def test_pipeline_rematch_and_web(env, tmp_path):
    cfg, db = env
    from trafficlens import worker
    from trafficlens.web import create_app
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    s = pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")
    assert s["verdict"] == "critical" and s["ioc_hits"] == 5

    app = create_app(cfg, start_workers=False)
    c = app.test_client()
    H = {"X-Requested-With": "TrafficLens"}
    r = c.get("/")
    assert r.status_code == 200 and "x.pcap" in r.text and "Компрометация" in r.text
    r = c.get(f"/jobs/{jid}")
    assert r.status_code == 200 and "Обнаружены признаки компрометации" in r.text and "203.0.113.66" in r.text
    assert c.get(f"/jobs/{jid}/report.html").status_code == 200
    assert c.get("/iocs").status_code == 200
    assert c.get("/api/iocs/lookup?q=203.0.113.66").json["results"][0]["source"] == "custom"
    # POST без заголовка отклоняется (защита от CSRF)
    assert c.post(f"/api/jobs/{jid}/rematch").status_code == 400
    assert c.post(f"/api/jobs/{jid}/rematch", headers=H).json["ok"]
    r = c.post("/api/iocs/custom", json={"name": "extra", "text": "198.51.100.200\nмусор"}, headers=H)
    assert r.json["count"] == 1 and len(r.json["errors"]) == 1
    assert c.post("/api/iocs/custom", json={"name": "../x", "text": ""}, headers=H).status_code == 400
    # загрузка: не-PCAP отклоняется
    import io
    r = c.post("/api/upload", data={"file": (io.BytesIO(b"hello"), "a.pcap")}, headers=H, content_type="multipart/form-data")
    assert r.status_code == 400
    r = c.post("/api/upload", data={"file": (io.BytesIO(b"\x0a\x0d\x0d\x0a" + b"\0" * 40), "b.pcapng")}, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200 and len(r.json["jobs"]) == 1
    assert c.get("/jobs/../../etc/passwd").status_code == 404
    assert c.post(f"/api/jobs/{jid}/delete", headers=H).json["ok"]
    assert db.job(jid) is None


def test_auth(env):
    cfg, db = env
    cfg["auth"]["password"] = "s3cret"
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()
    assert c.get("/").status_code == 302
    assert c.get("/api/jobs").status_code == 401
    assert c.post("/login", data={"password": "s3cret"}).status_code == 302
    assert c.get("/").status_code == 200


def test_pcap_sha256_computed_once_on_ingest(env, tmp_path, monkeypatch):
    import hashlib
    from trafficlens import worker

    cfg, db = env
    payload = b"\xd4\xc3\xb2\xa1" + b"\0" * 64
    src = tmp_path / "ingest-sha.pcap"
    src.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    jid = worker.enqueue_file(cfg, db, src, "ingest-sha.pcap", "upload", move=False)
    job = db.job(jid)
    assert job["summary"]["pcap_sha256"] == expected

    def _must_not_recompute(path):
        raise AssertionError("pcap_sha256 пересчитан в build_report")

    monkeypatch.setattr(report, "sha256_file", _must_not_recompute)
    jd = pipeline.job_dir(cfg, jid)
    (jd / "zeek").mkdir(parents=True, exist_ok=True)
    summary = pipeline.build_report(cfg, db, job)
    assert summary["pcap_sha256"] == expected


def test_auth_hash_headers_redaction_and_ratelimit(env, tmp_path):
    from trafficlens import web as web_mod, worker

    cfg, db = env
    cfg["auth"]["password"] = ""
    cfg["auth"]["password_hash"] = web_mod.hash_password("s3cret")
    c = web_mod.create_app(cfg, start_workers=False).test_client()

    r = c.get("/")
    assert r.status_code == 302
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert c.post("/login", data={"password": "wrong"}).status_code == 403
    assert c.post("/login", data={"password": "s3cret"}).status_code == 302

    c2 = web_mod.create_app(cfg, start_workers=False).test_client()
    codes = [c2.post("/login", data={"password": "bad"}).status_code for _ in range(6)]
    assert codes[:5] == [403] * 5 and codes[5] == 429

    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    jobs = c.get("/api/jobs").get_json()["jobs"]
    mine = [j for j in jobs if j["id"] == jid][0]
    assert "/" not in mine["pcap_path"]
    one = c.get(f"/api/jobs/{jid}").get_json()
    assert "/" not in one["pcap_path"]


def test_retention_days_quota_dryrun(env, tmp_path):
    import time as _time
    from trafficlens import worker as worker_mod

    cfg, db = env
    cfg["retention"] = {"days": 7, "max_total_gb": 0, "keep_verdicts": ["critical"], "dry_run": False}

    def mk(name, age_days, verdict):
        src = tmp_path / name
        src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 32)
        jid = worker_mod.enqueue_file(cfg, db, src, name, "upload", move=False)
        created = _time.time() - age_days * 86400
        with db.conn() as c:
            c.execute("UPDATE jobs SET created=? WHERE id=?", (created, jid))
        db.update_job(jid, status="done", summary={"verdict": {"level": verdict}})
        return jid

    old_clean = mk("a.pcap", 10, "clean")
    old_crit = mk("b.pcap", 10, "critical")
    fresh = mk("c.pcap", 1, "clean")

    sched = worker_mod.Scheduler(cfg, db)
    sched.retention()
    ids = {j["id"] for j in db.jobs()}
    assert old_clean not in ids
    assert old_crit in ids and fresh in ids

    cfg["retention"]["dry_run"] = True
    x = mk("x.pcap", 30, "clean")
    sched.retention()
    assert x in {j["id"] for j in db.jobs()}
    cfg["retention"]["dry_run"] = False

    big = []
    for name, age in (("d.pcap", 3), ("e.pcap", 2), ("f.pcap", 1)):
        src = tmp_path / name
        src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 100_000)
        jid = worker_mod.enqueue_file(cfg, db, src, name, "upload", move=False)
        with db.conn() as c:
            c.execute("UPDATE jobs SET created=? WHERE id=?", (_time.time() - age * 86400, jid))
        verdict = "critical" if name == "f.pcap" else "clean"
        db.update_job(jid, status="done", summary={"verdict": {"level": verdict}})
        big.append(jid)
    d, e, f = big
    cfg["retention"] = {"days": 0, "max_total_gb": 250_000 / 1024**3,
                        "keep_verdicts": ["critical"], "dry_run": False}
    sched.retention()
    ids = {j["id"] for j in db.jobs()}
    assert d not in ids and e in ids and f in ids


def test_verdict_scoring(env):
    from trafficlens import report as report_mod

    cfg, _db = env
    base = {"ioc_hits": [], "alerts": [], "files": [],
            "findings": {"beacons": [], "large_uploads": [], "cleartext_auth": []},
            "dns": {"suspicious": []}, "tls": {"invalid": []}}

    v = report_mod.verdict(dict(base), cfg=cfg)
    assert v["level"] == "clean" and v["score"] == 0 and "Явных" in v["label"]

    hit = {"type": "domain", "value": "evil.example", "max_conf": 100}
    v = report_mod.verdict(dict(base, ioc_hits=[hit]), cfg=cfg)
    assert v["level"] == "suspicious" and v["score"] == 40 and v["reasons"]

    v = report_mod.verdict(dict(base, ioc_hits=[hit], alerts=[{"severity": 1, "name": "ET MALWARE"}]), cfg=cfg)
    assert v["level"] == "critical"

    low = dict(base, ioc_hits=[{"type": "domain", "value": "x", "max_conf": 10}])
    assert report_mod.verdict(low, cfg=cfg)["level"] == "clean"  # 40*0.1=4 < 30

    cfg["verdict"]["thresholds"] = {"suspicious": 100, "critical": 200}
    assert report_mod.verdict(dict(base, ioc_hits=[hit]), cfg=cfg)["level"] == "clean"
    del cfg["verdict"]["thresholds"]

    assert report_mod._verdict_legacy(dict(base, ioc_hits=[hit]))["level"] == "critical"
    assert report_mod._verdict_legacy(dict(base))["label"].startswith("Явных")

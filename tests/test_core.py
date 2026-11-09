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
    assert "ctx_conn_dst" in ip_hit["contexts"] and "ctx_dns_answer" in ip_hit["contexts"]
    assert ip_hit["count"] >= 16
    assert ("domain", "evil-c2.example") in hits
    assert {"ctx_dns_query", "ctx_tls_sni"} <= set(hits[("domain", "evil-c2.example")]["contexts"])
    assert ("url", "198.51.100.23/payload.exe") in hits
    assert ("sha256", fx.EICAR_SHA256) in hits
    assert ("ja3", fx.JA3) in hits

    assert rep["verdict"]["level"] == "critical"
    assert any("203.0.113.66:8443" in json.dumps(x, ensure_ascii=False) for x in rep["verdict"]["reasons"])
    assert any("payload.exe" in json.dumps(x, ensure_ascii=False) for x in rep["verdict"]["reasons"])

    ph = rep["priority_hosts"]
    assert ph and ph[0]["ip"] == fx.WS and ph[0]["level"] == "high"
    assert ph[0]["counts"]["ioc"] >= 4 and ph[0]["counts"]["files"] == 1 and ph[0]["counts"]["alerts"] >= 1
    assert "203.0.113.66" in ph[0]["external"] and any("payload.exe" in json.dumps(x, ensure_ascii=False) for x in ph[0]["reasons"])
    from trafficlens.render import render_report
    html = render_report(rep)
    assert rep["graph"]["nodes"] and rep["graph"]["links"]
    assert "Приоритетные хосты" in html and fx.WS in html
    assert 'id="tab-graph"' in html and 'id="netgraph"' in html

    # старые отчёты (JSON без ключа graph): render_report достраивает граф из connections
    legacy = json.loads(json.dumps(rep, default=list))
    del legacy["graph"]
    html = render_report(legacy)
    assert legacy["graph"]["links"] and 'id="netgraph"' in html

    # английская версия: переведены и шаблон, и данные отчёта (контексты, типы, вердикт, направления)
    html_en = render_report(json.loads(json.dumps(rep, default=list)), lang="en")
    for s in (">Summary<", "Priority hosts", "Signatures", "Network activity", "Anomalies", "Download HTML", "External addresses", "1 h 16 min",
              "Signs of compromise detected", "beacon", "Domain", "Connection (responder)", "DNS query", "download"):
        assert s in html_en, s
    # сырые токены не должны попадать в таблицы (в TL_I18N-бандле ключи есть всегда — проверяем ячейки)
    assert ">ctx_" not in html_en and "ctx_conn_dst," not in html_en
    for s in ("Сводка", "Сигнатуры", "Сетевая активность", "Аномалии", "Приоритетные хосты", "Фильтр по таблице", "Сформировано",
              "Обнаружены признаки", "маяк", "Домен", "Соединение (получатель)", "загрузка в сеть", "DNS-запрос"):
        assert s not in html_en, s
    t = rep["totals"]
    assert t["files"] == 3 and t["alerts"] == 2 and t["alert_sigs"] == 1

    f0 = rep["files"][0]  # файлы с IOC — первыми
    assert f0["sha256"] == fx.EICAR_SHA256 and f0["direction"] == "download"
    assert f0["filename"] == "payload.exe" and f0["extracted"] == "HTTP-FEICAR1"
    smb = next(f for f in rep["files"] if f["fuid"] == "FSMB1")
    assert smb["filename"] == "Отчёт Q3.pdf" and smb["direction"] == "internal"

    b = rep["findings"]["beacons"]
    assert b and b[0]["dst"] == "203.0.113.66" and 55 < b[0]["interval"] < 65 and b[0]["ioc"]
    assert any(u["dst"] == "198.51.100.200" for u in rep["findings"]["large_uploads"])
    assert any(u["port"] == 4444 for u in rep["findings"]["unusual_ports"])
    assert any(c["user"] == "backup" for c in rep["findings"]["cleartext_auth"])
    assert any(c["dur"] >= 3600 for c in rep["findings"]["long_conns"])
    assert any(isinstance(d["reason"], dict) and d["reason"].get("k") == "dns_entropy" for d in rep["dns"]["suspicious"])
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
    assert rep["priority_hosts"] == []
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
    r = c.get("/login")
    assert 'name="username"' in r.text and 'name="password"' in r.text
    assert c.post("/login", data={"username": "root", "password": "s3cret"}).status_code == 403
    assert c.post("/login", data={"username": "admin", "password": "s3cret"}).status_code == 302
    assert c.get("/").status_code == 200


def test_i18n_and_theme_markup(env):
    cfg, db = env
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()
    r = c.get("/login?lang=en")
    assert "Sign in to TrafficLens" in r.text and "Username" in r.text
    assert "tl_lang=en" in r.headers.get("Set-Cookie", "")
    assert "data-action=\"theme\"" in r.text
    r = c.get("/login?lang=ru")
    assert "Вход в TrafficLens" in r.text


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
    assert c.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 403
    assert c.post("/login", data={"username": "admin", "password": "s3cret"}).status_code == 302

    c2 = web_mod.create_app(cfg, start_workers=False).test_client()
    codes = [c2.post("/login", data={"username": "admin", "password": "bad"}).status_code for _ in range(6)]
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


def test_pdf_export(env, tmp_path):
    """PDF-отчёт собирается на обоих языках, кириллический TTF подхватывается."""
    cfg, db = env
    jd = fx.make_job(tmp_path / "job")
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg, {"filename": "t.pcap"})
    from trafficlens.pdf import _fonts, render_pdf
    font, _bold = _fonts()
    assert font == "TL"  # иначе кириллица в PDF будет битой — шрифт не найден
    for lang in ("ru", "en"):
        data = render_pdf(json.loads(json.dumps(rep, default=list)), lang=lang)
        assert data.startswith(b"%PDF") and len(data) > 10_000
    assert render_pdf(rep, lang="ru") != render_pdf(rep, lang="en")


def test_pdf_endpoint(env, tmp_path):
    cfg, db = env
    from trafficlens import worker
    from trafficlens.web import create_app
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")
    c = create_app(cfg, start_workers=False).test_client()
    r = c.get(f"/jobs/{jid}/report.pdf?lang=en")
    assert r.status_code == 200 and r.data.startswith(b"%PDF")
    assert r.headers["Content-Type"] == "application/pdf"


def test_search_jobs(env, tmp_path):
    """Серверный поиск: имя файла, хосты, IOC, переданные файлы."""
    cfg, db = env
    from trafficlens import worker
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "capture-friday.pcap", "upload", move=False)
    other = tmp_path / "y.pcap"
    other.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    worker.enqueue_file(cfg, db, other, "nothing-here.pcap", "upload", move=False)  # queued, без отчёта
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")

    for q in ("203.0.113", "evil-c2", "payload.exe", "WS-01", "friday"):
        assert [j["id"] for j in pipeline.search_jobs(cfg, db, q)] == [jid], q
    assert pipeline.search_jobs(cfg, db, "zzz-no-such") == []
    assert len(pipeline.search_jobs(cfg, db, "")) == 2  # пустой запрос — весь список

    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()
    assert "capture-friday.pcap" in c.get("/?q=203.0.113").text
    r = c.get("/?q=zzz-no-such")
    assert "capture-friday.pcap" not in r.text and "nothing-here.pcap" not in r.text


def test_mitre_mapping(env, tmp_path):
    from trafficlens import mitre
    from trafficlens.render import render_report

    assert mitre.alert_tags("A Network Trojan was detected") == [("TA0011", "T1071")]
    assert ("TA0004", "T1068") in mitre.alert_tags("Successful Administrator Privilege Gain")
    assert mitre.alert_tags("attempted recon") == [("TA0007", "T1046")]
    assert mitre.alert_tags("Misc activity") == [] and mitre.alert_tags("") == []

    cfg, db = env
    jd = fx.make_job(tmp_path / "job")
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg, {"filename": "t.pcap"})
    mt = {t["id"]: t for t in mitre.mitre_summary(rep)}
    assert "TA0011" in mt  # IOC, маячки, невалидный TLS, подозрительный DNS, файл с IOC
    assert "TA0010" in mt  # крупная выгрузка
    assert "TA0006" in mt  # учётные данные в открытом виде (FTP)
    techs = {te["id"] for t in mt.values() for te in t["techs"]}
    assert {"T1071", "T1041", "T1040", "T1105", "T1571", "T1573", "T1071.004"} <= techs
    html = render_report(json.loads(json.dumps(rep, default=list)), lang="en")
    assert "TA0011" in html and "attack.mitre.org/techniques/T1071/" in html


def _count_pcap_packets(path: Path) -> int:
    import struct
    n = 0
    with path.open("rb") as fh:
        magic = fh.read(4)
        assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
        fh.read(20)
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            incl = struct.unpack("<IIII", rh)[2]
            fh.seek(incl, 1)
            n += 1
    return n


def test_pcapfilter_time_window(env, tmp_path):
    """Обрезка по времени: classic pcap и pcapng; enqueue записывает фильтр в сводку."""
    import struct
    from trafficlens import pcapfilter, worker

    cfg, db = env
    payload = b"\0" * 20
    src = tmp_path / "in.pcap"
    with src.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for sec in (100, 200, 300):
            fh.write(struct.pack("<IIII", sec, 0, len(payload), len(payload)) + payload)
    out = tmp_path / "out.pcap"
    assert pcapfilter.trim_time(src, out, 150.0, 250.0) == (1, 3)
    assert _count_pcap_packets(out) == 1
    assert pcapfilter.trim_time(src, out, None, 250.0) == (2, 3)

    def block(btype, body):
        pad = ((len(body) + 3) & ~3) - len(body)
        ln = 12 + len(body) + pad
        return struct.pack("<II", btype, ln) + body + b"\0" * pad + struct.pack("<I", ln)

    def epb(ts):
        m = int(ts * 1_000_000)
        return block(6, struct.pack("<IIIII", 0, m >> 32, m & 0xFFFFFFFF, len(payload), len(payload)) + payload)

    ng = tmp_path / "in.pcapng"
    ng.write_bytes(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
                   + block(1, struct.pack("<HHI", 1, 0, 65535))
                   + epb(100) + block(3, struct.pack("<I", len(payload)) + payload) + epb(200))
    assert pcapfilter.trim_time(ng, tmp_path / "out.pcapng", 150.0, None) == (1, 3)  # SPB без метки отброшен

    jid = worker.enqueue_file(cfg, db, src, "in.pcap", "upload", move=False, ts_from=150.0, ts_to=350.0)
    job = db.job(jid)
    assert job["summary"]["filter"] == {"bpf": "", "from": 150.0, "to": 350.0}
    assert Path(job["pcap_path"]).stat().st_size == 24 + 2 * (16 + len(payload))  # заголовок + два пакета (200, 300)

    # то же через веб-эндпоинт + валидация окна
    import io
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()
    H = {"X-Requested-With": "TrafficLens"}
    data = src.read_bytes()
    r = c.post("/api/upload", data={"file": (io.BytesIO(data), "win.pcap"), "t_from": "150", "t_to": "250"},
               headers=H, content_type="multipart/form-data")
    assert r.status_code == 200
    job = db.job(r.json["jobs"][0])
    assert job["summary"]["filter"]["from"] == 150.0 and job["summary"]["filter"]["to"] == 250.0
    r = c.post("/api/upload", data={"file": (io.BytesIO(data), "win2.pcap"), "t_from": "300", "t_to": "100"},
               headers=H, content_type="multipart/form-data")
    assert r.status_code == 400 and "error" in r.json


def test_pcapfilter_bpf(tmp_path):
    """BPF через tcpdump (пропускается, если tcpdump не установлен)."""
    import importlib.util
    import shutil

    if not shutil.which("tcpdump"):
        pytest.skip("tcpdump не найден")
    spec = importlib.util.spec_from_file_location("make_test_pcap", Path(__file__).resolve().parents[1] / "tools" / "make_test_pcap.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    src = tmp_path / "bpf.pcap"
    p = m.Pcap(str(src))
    p.udp(1000.0, "192.168.1.50", 12345, "192.168.1.1", 53, b"\x00" * 10)
    p.tcp(1001.0, "192.168.1.50", 40000, "93.184.216.34", 443, 1, 0, 0x02)
    p.close()

    from trafficlens import pcapfilter
    out = tmp_path / "only-dns.pcap"
    desc = pcapfilter.filter_pcap(src, out, bpf="udp port 53")
    assert desc["bpf"] == "udp port 53"
    assert _count_pcap_packets(out) == 1
    with pytest.raises(ValueError):
        pcapfilter.filter_pcap(src, tmp_path / "bad.pcap", bpf="this is ((broken")


def test_rule_sources(env, monkeypatch):
    """Дополнительные источники правил: добавление/удаление через API, --url в suricata-update."""
    from trafficlens import runner
    from trafficlens.web import create_app

    cfg, db = env
    c = create_app(cfg, start_workers=False).test_client()
    H = {"X-Requested-With": "TrafficLens"}

    assert c.post("/api/rules/sources", json={"url": "ftp://x.rules"}, headers=H).status_code == 400
    r = c.post("/api/rules/sources", json={"url": "https://rules.example/etpro.rules", "note": "ET Pro"}, headers=H)
    assert r.json["ok"] and r.json["count"] == 1
    assert c.post("/api/rules/sources", json={"url": "https://rules.example/etpro.rules"}, headers=H).status_code == 400  # дубликат
    assert runner.rule_sources(cfg)[0]["note"] == "ET Pro"

    calls = []
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/bin/true" if name == "suricata-update" else None)

    def fake_run(cmd, **kw):
        calls.append(cmd)

        class R:
            returncode, stdout, stderr = 0, "", ""
        return R()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    ok, _msg = runner.update_rules(cfg)
    assert ok and "--url" in calls[0] and "https://rules.example/etpro.rules" in calls[0]

    assert "rules.example/etpro.rules" in c.get("/iocs").text
    assert c.post("/api/rules/sources/delete", json={"url": "https://rules.example/etpro.rules"}, headers=H).json["ok"]
    assert runner.rule_sources(cfg) == []


def test_virustotal_context_menu(env, tmp_path):
    """Контекстное меню «Проверить на VirusTotal» встроено в отчёт (RU и EN)."""
    cfg, db = env
    jd = fx.make_job(tmp_path / "job")
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg, {"filename": "t.pcap"})
    from trafficlens.render import render_report
    html = render_report(json.loads(json.dumps(rep, default=list)), lang="en")
    assert "virustotal.com/gui/search/" in html and "Check on VirusTotal" in html
    assert "blockboard" in html and "Block in BlockBoard" in html
    html_ru = render_report(json.loads(json.dumps(rep, default=list)), lang="ru")
    assert "Проверить на VirusTotal" in html_ru
    assert "Заблокировать в BlockBoard" in html_ru


def test_host_card(env, tmp_path):
    """Карточка хоста: таймлайн из логов, IOC-срез, контакты; веб-страница и ссылки из отчёта."""
    from collections import Counter

    from trafficlens import hostcard, worker
    from trafficlens.web import create_app

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")
    job = db.job(jid)

    card = hostcard.build(cfg, job, fx.WS)
    assert card["local"] and card["name"] == "WS-01" and card["mac"] == "aa:bb:cc:00:11:22"
    assert card["risk"] and card["risk"]["level"] == "high"
    kinds = Counter(e["kind"] for e in card["events"])
    for k in ("dns", "tls", "http", "file", "alert", "notice", "beacon", "upload", "cleartext", "tls_bad"):
        assert kinds[k], k
    ts = [e["ts"] for e in card["events"] if e["ts"]]  # события с меткой времени идут по возрастанию
    assert ts == sorted(ts)
    assert card["ioc_hits"] and any(h["value"] == "evil-c2.example" for h in card["ioc_hits"])
    assert any(f["filename"] == "payload.exe" for f in card["files"])
    ct = {c["ip"]: c for c in card["contacts"]}
    assert ct["203.0.113.66"]["ioc"] and ct["203.0.113.66"]["name"] == "api.evil-c2.example"
    assert card["totals"]["conns"] > 50
    other = hostcard.build(cfg, job, "93.184.216.34")  # внешний хост — валидная карточка без IOC
    assert other and not other["local"] and not other["ioc_hits"]

    c = create_app(cfg, start_workers=False).test_client()
    r = c.get(f"/jobs/{jid}/host/{fx.WS}")
    assert r.status_code == 200 and "WS-01" in r.text and "payload.exe" in r.text and "Маяк" in r.text
    r = c.get(f"/jobs/{jid}/host/{fx.WS}?lang=en")
    assert "Event timeline" in r.text and "Beacon" in r.text
    assert c.get(f"/jobs/{jid}/host/bad$ip").status_code == 404
    # ссылка на карточку есть в веб-отчёте и отсутствует в автономном HTML
    assert f"/jobs/{jid}/host/{fx.WS}" in c.get(f"/jobs/{jid}").text
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    from trafficlens.render import render_report
    assert f"/host/{fx.WS}" not in render_report(rep, embedded=False)


def test_kill_chain(env, tmp_path):
    """Цепочка компрометации: этапы из report.json, хосты на нескольких этапах, веб-страница RU/EN."""
    from trafficlens import killchain, worker
    from trafficlens.web import create_app

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")

    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    ch = killchain.build(rep)
    st = {s["key"]: s for s in ch["stages"]}
    assert [s["key"] for s in ch["stages"]] == ["recon", "initial", "execution", "privesc", "creds", "c2", "exfil", "impact"]
    # фикстура: маячок + IOC -> C2, FTP-пароль -> учётные данные, выгрузка 40 МБ -> эксфильтрация
    assert any(i["kind"] == "beacon" for i in st["c2"]["events"])
    assert any(i["kind"] == "ioc" and i["title"] == "evil-c2.example" for i in st["c2"]["events"])
    assert st["c2"]["first"] and st["c2"]["first"] <= st["c2"]["last"]
    assert any(i["kind"] == "cleartext" for i in st["creds"]["events"])
    assert any(i["kind"] == "upload" for i in st["exfil"]["events"])
    assert not st["impact"]["events"]  # пустой этап тоже присутствует
    assert ch["covered"] >= 3
    # рабочая станция замечена минимум на трёх этапах цепочки
    multi = {h["ip"]: h["stages"] for h in ch["hosts"]}
    assert fx.WS in multi and len(multi[fx.WS]) >= 3
    # текстовые цепочки для тикета: хост → домен → IP:порт маячка; файл → хэш
    texts = [t["text"] for t in ch["tickets"]]
    assert any("evil-c2.example" in t and "203.0.113.66:8443" in t and fx.WS in t for t in texts), texts
    assert any("payload.exe" in t and "275a021b" in t for t in texts), texts

    c = create_app(cfg, start_workers=False).test_client()
    r = c.get(f"/jobs/{jid}/chain")
    assert r.status_code == 200 and "Цепочка компрометации" in r.text and "Управление (C2)" in r.text
    assert "203.0.113.66" in r.text and "TA0011" in r.text
    # плашки тактик/техник ведут на attack.mitre.org, цепочка для тикета показана с кнопкой копирования
    assert "https://attack.mitre.org/tactics/TA0011/" in r.text
    assert "Цепочки для тикета" in r.text and "evil-c2.example → 203.0.113.66:8443" in r.text
    r = c.get(f"/jobs/{jid}/chain?lang=en")
    assert "Compromise chain" in r.text and "Exfiltration" in r.text and "Ticket-ready chains" in r.text
    # кнопка перехода есть в веб-отчёте и отсутствует в автономном HTML
    assert f"/jobs/{jid}/chain" in c.get(f"/jobs/{jid}").text
    from trafficlens.render import render_report
    assert "/chain" not in render_report(rep, embedded=False)


def test_analyst_markup(env, tmp_path):
    """Разметка аналитиком: статусы и allowlist снимают очки при пересверке, сброс возвращает."""
    from trafficlens import markup, worker
    from trafficlens.web import create_app

    H = {"X-Requested-With": "TrafficLens"}
    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    s0 = pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")
    assert s0["verdict"] == "critical"
    rep0 = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    score0 = rep0["verdict"]["score"]
    sid = str(rep0["alerts"][0]["sid"])
    assert rep0["alerts"][0]["severity"] == 1  # вес alert_sev_1 участвует в score

    c = create_app(cfg, start_workers=False).test_client()
    # ложная сигнатура: score падает сразу (авто-пересборка), бейдж виден в HTML
    r = c.post(f"/api/jobs/{jid}/marks", json={"kind": "alert", "key": sid, "status": "false_positive"}, headers=H)
    assert r.status_code == 200 and r.get_json()["summary"]["verdict"]
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    assert rep["alerts"][0]["status"] == "false_positive"
    assert rep["verdict"]["score"] < score0
    assert "Ложная" in c.get(f"/jobs/{jid}").text
    # сброс статуса возвращает очки
    c.post(f"/api/jobs/{jid}/marks", json={"kind": "alert", "key": sid, "status": "new"}, headers=H)
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    assert "status" not in rep["alerts"][0] and rep["verdict"]["score"] == score0

    # allowlist: IOC-хит остаётся виден со значком WL, но не даёт очков ни в одной задаче
    r = c.post("/api/allowlist", json={"kind": "ioc", "key": "evil-c2.example", "action": "add", "job_id": jid}, headers=H)
    assert r.get_json()["ok"] and r.get_json()["allowlist"] == 1
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    hit = next(h for h in rep["ioc_hits"] if h["value"] == "evil-c2.example")
    assert hit["wl"] is True and rep["verdict"]["score"] < score0
    assert "WL" in c.get(f"/jobs/{jid}").text
    assert "evil-c2.example" in c.get("/iocs").text  # список показан на странице IOC
    # маячок -> игнор: тоже снимает очки
    b0 = rep0["findings"]["beacons"][0]
    c.post(f"/api/jobs/{jid}/marks",
           json={"kind": "beacon", "key": markup.key_of("beacon", b0), "status": "ignored"}, headers=H)
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    assert rep["findings"]["beacons"][0]["status"] == "ignored"
    # полная очистка: allowlist del + без статусов -> score как в начале
    c.post("/api/allowlist", json={"kind": "ioc", "key": "evil-c2.example", "action": "del"}, headers=H)
    c.post(f"/api/jobs/{jid}/marks",
           json={"kind": "beacon", "key": markup.key_of("beacon", b0), "status": "new"}, headers=H)
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    assert rep["verdict"]["score"] == score0
    # валидация параметров
    assert c.post(f"/api/jobs/{jid}/marks", json={"kind": "nope", "key": "x", "status": "confirmed"}, headers=H).status_code == 400
    assert c.post("/api/allowlist", json={"kind": "ioc", "key": "", "action": "add"}, headers=H).status_code == 400


def test_csv_export(env, tmp_path):
    """CSV-экспорт: 4 раздела, BOM (utf-8-sig) для Excel, значения из фикстуры, 404 на мусор."""
    import codecs
    import csv as csvmod
    import io as iomod

    from trafficlens import worker
    from trafficlens.web import create_app

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")

    c = create_app(cfg, start_workers=False).test_client()
    for what, needles in (
        ("iocs", ["type,value", "evil-c2.example", "203.0.113.66"]),
        ("files", ["filename", "payload.exe", "275a021b"]),
        ("alerts", ["sid,signature", "2014819"]),
        ("hosts", ["ip,name", fx.WS]),
    ):
        r = c.get(f"/jobs/{jid}/export/{what}.csv")
        assert r.status_code == 200, what
        assert r.data.startswith(codecs.BOM_UTF8), what  # открывается в Excel двойным кликом
        assert "attachment" in r.headers.get("Content-Disposition", "")
        text = r.data.decode("utf-8-sig")
        for n in needles:
            assert n in text, (what, n)
        rows = list(csvmod.reader(iomod.StringIO(text)))
        assert len(rows) >= 2 and rows[0]  # заголовок + данные, парсится штатным csv
    # RU/EN локализация значений и неизвестный раздел -> 404
    assert "высокая" in c.get(f"/jobs/{jid}/export/alerts.csv").data.decode("utf-8-sig")
    assert "high" in c.get(f"/jobs/{jid}/export/alerts.csv?lang=en").data.decode("utf-8-sig")
    assert c.get(f"/jobs/{jid}/export/nope.csv").status_code == 404
    # кнопки CSV видны в веб-отчёте и отсутствуют в автономном HTML
    assert f"/jobs/{jid}/export/iocs.csv" in c.get(f"/jobs/{jid}").text
    from trafficlens.render import render_report
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    assert "export/" not in render_report(rep, embedded=False)


def test_evidence_badges(env, tmp_path):
    """Уверенность находок: бейджи «Факт»/«Эвристика» в причинах вердикта, риске хостов и разделах."""
    from trafficlens import worker
    from trafficlens.render import evidence_of_reason, render_report
    from trafficlens.web import create_app

    # классификация ключей причин
    assert evidence_of_reason({"k": "vr_ioc"}) == "fact"
    assert evidence_of_reason({"k": "hr_cleartext"}) == "fact"
    assert evidence_of_reason({"k": "vr_beacon"}) == "heuristic"
    assert evidence_of_reason({"k": "hr_dns"}) == "heuristic"
    assert evidence_of_reason("Suricata sev1 ...") == ""  # строковые причины старого формата — без бейджа

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")

    c = create_app(cfg, start_workers=False).test_client()
    html = c.get(f"/jobs/{jid}").text
    # в фикстуре есть и факты (IOC, сигнатура sev1, файл EICAR, cleartext), и эвристики (маячок, выгрузка)
    assert ">Факт<" in html and ">Эвристика<" in html
    assert "Статистическая или пороговая оценка" in html  # hint у эвристики
    assert "Прямое наблюдение в логах" in html
    en = c.get(f"/jobs/{jid}?lang=en").text
    assert ">Fact<" in en and ">Heuristic<" in en
    # бейджи есть и в автономном HTML, и в карточке хоста
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    standalone = render_report(rep, embedded=False)
    assert ">Факт<" in standalone and ">Эвристика<" in standalone
    card = c.get(f"/jobs/{jid}/host/{fx.WS}").text
    # язык карточки зависит от cookie тест-клиента — принимаем оба
    assert any(x in card for x in (">Факт<", ">Эвристика<", ">Fact<", ">Heuristic<"))


def test_help_page(env):
    """Встроенная инструкция: /help отдаёт RU/EN-версию по языку, ссылки в шапке, скриншоты на диске."""
    from trafficlens.render import STATIC
    from trafficlens.web import create_app

    cfg, db = env
    c = create_app(cfg, start_workers=False).test_client()
    r = c.get("/help")
    assert r.status_code == 200
    assert "Инструкция администратора" in r.text and "/static/help/ru/01-login.png" in r.text
    assert "Инструкция" in c.get("/").text  # ссылка в шапке
    r = c.get("/help?lang=en")
    assert "Administrator guide" in r.text and "/static/help/en/01-login.png" in r.text
    assert "Guide" in c.get("/?lang=en").text
    shots = ("01-login", "02-index", "03-report-top", "04-report-hosts",
             "05-host", "06-report-ioc", "07-report-graph", "08-chain", "09-iocs")
    for lang in ("ru", "en"):
        for n in shots:
            p = STATIC / "help" / lang / f"{n}.png"
            assert p.exists() and p.stat().st_size > 10000, (lang, n)


def test_hostcard_report_links(env, tmp_path):
    """Карточка хоста: ссылки ↗ ведут на отчёт с предзаполненным фильтром (?flt=...#вкладка)."""
    from trafficlens import worker
    from trafficlens.render import STATIC
    from trafficlens.web import create_app

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")

    c = create_app(cfg, start_workers=False).test_client()
    card = c.get(f"/jobs/{jid}/host/{fx.WS}").text
    assert f"/jobs/{jid}?flt={fx.WS}#ioc" in card
    assert f"/jobs/{jid}?flt={fx.WS}#net" in card
    assert f"/jobs/{jid}?flt={fx.WS}#files" in card
    assert "?flt=evil-c2.example#ioc" in card
    # report.js подхватывает ?flt= и проставляет фильтры активной вкладки;
    # важно: applyPreFilter вызывается ПОСЛЕ навешивания обработчиков input.filter,
    # иначе событие input уходит в никуда и строки не фильтруются
    js = (STATIC / "report.js").read_text(encoding="utf-8")
    assert 'get("flt")' in js
    assert js.find("applyPreFilter") > js.find('addEventListener("input"')


def test_index_filters(env, tmp_path):
    """Фильтры задач на главной: по вердикту, источнику и дате создания."""
    import time as _time

    from trafficlens import worker
    from trafficlens.web import _filter_jobs, create_app

    cfg, db = env
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "x.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done")  # вердикт critical, источник upload

    pcap2 = tmp_path / "y.pcap"
    pcap2.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid2 = worker.enqueue_file(cfg, db, pcap2, "y.pcap", "capture", move=False)
    db.update_job(jid2, status="done", summary={"verdict": "clean"})

    c = create_app(cfg, start_workers=False).test_client()
    r = c.get("/").text
    assert "x.pcap" in r and "y.pcap" in r
    r = c.get("/?verdict=critical").text
    assert "x.pcap" in r and "y.pcap" not in r
    assert "Найдено: 1" in r
    r = c.get("/?src=capture").text
    assert "y.pcap" in r and "x.pcap" not in r
    r = c.get("/?verdict=clean&src=upload").text
    assert "x.pcap" not in r and "y.pcap" not in r
    today = _time.strftime("%Y-%m-%d")
    assert "x.pcap" in c.get(f"/?dfrom={today}").text
    assert "x.pcap" not in c.get("/?dfrom=2999-01-01").text
    # выбранные значения сохраняются в форме
    r = c.get("/?verdict=critical").text
    assert 'value="critical" selected' in r
    # unit-хелпер напрямую, в т.ч. невалидная дата не ломает выборку
    jobs = db.jobs()
    assert [j["filename"] for j in _filter_jobs(jobs, {"verdict": "clean"})] == ["y.pcap"]
    assert len(_filter_jobs(jobs, {"dfrom": "не-дата"})) == 2

"""Качество сигналов: слабые TLS-находки, потолки категорий, шумовые сигнатуры,
служебные файлы, DoH/DoT, индекс подсетей, открытые фиды без ключа."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, ioc_store, mitre, quality, report, runner  # noqa: E402
from trafficlens.db import DB  # noqa: E402
from trafficlens.ioc_store import Indicator  # noqa: E402
from trafficlens.render import render_report  # noqa: E402

WEAK = "unable to get local issuer certificate"


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    return config.load()


def _rep(**over):
    rep = {"ioc_hits": [], "alerts": [], "files": [], "tls": {"invalid": []}, "dns": {"suspicious": []},
           "findings": {"beacons": [], "large_uploads": [], "cleartext_auth": []}}
    rep.update(over)
    return rep


def _tls(n, status, sni_tpl="s{}.example", src="192.168.1.50"):
    return [{"ts": 1.0, "src": src, "dst": f"203.0.113.{i % 200}", "sni": sni_tpl.format(i), "status": status} for i in range(n)]


def test_weak_tls_does_not_score(cfg):
    # сценарий example-01: 54 «unable to get local issuer» на обычном сёрфинге
    v = report.verdict(_rep(tls={"invalid": _tls(52, WEAK) + _tls(2, "self-signed certificate in certificate chain")}), cfg=cfg)
    assert v["score"] == 0 and v["level"] == "clean"


def test_strong_tls_dedup_and_cap(cfg):
    inv = _tls(3, "self signed certificate") * 4 + _tls(5, "certificate has expired", sni_tpl="e{}.example")
    v = report.verdict(_rep(tls={"invalid": inv}), cfg=cfg)
    assert v["score"] == 20           # 8 уникальных SNI × 10, потолок категории 20
    capped = [r for r in v["reasons"] if r["k"] == "vr_capped_tls_invalid"]
    assert capped and capped[0]["n"] == 6 and capped[0]["pts"] is None


def test_gate_without_strong_evidence(cfg):
    beacons = [{"src": "192.168.1.50", "dst": f"198.51.100.{i}", "dp": 443} for i in range(6)]
    uploads = [{"src": "192.168.1.50", "dst": f"198.51.100.{i}"} for i in range(4)]
    rep = _rep(findings={"beacons": beacons, "large_uploads": uploads, "cleartext_auth": []},
               dns={"suspicious": [{"name": f"x{i}.biz"} for i in range(5)]})
    v = report.verdict(rep, cfg=cfg)
    assert v["score"] >= 80 and v["level"] == "suspicious" and v["gated"] is True
    rep["ioc_hits"] = [{"value": "203.0.113.66", "type": "ip", "max_conf": 100, "hosts": ["192.168.1.50"]}]
    v = report.verdict(rep, cfg=cfg)
    assert v["level"] == "critical" and not v["gated"]


def test_caps_configurable(cfg):
    cfg["verdict"]["caps"] = {"tls_invalid": None}
    v = report.verdict(_rep(tls={"invalid": _tls(8, "certificate has expired")}), cfg=cfg)
    assert v["score"] == 80 and v["level"] == "suspicious"   # без потолка, но всё равно гейт


def test_quality_helpers():
    assert quality.tls_is_weak("Unable to get local issuer certificate")
    assert quality.tls_is_weak("self-signed certificate in certificate chain")
    assert not quality.tls_is_weak("self-signed certificate")
    assert quality.alert_is_noise("SURICATA TCPv4 invalid checksum")
    assert not quality.alert_is_noise("ET MALWARE Something")
    assert quality.file_is_service("application/ocsp-response")
    assert quality.file_is_service("", "http://ocsp.digicert.com/")
    assert quality.guess_type("current.iso") == "application/x-iso9660-image"
    assert quality.doh_kind("1.1.1.1", 443) == "DoH" and quality.doh_kind("203.0.113.5", 853) == "DoT"
    assert quality.doh_kind("203.0.113.5", 443, "dns.google") == "DoH" and quality.doh_kind("203.0.113.5", 443) == ""


def _append(p: Path, rows):
    with p.open("a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_build_noise_files_doh(cfg, tmp_path):
    db = DB(cfg.db_path)
    jd = fx.make_job(tmp_path / "job")
    z = jd / "zeek"
    # шум checksum offload
    _append(jd / "suricata" / "eve.json", [
        {"timestamp": "2026-11-04T10:01:00.000000+0500", "event_type": "alert", "src_ip": "93.184.216.34", "src_port": 443,
         "dest_ip": fx.WS, "dest_port": 50001, "alert": {"signature_id": 2200074, "signature": "SURICATA TCPv4 invalid checksum",
                                                          "category": "Generic Protocol Command Decode", "severity": 3}}] * 50)
    # одинаковые OCSP-ответы и обрезанный ISO без MIME
    ocsp = {"ts": fx.T0 + 300, "fuid": "FO", "uid": "Co", "id.orig_h": fx.WS, "id.orig_p": 54000, "id.resp_h": "117.18.237.29",
            "id.resp_p": 80, "source": "HTTP", "mime_type": "application/ocsp-response", "is_orig": False, "seen_bytes": 471,
            "total_bytes": 471, "md5": "d" * 32, "sha1": "e" * 40, "sha256": "f" * 64}
    iso = {"ts": fx.T0 + 310, "fuid": "FISO", "uid": "Ciso", "id.orig_h": fx.WS, "id.orig_p": 54001, "id.resp_h": "152.19.134.43",
           "id.resp_p": 80, "source": "HTTP", "mime_type": "", "filename": "current.iso", "is_orig": False,
           "seen_bytes": 52428800, "total_bytes": 53174753, "md5": "1" * 32, "sha1": "2" * 40, "sha256": "3" * 64,
           "extracted": "HTTP-FISO", "extracted_cutoff": True}
    _append(z / "files.log", [dict(ocsp, fuid=f"FO{i}") for i in range(5)] + [iso])
    # DoH на 1.1.1.1 и DoT на 853
    _append(z / "conn.log", [fx.conn(fx.T0 + 400 + i, fx.WS, 55000 + i, "1.1.1.1", 443, svc="ssl", uid=f"Cdoh{i}") for i in range(3)]
            + [fx.conn(fx.T0 + 410, fx.WS, 55100, "203.0.113.200", 853, svc="ssl", uid="Cdot")])

    rep = report.build(jd, ioc_store.IOCIndex(db), cfg, {"filename": "t.pcap"})
    assert rep["totals"]["alerts_suppressed"] == 50
    assert all("checksum" not in a["signature"] for a in rep["alerts"])
    assert rep["alerts_suppressed"][0]["sid"] == 2200074

    svc = [f for f in rep["files"] if f["service"]]
    assert len(svc) == 1 and svc[0]["repeat"] == 5 and rep["totals"]["files_service"] == 1
    iso_row = next(f for f in rep["files"] if f["fuid"] == "FISO")
    assert iso_row["cutoff"] and iso_row["mime_guess"] == "application/x-iso9660-image" and not iso_row["service"]
    main = [f for f in rep["files"] if not f["service"] and not f["ioc"]]
    assert main[0]["fuid"] == "FISO"   # крупный файл — первым после IOC

    edns = {(d["dst"], d["kind"]): d for d in rep["findings"]["encrypted_dns"]}
    assert edns[("1.1.1.1", "DoH")]["count"] == 3 and ("203.0.113.200", "DoT") in edns
    assert rep["meta"]["dns_absent"] is False

    html = render_report(rep, embedded=False)
    assert "t-files-svc" in html and "DoH" in html and "2200074" not in html.split('id="t-alerts"')[1].split("</table>")[0]


def test_dns_absent_banner(cfg, tmp_path):
    db = DB(cfg.db_path)
    jd = tmp_path / "nodns"
    (jd / "zeek").mkdir(parents=True)
    (jd / "zeek" / "conn.log").write_text(json.dumps(fx.conn(fx.T0, fx.WS, 50000, "93.184.216.34", 443, svc="ssl")) + "\n")
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["meta"]["dns_absent"] is True
    assert "banner" in render_report(rep)


def test_mitre_weak_tls_and_noise():
    rep = _rep(tls={"invalid": _tls(10, WEAK)},
               alerts=[{"signature": "SURICATA TCPv4 invalid checksum", "category": "a network trojan was detected", "count": 9}])
    assert mitre.mitre_summary(rep) == []
    rep["tls"]["invalid"] = _tls(2, "self signed certificate")
    assert mitre.mitre_summary(rep) == []          # без маячка T1573 не ставим
    rep["findings"]["beacons"] = [{"src": "192.168.1.50", "dst": "203.0.113.1", "dp": 443}]
    techs = {t["id"] for x in mitre.mitre_summary(rep) for t in x["techs"]}
    assert "T1573" in techs


def test_cidr_index_narrowest_and_cache():
    idx = ioc_store.IOCIndex()
    idx.add(Indicator("cidr", "198.51.100.0/24", info="wide"))
    idx.add(Indicator("cidr", "198.51.100.128/25", info="narrow"))
    idx.add(Indicator("cidr", "2001:db8::/32", info="v6"))
    for i in range(2000):
        idx.add(Indicator("cidr", f"10.{i // 256}.{i % 256}.0/24"))
    m = idx.ip("198.51.100.200")
    assert m and m.value == "198.51.100.128/25" and m.entries[0]["info"] == "narrow"
    assert idx.ip("198.51.100.5").value == "198.51.100.0/24"
    assert idx.ip("2001:db8::1").value == "2001:db8::/32"
    assert idx.ip("203.0.113.1") is None and idx.ip("not-an-ip") is None
    idx.add(Indicator("cidr", "203.0.113.0/24"))   # индекс перестраивается после add
    assert idx.ip("203.0.113.1").value == "203.0.113.0/24"


def test_public_feeds(monkeypatch):
    class R:
        def __init__(self, text):
            self.text, self.ok = text, True

        def raise_for_status(self):
            pass

    pages = {
        feeds.SPAMHAUS_DROP[0]: '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
                                '{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}\n'
                                '{"type":"metadata","timestamp":1793769600,"size":2}\n',
        feeds.SPAMHAUS_DROP[1]: '{"cidr":"2a06:e480::/29","sblid":"SBL303641","rir":"ripencc"}\n',
        feeds.ET_COMPROMISED: "# comment\n1.2.3.4\n5.6.7.8\n\nnot-ip\n",
        feeds.TOR_EXITS: "185.220.101.1\n185.220.101.2\n",
    }
    monkeypatch.setattr(feeds.requests, "get", lambda url, **kw: R(pages[url]))
    drop = feeds.fetch_spamhaus_drop()
    assert [(i.type, i.value) for i in drop] == [("cidr", "1.10.16.0/20"), ("cidr", "1.19.0.0/16"), ("cidr", "2a06:e480::/29")]
    assert "SBL256894" in drop[0].info
    et = feeds.fetch_et_compromised()
    assert [i.value for i in et] == ["1.2.3.4", "5.6.7.8"] and et[0].confidence == 60
    assert [i.confidence for i in feeds.fetch_tor_exits()] == [20, 20]


def test_update_rules_disable_conf_and_et_open(cfg, monkeypatch):
    calls = []

    class P:
        returncode, stdout, stderr = 0, "This is Suricata version 7.0.10 RELEASE\n", ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return P()

    monkeypatch.setattr(runner.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(runner, "suricata_bin", lambda c: "/usr/bin/suricata")
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    ok, _ = runner.update_rules(cfg)
    cmd = calls[-1]
    assert ok and "--disable-conf" in cmd and "--url" not in cmd   # без доп. источников — ET Open по умолчанию
    assert "re:invalid checksum" in (cfg.rules_dir / "disable.conf").read_text()
    runner.save_rule_sources(cfg, [{"url": "https://rules.example/extra.rules"}])
    runner.update_rules(cfg)
    cmd = calls[-1]
    urls = [cmd[i + 1] for i, x in enumerate(cmd) if x == "--url"]
    assert urls == ["https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz",
                    "https://rules.example/extra.rules"]


def test_host_risk_gate_and_caps(cfg, tmp_path):
    """Приоритетные хосты: слабые TLS не дают риска, без IOC/sev1/файлов уровень не выше medium."""
    db = DB(cfg.db_path)
    jd = tmp_path / "hr"
    z = jd / "zeek"
    z.mkdir(parents=True)
    rows = [{"ts": fx.T0 + i, "uid": f"C{i}", "id.orig_h": fx.WS, "id.orig_p": 50000 + i, "id.resp_h": f"203.0.113.{i}",
             "id.resp_p": 443, "version": "TLSv12", "server_name": f"s{i}.example",
             "validation_status": WEAK if i < 40 else "certificate has expired"} for i in range(50)]
    (z / "ssl.log").write_text("".join(json.dumps(r) + "\n" for r in rows))
    rep = report.build(jd, ioc_store.IOCIndex(db), cfg)
    assert rep["verdict"]["score"] == 20
    h = rep["priority_hosts"][0]
    assert h["ip"] == fx.WS and h["score"] == 20 and h["level"] == "low"
    assert sum(1 for t in rep["tls"]["invalid"] if t["weak"]) == 40

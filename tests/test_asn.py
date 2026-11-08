"""Офлайн-база ASN (iptoasn): загрузка TSV, поиск по диапазонам, обогащение отчёта."""
import gzip
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import asn, config, feeds, pipeline, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402

TSV = "\n".join([
    "203.0.113.0\t203.0.113.255\t64496\tZZ\tTESTNET-3 example",
    "198.51.100.0\t198.51.100.255\t64497\tZZ\tTESTNET-2 example",
    "1.0.0.0\t1.0.0.255\t0\tAU\t",            # AS 0 — «не назначен», должен давать None
    "битая строка",
]) + "\n"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    cfg["retro"]["enabled"] = False
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    with gzip.open(asn.db_path(cfg), "wt", encoding="utf-8") as f:
        f.write(TSV)
    return cfg, db


def test_lookup_and_status(env):
    cfg, _ = env
    st = asn.status(cfg)
    assert st["present"] and st["ranges"] == 3

    hit = asn.lookup(cfg, "203.0.113.66")
    assert hit == {"asn": 64496, "cc": "ZZ", "name": "TESTNET-3 example"}
    assert asn.lookup(cfg, "203.0.113.255")["asn"] == 64496      # граница диапазона
    assert asn.lookup(cfg, "8.8.8.8") is None                    # вне диапазонов
    assert asn.lookup(cfg, "1.0.0.10") is None                   # AS 0 — не назначен
    assert asn.lookup(cfg, "не-адрес") is None

    asn.db_path(cfg).unlink()
    assert asn.lookup(cfg, "203.0.113.66") is None and not asn.status(cfg)["present"]


def test_enrich_in_report(env, tmp_path):
    cfg, db = env
    pcap = tmp_path / "w.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "w.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)

    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    ext = {e["ip"]: e for e in rep["top_external"]}
    assert ext["203.0.113.66"]["asn"] == 64496
    assert ext["203.0.113.66"]["as_name"] == "TESTNET-3 example"
    assert ext["198.51.100.23"]["as_cc"] == "ZZ"


def test_update_writes_db(env, monkeypatch):
    cfg, db = env
    asn.db_path(cfg).unlink()
    payload = gzip.compress(TSV.encode())

    class _Resp:
        def raise_for_status(self):
            pass

        def iter_content(self, n):
            yield payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(asn.requests, "get", lambda *a, **kw: _Resp())
    res = worker.run_asn_update(cfg, db)
    assert res["ranges"] == 3 and asn.lookup(cfg, "198.51.100.23")["asn"] == 64497
    saved = db.kv_get("asn_status")
    assert saved["ranges"] == 3 and "error" not in saved

"""Экспорт находок задачи в пользовательский список IOC (from-reports.txt)."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, pipeline, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402

H = {"X-Requested-With": "TrafficLens"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    cfg["retro"]["enabled"] = False
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


def _rep(cfg, jid):
    return json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))


def test_export_adds_and_dedups(env, tmp_path):
    cfg, db = env
    jid = _done_job(cfg, db, tmp_path)
    job = db.job(jid)
    rep = _rep(cfg, jid)

    # эталонные индикаторы уже есть в investigation.txt — удалим его, чтобы экспорт начинался с чистого листа
    (cfg.custom_ioc_dir / "investigation.txt").unlink()
    feeds.update_all(cfg, db, only="custom")

    r1 = feeds.add_job_iocs_to_custom(cfg, job, rep)
    assert r1["added"] == len(rep["ioc_hits"]) > 0 and r1["dup"] == 0
    text = (cfg.custom_ioc_dir / feeds.FROM_REPORTS).read_text(encoding="utf-8")
    assert "203.0.113.66" in text and jid in text        # значение + откуда взялось

    r2 = feeds.add_job_iocs_to_custom(cfg, job, rep)     # повтор — всё уже в списках
    assert r2["added"] == 0 and r2["dup"] == len(rep["ioc_hits"])


def test_export_skips_false_positive(env, tmp_path):
    cfg, db = env
    jid = _done_job(cfg, db, tmp_path)

    rep = _rep(cfg, jid)
    victim = rep["ioc_hits"][0]["value"]
    db.set_mark(jid, "ioc", victim, "false_positive", "тест")
    pipeline.rematch(cfg, db, jid)                        # отчёт пересобран — статус попал в хиты

    # эталонные индикаторы уже есть в investigation.txt — удалим его, чтобы экспорт начинался с чистого листа
    (cfg.custom_ioc_dir / "investigation.txt").unlink()
    feeds.update_all(cfg, db, only="custom")

    rep = _rep(cfg, jid)
    assert any(h["value"] == victim and h.get("status") == "false_positive" for h in rep["ioc_hits"])

    r = feeds.add_job_iocs_to_custom(cfg, db.job(jid), rep)
    assert r["skipped"] == 1 and r["added"] == len(rep["ioc_hits"]) - 1
    assert victim not in (cfg.custom_ioc_dir / feeds.FROM_REPORTS).read_text(encoding="utf-8")


def test_export_endpoint(env, tmp_path):
    cfg, db = env
    jid = _done_job(cfg, db, tmp_path)
    (cfg.custom_ioc_dir / "investigation.txt").unlink()
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()

    assert c.post(f"/api/jobs/{jid}/export-iocs").status_code == 400          # без заголовка — CSRF-защита
    r = c.post(f"/api/jobs/{jid}/export-iocs", headers=H)
    assert r.status_code == 200 and r.json["ok"] and r.json["added"] == 5
    assert (cfg.custom_ioc_dir / feeds.FROM_REPORTS).exists()
    r2 = c.post(f"/api/jobs/{jid}/export-iocs", headers=H)                    # повтор — только дубли
    assert r2.json["added"] == 0 and r2.json["dup"] == 5

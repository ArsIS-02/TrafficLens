"""«Где ещё встречался»: sightings — связка IOC между задачами."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, pipeline, render, worker, web  # noqa: E402
from trafficlens.db import DB  # noqa: E402


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


def _hits(cfg, jid):
    rep = json.loads((pipeline.job_dir(cfg, jid) / "report.json").read_text(encoding="utf-8"))
    return rep, [(h["type"], h["value"]) for h in rep["ioc_hits"]]


def test_sightings_link_jobs(env, tmp_path):
    cfg, db = env
    j1 = _done_job(cfg, db, tmp_path, "a.pcap")
    j2 = _done_job(cfg, db, tmp_path, "b.pcap")
    _, pairs = _hits(cfg, j1)
    assert pairs, "у эталонного дампа должны быть IOC-хиты"

    ew = db.sightings_elsewhere(pairs, exclude_job=j1)
    assert pairs[0] in ew
    assert ew[pairs[0]][0]["job_id"] == j2
    # текущая задача не показывается сама себе
    assert all(e["job_id"] != j1 for lst in ew.values() for e in lst)
    # а для второй задачи видна первая
    ew2 = db.sightings_elsewhere(pairs, exclude_job=j2)
    assert ew2[pairs[0]][0]["job_id"] == j1


def test_sightings_removed_with_job(env, tmp_path):
    cfg, db = env
    j1 = _done_job(cfg, db, tmp_path, "a.pcap")
    j2 = _done_job(cfg, db, tmp_path, "b.pcap")
    _, pairs = _hits(cfg, j1)
    assert db.sightings_elsewhere(pairs, exclude_job=j1)
    pipeline.delete(cfg, db, j2)
    assert db.sightings_elsewhere(pairs, exclude_job=j1) == {}


def test_backfill_from_reports(env, tmp_path):
    cfg, db = env
    j1 = _done_job(cfg, db, tmp_path, "a.pcap")
    with db.conn() as c:
        c.execute("DELETE FROM sightings")
    assert db.sightings_count() == 0
    web._backfill_sightings(cfg, db)
    assert db.sightings_count() > 0
    _, pairs = _hits(cfg, j1)
    assert pairs[0] in db.sightings_elsewhere(pairs, exclude_job="нет-такой")


def test_report_shows_elsewhere_badge(env, tmp_path):
    cfg, db = env
    j1 = _done_job(cfg, db, tmp_path, "a.pcap")
    j2 = _done_job(cfg, db, tmp_path, "b.pcap")
    rep, pairs = _hits(cfg, j1)
    ew = db.sightings_elsewhere(pairs, exclude_job=j1)
    html = render.render_report(rep, embedded=True, job={"id": j1}, lang="ru",
                                elsewhere=ew, jobnames={j2: "b.pcap"})
    assert "ещё в 1" in html
    assert "b.pcap" in html                       # имя задачи в подсказке бейджа
    assert "/?q=" in html                         # ссылка на поиск задач
    # без данных — без бейджа
    html2 = render.render_report(rep, embedded=True, job={"id": j1}, lang="ru",
                                 elsewhere={}, jobnames={})
    assert "ещё в" not in html2

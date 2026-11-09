import json
import random
import string
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trafficlens import config, pipeline  # noqa: E402
from trafficlens.db import DB  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    db = DB(cfg.db_path)
    return cfg, db


def _dns_rows(base, n=10, nx=True):
    rnd = random.Random(42)
    rows = []
    for i in range(n):
        label = "".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        rows.append({"ts": 1700000000.0 + i, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                     "query": f"{label}.{base}", "qtype_name": "A",
                     "rcode_name": "NXDOMAIN" if nx else "NOERROR", "answers": []})
    return rows


def _run_report(env, tmp_path, rows):
    cfg, db = env
    db.add_job("dga-test", "upload", "dga.pcap", str(tmp_path / "x.pcap"), 1, status="queued")
    jd = pipeline.job_dir(cfg, "dga-test")
    (jd / "zeek").mkdir(parents=True, exist_ok=True)
    (jd / "suricata").mkdir(exist_ok=True)
    with (jd / "zeek" / "dns.log").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    job = db.job("dga-test")
    pipeline.build_report(cfg, db, job)
    return json.loads((jd / "report.json").read_text(encoding="utf-8"))


def test_dga_detected(env, tmp_path):
    rep = _run_report(env, tmp_path, _dns_rows("evil-dga.example"))
    susp = rep["dns"]["suspicious"]
    names = {s["name"]: s for s in susp}
    assert "*.evil-dga.example" in names
    assert names["*.evil-dga.example"]["reason"]["k"] == "dga"


def test_dga_whitelist_skipped(env, tmp_path):
    rep = _run_report(env, tmp_path, _dns_rows("googlevideo.com"))
    assert not any(s["reason"]["k"] == "dga" for s in rep["dns"]["suspicious"])


def test_dga_few_labels_no_signal(env, tmp_path):
    rep = _run_report(env, tmp_path, _dns_rows("evil-dga.example", n=3))
    assert not any(s["reason"]["k"] == "dga" for s in rep["dns"]["suspicious"])

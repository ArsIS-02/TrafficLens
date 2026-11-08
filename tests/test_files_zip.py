"""Скачивание всех извлечённых файлов задачи одним ZIP (пароль infected)."""
import io
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, pipeline, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    cfg = config.load()
    cfg["retro"]["enabled"] = False
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    pcap = tmp_path / "w.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    jid = worker.enqueue_file(cfg, db, pcap, "w.pcap", "upload", move=False)
    fx.make_job(pipeline.job_dir(cfg, jid))
    pipeline.rematch(cfg, db, jid)
    db.update_job(jid, status="done", finished=time.time())
    return cfg, db, jid


def test_files_zip_endpoint(env):
    import pyzipper
    cfg, db, jid = env
    from trafficlens.web import create_app
    c = create_app(cfg, start_workers=False).test_client()

    r = c.get(f"/jobs/{jid}/files.zip")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    with pyzipper.AESZipFile(io.BytesIO(r.data)) as zf:
        zf.setpassword(b"infected")
        assert zf.namelist() == ["HTTP-FEICAR1.bin"]
        assert zf.read("HTTP-FEICAR1.bin").startswith(b"X5O!")   # EICAR из фикстуры

    # задача без извлечённых файлов — 404
    d = pipeline.job_dir(cfg, jid) / "zeek" / "extract_files"
    for p in d.iterdir():
        p.unlink()
    assert c.get(f"/jobs/{jid}/files.zip").status_code == 404

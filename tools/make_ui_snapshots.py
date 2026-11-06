#!/usr/bin/env python3
"""Генерирует статические HTML-снимки UI TrafficLens для скриншотов (без запуска сервера).

Запуск из корня репозитория:  python3 tools/make_ui_snapshots.py
Результат — HTML с инлайн-CSS/JS в ./shots/html/ (светлая и тёмная темы,
RU/EN, вкладка «Граф» открыта в report-graph.html).

Скриншоты (macOS, Chrome):
  for f in login-ru login-en index index-dark iocs iocs-dark report report-dark report-en report-graph host chain; do
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
      --disable-gpu --hide-scrollbars --window-size=1440,900 \
      --screenshot="docs/screenshots/ui/$f.png" "file://$PWD/shots/html/$f.html"
  done
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tests import fixtures as fx  # noqa: E402
from trafficlens import config, feeds, pipeline, render, worker  # noqa: E402
from trafficlens.db import DB  # noqa: E402
from trafficlens.web import create_app  # noqa: E402

OUT = REPO / "shots"
DATA = OUT / "data"
HTML = OUT / "html"
STATIC = REPO / "trafficlens" / "static"


def inline_assets(html: str) -> str:
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    app = (STATIC / "app.js").read_text(encoding="utf-8")
    rep = (STATIC / "report.js").read_text(encoding="utf-8")
    html = html.replace('<link rel="stylesheet" href="/static/style.css">', f"<style>{css}</style>")
    html = html.replace('<script src="/static/app.js"></script>', f"<script>{app}</script>")
    html = html.replace('<script src="/static/report.js"></script>', f"<script>{rep}</script>")
    return html


def theme_variant(html: str, theme: str) -> str:
    """Принудительно выставляет тему (иначе страница следует системной)."""
    marker = "<script>(function(){try{var s=localStorage.getItem('tl-theme');"
    if marker in html:
        start = html.index(marker)
        end = html.index("</script>", start) + len("</script>")
        html = html[:start] + (
            f"<script>try{{localStorage.setItem('tl-theme','{theme}')}}catch(e){{}}"
            f"document.documentElement.dataset.theme='{theme}'</script>"
        ) + html[end:]
    return html


def graph_variant(html: str) -> str:
    """Открывает вкладку «Граф» вместо «Сводка»."""
    html = html.replace('class="tab active" data-tab="summary"', 'class="tab" data-tab="summary"')
    html = html.replace('class="tab" data-tab="graph"', 'class="tab active" data-tab="graph"')
    html = html.replace('class="tabpane active" id="tab-summary"', 'class="tabpane" id="tab-summary"')
    html = html.replace('class="tabpane" id="tab-graph"', 'class="tabpane active" id="tab-graph"')
    return html


def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)  # иначе демо-задачи накапливаются
    HTML.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)
    cfg = config.load(str(DATA))
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")

    pcap = DATA / "demo-c2-eicar.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
    jid = "20261105-180000-demo"
    jd = pipeline.job_dir(cfg, jid)
    fx.make_job(jd)
    real = worker.enqueue_file(cfg, db, pcap, "demo-c2-eicar.pcap", "upload", move=False, status="done")
    # переносим готовые логи на реальный id задачи
    shutil.rmtree(pipeline.job_dir(cfg, real), ignore_errors=True)
    shutil.move(str(jd), str(pipeline.job_dir(cfg, real)))
    s = pipeline.rematch(cfg, db, real)
    db.update_job(real, status="done", summary=s)

    app = create_app(cfg, start_workers=False)
    c = app.test_client()
    pages = {
        "index": c.get("/").text,
        "iocs": c.get("/iocs").text,
        "report": c.get(f"/jobs/{real}").text,
        "report-en": c.get(f"/jobs/{real}?lang=en").text,
        "host": c.get(f"/jobs/{real}/host/{fx.WS}?lang=ru").text,
        "chain": c.get(f"/jobs/{real}/chain?lang=ru").text,
    }
    for name, html in pages.items():
        full = inline_assets(html)
        (HTML / f"{name}.html").write_text(theme_variant(full, "light"), encoding="utf-8")
        (HTML / f"{name}-dark.html").write_text(theme_variant(full, "dark"), encoding="utf-8")
    (HTML / "report-graph.html").write_text(
        graph_variant(theme_variant(inline_assets(pages["report"]), "light")), encoding="utf-8")

    cfg["auth"]["password"] = "s3cret"
    app2 = create_app(cfg, start_workers=False)
    c2 = app2.test_client()
    (HTML / "login-ru.html").write_text(theme_variant(inline_assets(c2.get("/login").text), "light"), encoding="utf-8")
    (HTML / "login-en.html").write_text(theme_variant(inline_assets(c2.get("/login?lang=en").text), "dark"), encoding="utf-8")
    print(HTML)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Скриншоты для встроенной инструкции (/help).

Поднимает локальный экземпляр TrafficLens на временных демо-данных (та же
фикстура, что в тестах), снимает страницы в RU и EN через Playwright
(системный Chrome, скачивать chromium не нужно), расставляет номерные
указатели и сохраняет результат в trafficlens/static/help/<lang>/.

Запуск из корня репозитория:
    ./.venv/bin/python tools/make_guide_shots.py

Требования: пакет playwright (pip install playwright) и установленный
Google Chrome (используется channel="chrome"). Сырые снимки без разметки
складываются в shots_raw/ рядом для проверки.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

OUT = ROOT / "trafficlens" / "static" / "help"
RAW = ROOT / "shots_raw"
VIEW_W, VIEW_H = 1440, 1100
DSF = 2  # device_scale_factor: чёткие снимки на Retina

# маркеры: (номер, селектор); префиксы:
#   "closest:.panel|<css>"  — панель, содержащая первый элемент <css>
#   "<css>"                 — первый подходящий элемент
SHOTS = [
    # имя, путь (без ?lang=), JS-подготовка, селектор ожидания, якорь прокрутки, маркеры
    ("01-login", "/login", None, "#username", None,
     [(1, "#username"), (2, "#password"), (3, "button[type=submit]")]),
    ("02-index", "/", "var d=document.querySelector('.pcap-filter'); if(d) d.open=true;", "#jobs-table", None,
     [(1, "#drop"), (2, ".pcap-filter"), (3, "input[name=q]"), (4, "select[name=verdict]"),
      (5, "#jobs-table tbody tr")]),
    ("03-report-top", "/jobs/{job}", None, ".verdict", None,
     [(1, ".verdict"), (2, ".actions"), (3, ".kpis")]),
    ("04-report-hosts", "/jobs/{job}", None, "#t-hosts", "#t-hosts",
     [(1, "closest:.panel|#t-hosts"), (2, "#t-hosts tbody tr"),
      (3, "closest:.panel|a[href*='attack.mitre.org/tactics']")]),
    ("05-host", "/jobs/{job}/host/192.168.1.50", None, "#t-tl", None,
     [(1, ".verdict"), (2, ".kpis"), (3, "a[href*='?flt=']"), (4, "#t-tl"), (5, "#t-ct")]),
    ("06-report-ioc", "/jobs/{job}#ioc", None, "#t-ioc tbody tr", None,
     [(1, "#t-ioc"), (2, "[data-filter=t-ioc]"), (3, "a[href$='export/iocs.csv']"), (4, "#t-ioc .markbtn")]),
    ("07-report-graph", "/jobs/{job}#graph", None, ".netgraph .gnode", None,
     [(1, ".netgraph"), (2, ".gzoom")]),
    ("08-chain", "/jobs/{job}/chain", None, ".chain-tickets", ".chain-tickets",
     [(1, ".chain"), (2, ".chain-tickets")]),
    ("09-iocs", "/iocs", None, "[data-action=ioc-update]", None,
     [(1, "button[data-action=ioc-update].primary"), (2, "button[data-action=rules-update]"),
      (3, "#rulesrc-form"), (4, "#custom-form")]),
]
FULL_PAGE = {"05-host", "09-iocs"}

COLLECT_JS = """(sels) => {
  const find = (sel) => {
    if (sel.startsWith('closest:')) {
      const i = sel.indexOf('|');
      const t = document.querySelector(sel.slice(i + 1));
      return t && t.closest(sel.slice(8, i));
    }
    return document.querySelector(sel);
  };
  const out = [];
  for (const [n, sel] of sels) {
    const el = find(sel);
    if (!el) return {error: 'не найден селектор: ' + sel};
    const r = el.getBoundingClientRect();
    out.push({n, x: r.x, y: r.y, w: r.width, h: r.height, sx: scrollX, sy: scrollY,
              vis: r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth});
  }
  return {out};
}"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_app(job_name: str = "demo-c2-eicar-3.pcap") -> tuple[object, str]:
    """Временный экземпляр с демо-задачей; возвращает (app, job_id)."""
    tmp = Path(tempfile.mkdtemp(prefix="tl-help-"))
    os.environ["TL_DATA_DIR"] = str(tmp)
    from trafficlens import config, feeds, pipeline, worker
    from trafficlens.db import DB
    import fixtures as fx

    cfg = config.load()
    cfg["auth"]["password"] = ""  # без авторизации: /login всё равно рендерится
    db = DB(cfg.db_path)
    (cfg.custom_ioc_dir / "investigation.txt").write_text(fx.CUSTOM_IOCS, encoding="utf-8")
    feeds.update_all(cfg, db, only="custom")
    jid = None
    for name in ("demo-c2-eicar-1.pcap", "demo-c2-eicar-2.pcap", job_name):
        pcap = tmp / name
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
        jid = worker.enqueue_file(cfg, db, pcap, name, "upload", move=False)
        fx.make_job(pipeline.job_dir(cfg, jid))
        pipeline.rematch(cfg, db, jid)
        db.update_job(jid, status="done")
    from trafficlens.web import create_app
    return create_app(cfg, start_workers=False), jid


def annotate(png: Path, markers: list[dict], out: Path, page_coords: bool = False) -> None:
    """Рамки и номерные кружки поверх снимка (координаты — CSS px, картинка ×DSF).

    Для обычных снимков координаты вьюпорт-относительные, для full_page —
    абсолютные по странице (x+scrollX, y+scrollY).
    """
    from PIL import Image, ImageDraw, ImageFont

    im = Image.open(png).convert("RGB")
    dr = ImageDraw.Draw(im)
    font = ImageFont.load_default(size=26 * DSF // 2)
    color = (217, 48, 37)  # красный указатель
    for m in markers:
        mx = m["x"] + (m["sx"] if page_coords else 0)
        my = m["y"] + (m["sy"] if page_coords else 0)
        x0 = max(0, mx * DSF - 8 * DSF)
        y0 = max(0, my * DSF - 8 * DSF)
        x1 = min(im.width, (mx + m["w"]) * DSF + 8 * DSF)
        y1 = min(im.height, (my + m["h"]) * DSF + 8 * DSF)
        dr.rounded_rectangle([x0, y0, x1, y1], radius=8 * DSF, outline=color, width=3 * DSF)
        # кружок с номером — центром на угол рамки, чтобы не закрывать содержимое
        r = 16 * DSF
        cx, cy = max(r, x0), max(r, y0)
        dr.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color, outline=(255, 255, 255), width=DSF)
        t = str(m["n"])
        tb = dr.textbbox((0, 0), t, font=font)
        dr.text((cx - (tb[2] - tb[0]) / 2 - tb[0], cy - (tb[3] - tb[1]) / 2 - tb[1]), t,
                fill=(255, 255, 255), font=font)
    out.parent.mkdir(parents=True, exist_ok=True)
    im.save(out, optimize=True)


def main() -> None:
    from playwright.sync_api import sync_playwright
    from werkzeug.serving import make_server

    app, jid = make_app()
    port = free_port()
    srv = make_server("127.0.0.1", port, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    RAW.mkdir(exist_ok=True)
    print(f"демо-экземпляр на {base}, задача {jid}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome")
            ctx = browser.new_context(viewport={"width": VIEW_W, "height": VIEW_H},
                                      device_scale_factor=DSF)
            page = ctx.new_page()
            for lang in ("ru", "en"):
                for name, path, prep, wait, anchor, sels in SHOTS:
                    p_, _, frag = path.format(job=jid).partition("#")
                    url = f"{base}{p_}?lang={lang}" + (f"#{frag}" if frag else "")
                    page.goto(url, wait_until="networkidle")
                    if prep:
                        page.evaluate(prep)
                    page.wait_for_selector(wait, timeout=10000)
                    page.wait_for_timeout(300)
                    page.evaluate("scrollTo(0, 0)")
                    if anchor:
                        page.evaluate("(a) => { const el = document.querySelector(a);"
                                      " if (el) scrollTo(0, el.getBoundingClientRect().top + scrollY - 175); }", anchor)
                        page.wait_for_timeout(150)
                    res = page.evaluate(COLLECT_JS, [[n, s] for n, s in sels])
                    if "error" in res:
                        raise RuntimeError(f"{name} ({lang}): {res['error']}")
                    raw = RAW / f"{lang}-{name}.png"
                    page.screenshot(path=str(raw), full_page=name in FULL_PAGE)
                    markers = res["out"]
                    if name not in FULL_PAGE:
                        bad = [m["n"] for m in markers if not m["vis"]]
                        if bad:
                            raise RuntimeError(f"{name} ({lang}): маркеры вне вьюпорта: {bad}")
                    annotate(raw, markers, OUT / lang / f"{name}.png", page_coords=name in FULL_PAGE)
                    print(f"  {lang}/{name}.png — {len(markers)} указателя")
            browser.close()
    finally:
        srv.shutdown()
    print(f"готово: {OUT}")


if __name__ == "__main__":
    main()

"""PDF-экспорт отчёта (reportlab). Конденсированная версия HTML-отчёта, язык — RU/EN."""
from __future__ import annotations

import io
import os

from .i18n import bundle as i18n_bundle
from .render import fmt_bytes, fmt_dur, fmt_ts, loc_ctx, loc_dir, loc_ioc, loc_reason, loc_sev

# Порядок поиска TTF с кириллилцей: переменная окружения, контейнер (fonts-dejavu-core), macOS.
_FONT_CANDIDATES = (
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
)

LEVEL_COLORS = {"critical": "#c0392b", "suspicious": "#b9770e", "clean": "#1e8449"}


def _fonts() -> tuple[str, str]:
    """Зарегистрировать TTF с кириллицей; фолбэк — встроенный Helvetica (кириллица не рисуется)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    env_font = os.environ.get("TL_PDF_FONT", "")
    env_bold = os.environ.get("TL_PDF_FONT_BOLD", "") or env_font
    pairs = [(env_font, env_bold)] if env_font else []
    pairs += _FONT_CANDIDATES
    for regular, bold in pairs:
        if os.path.exists(regular):
            try:
                pdfmetrics.registerFont(TTFont("TL", regular))
                pdfmetrics.registerFont(TTFont("TL-B", bold if os.path.exists(bold) else regular))
                return "TL", "TL-B"
            except Exception:  # noqa: BLE001 — битый TTF не должен ронять экспорт
                continue
    return "Helvetica", "Helvetica-Bold"


def render_pdf(rep: dict, lang: str = "ru") -> bytes:
    """Сформировать PDF отчёта. Возвращает bytes."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    L = i18n_bundle(lang)
    font, bold = _fonts()
    st = ParagraphStyle("base", fontName=font, fontSize=8.5, leading=11)
    st_b = ParagraphStyle("base-b", parent=st, fontName=bold)
    st_h = ParagraphStyle("h", parent=st_b, fontSize=11, spaceBefore=10, spaceAfter=4)
    st_title = ParagraphStyle("title", parent=st_b, fontSize=16, spaceAfter=2)
    st_small = ParagraphStyle("small", parent=st, fontSize=7.5, textColor=colors.HexColor("#666666"))

    def P(text, style=st) -> Paragraph:
        # Paragraph понимает мини-HTML: экранируем данные отчёта
        t = str(text if text not in (None, "") else "—")
        t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return Paragraph(t, style)

    def table(header: list, rows: list[list], widths=None) -> Table:
        data = [[P(h, st_b) for h in header]] + [[P(c) for c in row] for row in rows]
        tbl = Table(data, colWidths=widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f3")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c9d1d6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        return tbl

    meta = rep.get("meta", {})
    t = rep.get("totals", {})
    v = rep.get("verdict", {})
    f = rep.get("findings", {})
    period = meta.get("period", {})
    el = []

    # ---- шапка
    el.append(P(meta.get("filename", "report"), st_title))
    el.append(P(f"{L['traffic']}: {fmt_ts(period.get('start'))} — {fmt_ts(period.get('end'))} "
                f"({fmt_dur(period.get('duration'), lang)}) · {L['report_at']} {fmt_ts(meta.get('generated'))}", st_small))

    # ---- вердикт
    level = v.get("level", "clean")
    label = L.get("verdict_label_" + level, v.get("label", level))
    if v.get("score"):
        label += f" · score {v['score']}"
    el.append(Spacer(1, 4 * mm))
    vtbl = Table([[P(("!!! " if level == "critical" else "") + label, ParagraphStyle(
        "verdict", parent=st_b, fontSize=11, textColor=colors.white))]],
        colWidths=[180 * mm])
    vtbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(LEVEL_COLORS.get(level, "#888"))),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    el.append(vtbl)
    reasons = [loc_reason(L, x) for x in v.get("reasons") or []]
    if reasons:
        el.append(P(" · ".join(reasons), st_small))
    else:
        el.append(P(L["no_hits_banner"].format(n=meta.get("ioc_count", 0)), st_small))

    # ---- KPI
    kpis = [
        (L["kpi_ioc"], t.get("ioc_hits", 0)), (L["kpi_alerts"], t.get("alerts", 0)),
        (L["kpi_files"], t.get("files", 0)), (L["kpi_conns"], t.get("conns", 0)),
        (L["kpi_bytes"], fmt_bytes(t.get("bytes"), lang)),
        (L["kpi_hosts"], f"{t.get('hosts_local', 0)} / {t.get('hosts_external', 0)}"),
        (L["kpi_dns"], t.get("dns", 0)), (L["kpi_http_tls"], f"{t.get('http', 0)} / {t.get('tls', 0)}"),
    ]
    el.append(Spacer(1, 3 * mm))
    el.append(table([k for k, _ in kpis], [[v_ for _, v_ in kpis]]))

    # ---- приоритетные хосты
    if rep.get("priority_hosts"):
        el.append(P(L["ph_title"], st_h))
        el.append(table(
            [L["col_host"], "Risk score", L["col_reasons"], L["col_external"]],
            [[f"{h.get('ip')}" + (f"\n{h.get('name')}" if h.get("name") else ""),
              h.get("score", ""),
              "\n".join(loc_reason(L, x) for x in h.get("reasons", [])),
              ", ".join(h.get("external", []))]
             for h in rep["priority_hosts"][:20]],
            widths=[35 * mm, 18 * mm, 77 * mm, 50 * mm]))

    # ---- IOC
    el.append(P(L["ioc_hits_title"], st_h))
    hits = rep.get("ioc_hits") or []
    if hits:
        el.append(table(
            [L["col_type"], L["col_indicator"], L["col_context"], L["col_sources"], L["col_times"]],
            [[loc_ioc(L, h.get("type"), h.get("type_label")),
              h.get("value", ""),
              ", ".join(loc_ctx(L, c) for c in (h.get("contexts") or {})),
              "; ".join((s.get("source") or "") for s in (h.get("sources") or [])[:3]),
              h.get("count", 0)]
             for h in hits[:100]],
            widths=[22 * mm, 55 * mm, 45 * mm, 40 * mm, 18 * mm]))
    else:
        el.append(P(f"{L['no_ioc_hits']} ({meta.get('ioc_count', 0)} {L['indicators_n']})"))

    # ---- сигнатуры
    el.append(P(L["alerts_title"], st_h))
    alerts = rep.get("alerts") or []
    if alerts:
        el.append(table(
            [L["col_severity"], L["col_signature"], L["col_category"], L["col_times"]],
            [[loc_sev(L, a.get("severity"), a.get("sev_label")),
              f"{a.get('signature', '')} (sid {a.get('sid')})", a.get("category", ""), a.get("count", 0)]
             for a in alerts[:100]],
            widths=[20 * mm, 95 * mm, 45 * mm, 20 * mm]))
    else:
        el.append(P(L["no_alerts"]))

    # ---- файлы
    files = rep.get("files") or []
    if files:
        el.append(P(L["files_title"], st_h))
        el.append(table(
            [L["col_time"], L["col_sender_receiver"], L["col_direction"], L["col_name_url"], L["col_size"]],
            [[fmt_ts(x.get("ts"), "%d.%m %H:%M:%S"),
              f"{x.get('sender')} → {x.get('receiver')}",
              loc_dir(L, x.get("direction")),
              (x.get("filename") or "—") + (" [IOC]" if x.get("ioc") else ""),
              fmt_bytes(x.get("size"), lang)]
             for x in files[:100]],
            widths=[26 * mm, 50 * mm, 25 * mm, 59 * mm, 20 * mm]))

    # ---- аномалии
    def finding(title: str, header: list, rows: list[list], widths=None):
        if not rows:
            return
        el.append(P(title, st_h))
        el.append(table(header, rows, widths))

    finding(L["beacons_title"],
            [L["col_src"], L["col_dst"], L["col_conns"], L["col_interval"]],
            [[b.get("src"), f"{b.get('dst')}:{b.get('dp')}", b.get("count"), fmt_dur(b.get("interval"), lang)]
             for b in (f.get("beacons") or [])[:50]])
    finding(L["uploads_title"],
            [L["col_src"], L["col_receiver"], L["col_sent"], L["col_conns_short"]],
            [[u.get("src"), u.get("dst"), fmt_bytes(u.get("bytes"), lang), u.get("conns")]
             for u in (f.get("large_uploads") or [])[:50]])
    finding(L["cleartext_title"],
            [L["col_proto"], L["col_client_server"], L["col_user_count"]],
            [[c.get("proto"), f"{c.get('src')} → {c.get('dst')}", c.get("user")]
             for c in (f.get("cleartext_auth") or [])[:50]])
    finding(L["tls_invalid_title"],
            [L["col_client"], L["col_server"], "SNI", L["col_verify"]],
            [[x.get("src"), x.get("dst"), x.get("sni") or "—", x.get("status")]
             for x in (rep.get("tls", {}).get("invalid") or [])[:50]])
    finding(L["dns_suspicious_t"],
            [L["col_name"], L["col_reason"], L["col_times"]],
            [[d.get("name"), loc_reason(L, d.get("reason")), d.get("count")]
             for d in (rep.get("dns", {}).get("suspicious") or [])[:50]],
            widths=[50 * mm, 100 * mm, 30 * mm])

    # ---- внешние адреса
    ext = rep.get("top_external") or []
    if ext:
        el.append(P(L["ext_title"], st_h))
        el.append(table(
            [L["col_address"], L["col_bytes"], L["col_conns"], L["col_ports"]],
            [[e.get("ip") + (" [IOC]" if e.get("ioc") else "") + (f"\n{e.get('name')}" if e.get("name") else ""),
              fmt_bytes(e.get("bytes"), lang), e.get("conns"), " ".join(e.get("ports", [])[:5])]
             for e in ext[:50]],
            widths=[60 * mm, 30 * mm, 25 * mm, 65 * mm]))

    el.append(Spacer(1, 6 * mm))
    el.append(P(L["generated_by"], st_small))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm,
                            title=f"TrafficLens — {meta.get('filename', 'report')}")
    doc.build(el)
    return buf.getvalue()

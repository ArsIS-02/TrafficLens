/* Вкладки, фильтрация и сортировка таблиц, копирование — работает и в автономном отчёте. */
(function () {
  function showTab(id) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === id));
    document.querySelectorAll(".tabpane").forEach(p => p.classList.toggle("active", p.id === "tab-" + id));
    try { history.replaceState(null, "", "#" + id); } catch (e) { /* file:// */ }
  }
  document.addEventListener("click", e => {
    const t = e.target.closest(".tab");
    if (t) { showTab(t.dataset.tab); return; }
    const exb = e.target.closest("#export-iocs-btn");
    if (exb) {
      e.preventDefault();
      const I = window.TL_I18N || {};
      exb.disabled = true;
      fetch(`/api/jobs/${exb.dataset.job}/export-iocs`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "TrafficLens" },
        body: "{}",
      }).then(r => r.json().catch(() => ({}))).then(r => {
        exb.disabled = false;
        if (!window.TL || !TL.toast) return;
        if (r.ok) {
          TL.toast((I.export_iocs_done || "added {added}, dup {dup}, skipped {skipped}")
            .replace("{added}", r.added ?? 0).replace("{dup}", r.dup ?? 0).replace("{skipped}", r.skipped ?? 0));
        } else {
          TL.toast(r.error || "error", true);
        }
      }).catch(() => { exb.disabled = false; if (window.TL && TL.toast) TL.toast("network error", true); });
      return;
    }
    const go = e.target.closest("[data-goto]");
    if (go) { e.preventDefault(); showTab(go.dataset.goto); window.scrollTo({ top: 0 }); return; }
    const c = e.target.closest(".copy");
    if (c && navigator.clipboard) {
      navigator.clipboard.writeText(c.dataset.copy || c.textContent.trim()).then(() => {
        if (window.TL && TL.toast) TL.toast((window.TL_I18N || {}).copied || "OK");
      }).catch(() => {});
    }
  });

  // контекстное меню по значениям (.copy): копировать / проверить на VirusTotal
  let ctxMenu = null;
  function closeCtxMenu() { if (ctxMenu) { ctxMenu.remove(); ctxMenu = null; } }
  document.addEventListener("contextmenu", e => {
    const c = e.target.closest(".copy");
    if (!c) return;
    e.preventDefault();
    closeCtxMenu();
    const v = (c.dataset.copy || c.textContent).trim();
    if (!v) return;
    const I = window.TL_I18N || {};
    ctxMenu = document.createElement("div");
    ctxMenu.className = "ctx-menu";
    const mk = (label, fn) => {
      const b = document.createElement("button");
      b.type = "button"; b.textContent = label;
      b.addEventListener("click", () => { closeCtxMenu(); fn(); });
      ctxMenu.appendChild(b);
    };
    mk(I.copy_label || "Копировать", () => { if (navigator.clipboard) navigator.clipboard.writeText(v).catch(() => {}); });
    mk(I.vt_check || "Проверить на VirusTotal", () => window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(v), "_blank", "noopener"));
    // блокировка IP/домена в BlockBoard (пульт сам проверит тип индикатора)
    const BB = window.TL_BLOCKBOARD_URL || "https://blockboard.apps.monitoring.test/";
    mk(I.bb_block || "Заблокировать в BlockBoard", () => window.open(BB + "?block=" + encodeURIComponent(v) + "&reason=" + encodeURIComponent("TrafficLens"), "_blank", "noopener"));
    document.body.appendChild(ctxMenu);
    ctxMenu.style.left = Math.max(4, Math.min(e.clientX, window.innerWidth - ctxMenu.offsetWidth - 8)) + "px";
    ctxMenu.style.top = Math.max(4, Math.min(e.clientY, window.innerHeight - ctxMenu.offsetHeight - 8)) + "px";
  });
  document.addEventListener("click", closeCtxMenu);
  document.addEventListener("scroll", closeCtxMenu, true);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeCtxMenu(); });

  // ---------- разметка находок аналитиком (только во встроенном отчёте)
  const JOB = document.body.dataset.job || "";
  function paintMark(btn, status, wl) {
    const td = btn.closest("td");
    const I = window.TL_I18N || {};
    td.querySelectorAll("[data-mstatus-badge]").forEach(x => x.remove());
    if (status && status !== "new") {
      const s = document.createElement("span");
      s.className = "badge " + (status === "confirmed" ? "ok" : status === "false_positive" ? "warn" : "");
      s.dataset.mstatusBadge = "1";
      s.textContent = I["mark_" + status] || status;
      td.insertBefore(s, btn);
    }
    btn.dataset.mstatus = status || "new";
    const tr = btn.closest("tr");
    if (tr) { tr.classList.toggle("marked-fp", status === "false_positive"); tr.classList.toggle("marked-ig", status === "ignored"); }
    let wlb = td.querySelector("[data-mwl-badge]");
    if (wl && !wlb) {
      wlb = document.createElement("span");
      wlb.className = "badge accent"; wlb.dataset.mwlBadge = "1"; wlb.textContent = "WL"; wlb.title = I.mark_wl_title || "allowlist";
      td.insertBefore(wlb, btn);
    } else if (!wl && wlb) { wlb.remove(); }
    btn.dataset.mwl = wl ? "1" : "0";
  }
  async function postJSON(url, obj) {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Requested-With": "TrafficLens" },
      body: JSON.stringify(obj),
    });
    return r.json().catch(() => ({}));
  }
  document.addEventListener("click", e => {
    const btn = e.target.closest(".markbtn");
    if (!btn || !JOB) return;
    e.preventDefault();
    closeCtxMenu();
    const I = window.TL_I18N || {};
    const kind = btn.dataset["mkind"];
    const key = btn.dataset["mkey"];
    const cur = btn.dataset.mstatus || "new", wl = btn.dataset.mwl === "1";
    ctxMenu = document.createElement("div");
    ctxMenu.className = "ctx-menu";
    const mk = (label, fn, active) => {
      const b = document.createElement("button");
      b.type = "button"; b.textContent = (active ? "✓ " : "") + label;
      b.addEventListener("click", async () => {
        closeCtxMenu();
        await fn();
      });
      ctxMenu.appendChild(b);
    };
    const setStatus = st => async () => {
      const r = await postJSON(`/api/jobs/${JOB}/marks`, { kind, key, status: st });
      if (r.ok) {
        paintMark(btn, st, btn.dataset.mwl === "1");
        if (window.TL && TL.toast) TL.toast((I.mark_saved || "OK") + (r.summary ? `: ${r.summary.verdict_label || ""}` : ""));
      } else if (window.TL && TL.toast) TL.toast(r.error || "error", true);
    };
    mk(I.mark_confirmed || "Confirmed", setStatus("confirmed"), cur === "confirmed");
    mk(I.mark_false_positive || "False positive", setStatus("false_positive"), cur === "false_positive");
    mk(I.mark_ignored || "Ignored", setStatus("ignored"), cur === "ignored");
    if (cur !== "new") mk(I.mark_reset || "Reset", setStatus("new"));
    mk(wl ? (I.mark_wl_del || "Remove from allowlist") : (I.mark_wl_add || "Add to allowlist"), async () => {
      const r = await postJSON("/api/allowlist", { kind, key, action: wl ? "del" : "add", job_id: JOB });
      if (r.ok) {
        paintMark(btn, btn.dataset.mstatus || "new", !wl);
        if (window.TL && TL.toast) TL.toast(I.mark_saved || "OK");
      } else if (window.TL && TL.toast) TL.toast(r.error || "error", true);
    }, wl);
    document.body.appendChild(ctxMenu);
    ctxMenu.style.left = Math.max(4, Math.min(e.clientX, window.innerWidth - ctxMenu.offsetWidth - 8)) + "px";
    ctxMenu.style.top = Math.max(4, Math.min(e.clientY, window.innerHeight - ctxMenu.offsetHeight - 8)) + "px";
  });
  function fromHash() {
    const h = (location.hash || "").slice(1);
    if (h && document.getElementById("tab-" + h)) showTab(h);
  }
  window.addEventListener("hashchange", fromHash);
  fromHash();

  // фильтр: <input class="filter" data-filter="table-id">
  document.querySelectorAll("input.filter").forEach(inp => {
    inp.addEventListener("input", () => {
      const q = inp.value.trim().toLowerCase();
      const tb = document.getElementById(inp.dataset.filter);
      if (!tb) return;
      tb.querySelectorAll("tbody tr").forEach(tr => {
        tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    });
  });

  // предзаполнение фильтров активной вкладки из ?flt= (переходы из карточки хоста)
  // важно: после навешивания обработчиков выше, иначе событие input уйдёт в никуда
  (function applyPreFilter() {
    const flt = new URLSearchParams(location.search).get("flt");
    if (!flt) return;
    const pane = document.querySelector(".tabpane.active");
    (pane || document).querySelectorAll("input.filter").forEach(inp => {
      inp.value = flt;
      inp.dispatchEvent(new Event("input"));
    });
  })();

  // сортировка по клику на заголовок (th[data-sort] = num|text)
  document.querySelectorAll("table").forEach(tbl => {
    tbl.querySelectorAll("th[data-sort]").forEach((th, _) => {
      th.addEventListener("click", () => {
        const idx = Array.from(th.parentNode.children).indexOf(th);
        const num = th.dataset.sort === "num";
        const asc = !th.classList.contains("sorted-asc");
        tbl.querySelectorAll("th").forEach(x => x.classList.remove("sorted-asc", "sorted-desc"));
        th.classList.add(asc ? "sorted-asc" : "sorted-desc");
        const body = tbl.tBodies[0];
        const rows = Array.from(body.rows);
        const key = r => {
          const cell = r.cells[idx];
          if (!cell) return "";
          const v = cell.dataset.v !== undefined ? cell.dataset.v : cell.textContent.trim();
          return num ? parseFloat(v) || 0 : v.toLowerCase();
        };
        rows.sort((a, b) => { const x = key(a), y = key(b); return (x > y ? 1 : x < y ? -1 : 0) * (asc ? 1 : -1); });
        rows.forEach(r => body.appendChild(r));
      });
    });
  });
  // ---------- сетевой граф
  function initGraph() {
    const svg = document.getElementById("netgraph");
    const raw = document.getElementById("graph-data");
    if (!svg || !raw) return;
    let g = { nodes: [], links: [] };
    try { g = JSON.parse(raw.textContent); } catch (e) { }
    const NS = "http://www.w3.org/2000/svg";
    const nodes = new Map();
    const locals = (g.nodes || []).filter(n => n.local);
    const externals = (g.nodes || []).filter(n => !n.local);
    const maxB = Math.max(1, ...(g.nodes || []).map(n => n.bytes || 0), ...(g.links || []).map(l => l.bytes || 0));
    const place = (list, x) => list.forEach((n, i) => {
      const y = 60 + (list.length <= 1 ? 220 : i * (440 / (list.length - 1)));
      nodes.set(n.id, { ...n, x, y });
    });
    place(locals, 130); place(externals, 850);
    function el(name, attrs) { const e = document.createElementNS(NS, name); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }

    // все содержимое — в viewport-группе: pan/zoom через transform
    const view = { x: 0, y: 0, k: 1 };
    const vp = el("g", { id: "graph-vp" });
    const applyView = () => vp.setAttribute("transform", `translate(${view.x} ${view.y}) scale(${view.k})`);
    svg.appendChild(vp);
    applyView();

    const edges = [];
    (g.links || []).forEach(l => {
      const a = nodes.get(l.source), b = nodes.get(l.target);
      if (!a || !b) return;
      const w = 1 + Math.sqrt((l.bytes || 0) / maxB) * 7;
      const line = el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge" + (l.ioc ? " ioc" : ""), "stroke-width": w.toFixed(1) });
      line.appendChild(el("title", {})).textContent = `${l.source} → ${l.target}:${l.port || ""} ${l.proto || ""} ${l.bytes} B`;
      vp.appendChild(line);
      edges.push({ line, s: l.source, t: l.target });
    });
    nodes.forEach(n => {
      const r = 5 + Math.sqrt((n.bytes || 0) / maxB) * 10;
      const grp = el("g", { class: "gnode", transform: `translate(${n.x} ${n.y})`, "data-id": n.id });
      const c = el("circle", { cx: 0, cy: 0, r: r.toFixed(1), class: "node" + (n.local ? " local" : "") + (n.ioc ? " ioc" : "") });
      c.appendChild(el("title", {})).textContent = `${n.id}${n.name ? " · " + n.name : ""}`;
      grp.appendChild(c);
      const label = el("text", { x: n.local ? 14 : -14, y: 4, "text-anchor": n.local ? "start" : "end" });
      label.textContent = n.name || n.id;
      grp.appendChild(label);
      vp.appendChild(grp);
      n.grp = grp;
    });
    if (!nodes.size) {
      const t = el("text", { x: 500, y: 280, "text-anchor": "middle" });
      t.textContent = "—";
      vp.appendChild(t);
    }

    // координаты курсора в системе графа (с учётом pan/zoom)
    const toGraph = e => {
      const pt = svg.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY;
      const m = vp.getScreenCTM();
      return m ? pt.matrixTransform(m.inverse()) : pt;
    };
    const zoomAt = (p, factor) => {
      const k2 = Math.min(8, Math.max(0.25, view.k * factor));
      view.x += (view.k - k2) * p.x;
      view.y += (view.k - k2) * p.y;
      view.k = k2;
      applyView();
    };
    svg.addEventListener("wheel", e => {
      e.preventDefault();
      zoomAt(toGraph(e), e.deltaY < 0 ? 1.2 : 1 / 1.2);
    }, { passive: false });
    // кнопки +/−/сброс в шапке панели (шаблон report.html)
    document.querySelectorAll("[data-gzoom]").forEach(b => b.addEventListener("click", () => {
      const z = b.dataset.gzoom;
      if (z === "0") { view.x = 0; view.y = 0; view.k = 1; applyView(); return; }
      zoomAt({ x: 500, y: 280 }, z === "+" ? 1.4 : 1 / 1.4);
    }));

    // перетаскивание узлов и панорама фона
    let drag = null, pan = null;
    svg.addEventListener("pointerdown", e => {
      const grp = e.target.closest(".gnode");
      if (grp) {
        const n = nodes.get(grp.dataset.id);
        if (!n) return;
        e.preventDefault();
        const p = toGraph(e);
        drag = { n, dx: p.x - n.x, dy: p.y - n.y };
        grp.classList.add("drag");
      } else {
        pan = { sx: e.clientX, sy: e.clientY };
        svg.classList.add("panning");
      }
      try { svg.setPointerCapture(e.pointerId); } catch (err) { }
    });
    svg.addEventListener("pointermove", e => {
      if (drag) {
        const p = toGraph(e);
        drag.n.x = Math.max(30, Math.min(970, p.x - drag.dx));
        drag.n.y = Math.max(20, Math.min(540, p.y - drag.dy));
        drag.n.grp.setAttribute("transform", `translate(${drag.n.x} ${drag.n.y})`);
        edges.forEach(ed => {
          if (ed.s === drag.n.id) { ed.line.setAttribute("x1", drag.n.x); ed.line.setAttribute("y1", drag.n.y); }
          if (ed.t === drag.n.id) { ed.line.setAttribute("x2", drag.n.x); ed.line.setAttribute("y2", drag.n.y); }
        });
      } else if (pan) {
        const m = vp.getScreenCTM();
        const k = (m && m.a) || 1;  // экранных пикселей на единицу графа
        view.x += (e.clientX - pan.sx) / k;
        view.y += (e.clientY - pan.sy) / k;
        pan.sx = e.clientX; pan.sy = e.clientY;
        applyView();
      }
    });
    const drop = () => {
      if (drag) { drag.n.grp.classList.remove("drag"); drag = null; }
      if (pan) { pan = null; svg.classList.remove("panning"); }
    };
    svg.addEventListener("pointerup", drop);
    svg.addEventListener("pointercancel", drop);
  }

  document.addEventListener("DOMContentLoaded", initGraph);
})();

/* служебные файлы TLS свёрнуты в таблице «Файлы» */
document.addEventListener("click", function (e) {
  const b = e.target.closest("[data-toggle-svc]");
  if (!b) return;
  const tb = document.getElementById(b.dataset.toggleSvc);
  if (!tb) return;
  tb.hidden = !tb.hidden;
  b.textContent = (tb.hidden ? "▸ " : "▾ ") + b.textContent.replace(/^[▸▾]\s*/, "");
});

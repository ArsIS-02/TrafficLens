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
    const go = e.target.closest("[data-goto]");
    if (go) { e.preventDefault(); showTab(go.dataset.goto); window.scrollTo({ top: 0 }); return; }
    const c = e.target.closest(".copy");
    if (c && navigator.clipboard) {
      navigator.clipboard.writeText(c.dataset.copy || c.textContent.trim()).then(() => {
        if (window.TL && TL.toast) TL.toast((window.TL_I18N || {}).copied || "OK");
      }).catch(() => {});
    }
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
    const edges = [];
    (g.links || []).forEach(l => {
      const a = nodes.get(l.source), b = nodes.get(l.target);
      if (!a || !b) return;
      const w = 1 + Math.sqrt((l.bytes || 0) / maxB) * 7;
      const line = el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge" + (l.ioc ? " ioc" : ""), "stroke-width": w.toFixed(1) });
      line.appendChild(el("title", {})).textContent = `${l.source} → ${l.target}:${l.port || ""} ${l.proto || ""} ${l.bytes} B`;
      svg.appendChild(line);
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
      svg.appendChild(grp);
      n.grp = grp;
    });
    if (!nodes.size) {
      const t = el("text", { x: 500, y: 280, "text-anchor": "middle" });
      t.textContent = "—";
      svg.appendChild(t);
      return;
    }
    // перетаскивание узлов
    let drag = null;
    const toSvg = e => {
      const pt = svg.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY;
      const m = svg.getScreenCTM();
      return m ? pt.matrixTransform(m.inverse()) : pt;
    };
    svg.addEventListener("pointerdown", e => {
      const grp = e.target.closest(".gnode");
      if (!grp) return;
      const n = nodes.get(grp.dataset.id);
      if (!n) return;
      e.preventDefault();
      const p = toSvg(e);
      drag = { n, dx: p.x - n.x, dy: p.y - n.y };
      try { svg.setPointerCapture(e.pointerId); } catch (err) { }
      grp.classList.add("drag");
    });
    svg.addEventListener("pointermove", e => {
      if (!drag) return;
      const p = toSvg(e);
      drag.n.x = Math.max(30, Math.min(970, p.x - drag.dx));
      drag.n.y = Math.max(20, Math.min(540, p.y - drag.dy));
      drag.n.grp.setAttribute("transform", `translate(${drag.n.x} ${drag.n.y})`);
      edges.forEach(ed => {
        if (ed.s === drag.n.id) { ed.line.setAttribute("x1", drag.n.x); ed.line.setAttribute("y1", drag.n.y); }
        if (ed.t === drag.n.id) { ed.line.setAttribute("x2", drag.n.x); ed.line.setAttribute("y2", drag.n.y); }
      });
    });
    const drop = () => { if (drag) { drag.n.grp.classList.remove("drag"); drag = null; } };
    svg.addEventListener("pointerup", drop);
    svg.addEventListener("pointercancel", drop);
  }

  document.addEventListener("DOMContentLoaded", initGraph);
})();

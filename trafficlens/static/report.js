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
        if (window.TL && TL.toast) TL.toast("Скопировано");
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
})();

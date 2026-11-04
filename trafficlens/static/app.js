/* TrafficLens UI: собственные диалоги (без alert/confirm), уведомления, API, загрузка, обновление списка. */
window.TL = (function () {
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  function dialog({ title, message, ok = "OK", cancel = null, danger = false }) {
    return new Promise(resolve => {
      const back = el("div", "modal-back");
      const m = el("div", "modal");
      m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
      m.appendChild(el("h3", null, title || "TrafficLens"));
      if (message) m.appendChild(el("div", "body", message));
      const btns = el("div", "buttons");
      const close = v => { document.removeEventListener("keydown", onKey); back.remove(); resolve(v); };
      if (cancel) { const c = el("button", "btn", cancel); c.onclick = () => close(false); btns.appendChild(c); }
      const o = el("button", "btn " + (danger ? "danger solid" : "primary"), ok); o.onclick = () => close(true); btns.appendChild(o);
      m.appendChild(btns); back.appendChild(m);
      back.addEventListener("mousedown", e => { if (e.target === back) close(false); });
      function onKey(e) { if (e.key === "Escape") close(false); if (e.key === "Enter") close(true); }
      document.addEventListener("keydown", onKey);
      document.body.appendChild(back); o.focus();
    });
  }
  const confirm = (message, opts = {}) => dialog({ title: opts.title || "Подтверждение", message, ok: opts.ok || "Да", cancel: "Отмена", danger: !!opts.danger });
  const alert = (message, opts = {}) => dialog({ title: opts.title || "Сообщение", message, ok: "Понятно" });

  let toastBox;
  function toast(text, err = false) {
    if (!toastBox) { toastBox = el("div", "toasts"); document.body.appendChild(toastBox); }
    const t = el("div", "toast" + (err ? " err" : ""), text); toastBox.appendChild(t);
    setTimeout(() => t.remove(), err ? 6000 : 2800);
  }

  async function api(url, { method = "POST", body = null } = {}) {
    const opts = { method, headers: { "X-Requested-With": "TrafficLens" } };
    if (body !== null) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    let data = {};
    try { data = await r.json(); } catch (e) { /* не JSON */ }
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }

  // действия по data-action на кнопках
  document.addEventListener("click", async e => {
    const b = e.target.closest("[data-action]");
    if (!b) return;
    e.preventDefault();
    const a = b.dataset.action, job = b.dataset.job;
    try {
      if (a === "delete-job") {
        if (!await confirm("Удалить задачу " + job + " вместе с PCAP, логами и отчётом?", { danger: true, ok: "Удалить" })) return;
        await api(`/api/jobs/${job}/delete`); toast("Задача удалена");
        if (b.dataset.back) location.href = "/"; else b.closest("tr")?.remove();
      } else if (a === "rematch") {
        b.disabled = true; await api(`/api/jobs/${job}/rematch`); toast("Отчёт пересобран с актуальными IOC"); setTimeout(() => location.reload(), 600);
      } else if (a === "rerun") {
        if (!await confirm("Запустить полный повторный анализ (Zeek + Suricata)?", { ok: "Запустить" })) return;
        await api(`/api/jobs/${job}/rerun`); location.href = "/jobs/" + job;
      } else if (a === "ioc-update") {
        b.disabled = true; await api("/api/iocs/update", { body: { source: b.dataset.source || null } });
        toast("Обновление IOC запущено"); pollStatus();
      } else if (a === "rules-update") {
        b.disabled = true; await api("/api/rules/update"); toast("Обновление правил Suricata запущено"); pollStatus();
      } else if (a === "logout") {
        await api("/logout"); location.href = "/login";
      }
    } catch (err) { b.disabled = false; alert(err.message, { title: "Ошибка" }); }
  });

  function pollStatus() {
    const tick = async () => {
      try {
        const s = await api("/api/status", { method: "GET" });
        if (s.state.busy.length) { setTimeout(tick, 2500); return; }
        toast("Готово"); setTimeout(() => location.reload(), 500);
      } catch (e) { setTimeout(tick, 4000); }
    };
    setTimeout(tick, 1500);
  }

  // ---------- загрузка PCAP
  function initUpload() {
    const drop = document.getElementById("drop"); if (!drop) return;
    const input = document.getElementById("file");
    const bar = document.querySelector(".progress"), fill = bar?.firstElementChild;
    drop.addEventListener("click", () => input.click());
    ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", e => send(e.dataTransfer.files));
    input.addEventListener("change", () => send(input.files));
    function send(files) {
      if (!files || !files.length) return;
      const fd = new FormData(); Array.from(files).forEach(f => fd.append("file", f));
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload"); xhr.setRequestHeader("X-Requested-With", "TrafficLens");
      bar.style.display = "block"; fill.style.width = "0";
      xhr.upload.onprogress = e => { if (e.lengthComputable) fill.style.width = (e.loaded / e.total * 100).toFixed(1) + "%"; };
      xhr.onload = () => {
        bar.style.display = "none"; input.value = "";
        let d = {}; try { d = JSON.parse(xhr.responseText); } catch (e) { }
        if (xhr.status === 413) { alert("Файл больше разрешённого размера (max_upload_mb).", { title: "Не загружено" }); return; }
        if (d.errors && d.errors.length) alert(d.errors.join("\n"), { title: d.ok ? "Часть файлов не принята" : "Не загружено" });
        if (d.ok) { toast("Поставлено в очередь: " + d.jobs.length); refreshJobs(); }
      };
      xhr.onerror = () => { bar.style.display = "none"; alert("Сеть недоступна или соединение прервано.", { title: "Ошибка загрузки" }); };
      xhr.send(fd);
    }
  }

  // ---------- автообновление списка задач
  let refreshing = false;
  async function refreshJobs() {
    const tb = document.getElementById("jobs-body"); if (!tb || refreshing) return;
    refreshing = true;
    try {
      const r = await fetch("/", { headers: { "X-Partial": "1" } });
      const html = await r.text();
      const doc = new DOMParser().parseFromString(html, "text/html");
      const nb = doc.getElementById("jobs-body"); if (nb) tb.innerHTML = nb.innerHTML;
      const cap = doc.getElementById("capture-box"); const cur = document.getElementById("capture-box");
      if (cap && cur) cur.innerHTML = cap.innerHTML;
    } catch (e) { } finally { refreshing = false; }
  }
  function autoRefresh() {
    const tb = document.getElementById("jobs-body"); if (!tb) return;
    setInterval(() => { if (tb.querySelector("[data-live]") || document.getElementById("capture-box")?.dataset.active === "1") refreshJobs(); }, 4000);
  }
  function autoJob() {
    const p = document.querySelector("[data-job-live]"); if (!p) return;
    setInterval(async () => {
      try { const j = await api("/api/jobs/" + p.dataset.jobLive, { method: "GET" });
        if (j.status === "done" || j.status === "error") location.reload();
        const st = document.getElementById("job-stage"); if (st) st.textContent = j.stage || j.status;
      } catch (e) { }
    }, 3000);
  }

  // ---------- свои списки IOC
  function initCustom() {
    const form = document.getElementById("custom-form"); if (!form) return;
    const sel = document.getElementById("custom-name"), ta = document.getElementById("custom-text"), lists = JSON.parse(document.getElementById("custom-data").textContent);
    function load() { ta.value = lists[sel.value] || ""; document.getElementById("custom-new").style.display = sel.value === "__new" ? "" : "none"; }
    sel.addEventListener("change", load); load();
    form.addEventListener("submit", async e => {
      e.preventDefault();
      let name = sel.value === "__new" ? document.getElementById("custom-new").value.trim() : sel.value;
      try {
        const d = await api("/api/iocs/custom", { body: { name, text: ta.value } });
        if (d.errors.length) await alert(`Сохранено индикаторов: ${d.count}.\n\nНе распознаны:\n` + d.errors.join("\n"), { title: "Список сохранён" });
        else toast(`Сохранено индикаторов: ${d.count}`);
        location.reload();
      } catch (err) { alert(err.message, { title: "Ошибка" }); }
    });
    document.getElementById("custom-delete")?.addEventListener("click", async () => {
      if (sel.value === "__new") return;
      if (!await confirm(`Удалить список «${sel.value}»?`, { danger: true, ok: "Удалить" })) return;
      try { await api(`/api/iocs/custom/${sel.value}/delete`); location.reload(); } catch (err) { alert(err.message, { title: "Ошибка" }); }
    });
  }
  function initLookup() {
    const f = document.getElementById("lookup-form"); if (!f) return;
    f.addEventListener("submit", async e => {
      e.preventDefault();
      const q = document.getElementById("lookup-q").value.trim(); if (!q) return;
      const out = document.getElementById("lookup-out"); out.textContent = "Ищу…";
      try {
        const d = await api("/api/iocs/lookup?q=" + encodeURIComponent(q), { method: "GET" });
        out.innerHTML = "";
        if (!d.results.length) { out.appendChild(el("div", "badge ok", "Не найдено в базе IOC")); return; }
        const t = el("table"); t.innerHTML = "<thead><tr><th>Тип</th><th>Значение</th><th>Источник</th><th>Описание</th></tr></thead>";
        const tb = el("tbody");
        d.results.forEach(r => { const tr = el("tr"); [r.type, r.value, r.source, r.info].forEach(v => tr.appendChild(el("td", null, v))); tb.appendChild(tr); });
        t.appendChild(tb); out.appendChild(t);
      } catch (err) { out.textContent = err.message; }
    });
  }

  document.addEventListener("DOMContentLoaded", () => { initUpload(); autoRefresh(); autoJob(); initCustom(); initLookup(); });
  return { confirm, alert, toast, api };
})();

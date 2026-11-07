/* TrafficLens UI: собственные диалоги (без alert/confirm), уведомления, API, загрузка, обновление списка. */
window.TL = (function () {
  const I = window.TL_I18N || {};
  const tr = (k, vars) => { let s = I[k] || k; if (vars) for (const key in vars) s = s.replace("{" + key + "}", vars[key]); return s; };
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
  const confirm = (message, opts = {}) => dialog({ title: opts.title || tr("confirm_title"), message, ok: opts.ok || tr("yes"), cancel: tr("cancel"), danger: !!opts.danger });
  const alert = (message, opts = {}) => dialog({ title: opts.title || tr("alert_title"), message, ok: tr("ok_btn") });

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
      if (a === "theme") {
        const cur = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = cur;
        try { localStorage.setItem("tl-theme", cur); } catch (e) { }
        return;
      }
      if (a === "delete-job") {
        if (!await confirm(tr("del_job_confirm", { job }), { danger: true, ok: tr("delete") })) return;
        await api(`/api/jobs/${job}/delete`); toast(tr("del_job_ok"));
        if (b.dataset.back) location.href = "/"; else b.closest("tr")?.remove();
      } else if (a === "rematch") {
        b.disabled = true; await api(`/api/jobs/${job}/rematch`); toast(tr("rematch_ok")); setTimeout(() => location.reload(), 600);
      } else if (a === "rerun") {
        if (!await confirm(tr("rerun_confirm"), { ok: tr("run_btn") })) return;
        await api(`/api/jobs/${job}/rerun`); location.href = "/jobs/" + job;
      } else if (a === "ioc-update") {
        b.disabled = true; await api("/api/iocs/update", { body: { source: b.dataset.source || null } });
        toast(tr("ioc_update_started")); pollStatus();
      } else if (a === "rules-update") {
        b.disabled = true; await api("/api/rules/update"); toast(tr("rules_update_started")); pollStatus();
      } else if (a === "rulesrc-del") {
        if (!await confirm(tr("del_src_confirm", { name: b.dataset.url }), { danger: true, ok: tr("delete") })) return;
        await api("/api/rules/sources/delete", { body: { url: b.dataset.url } }); location.reload();
      } else if (a === "retro-ack") {
        await api("/api/retro/ack", { body: { job: job || null } }); toast(tr("retro_ack_ok")); setTimeout(() => location.reload(), 400);
      } else if (a === "retro-run") {
        b.disabled = true; await api("/api/retro/run", { body: { full: b.dataset.full === "1" } });
        toast(tr("retro_started")); pollStatus();
      } else if (a === "list-toggle") {
        b.disabled = true; await api("/api/iocs/lists/toggle", { body: { id: b.dataset.id, enabled: b.dataset.on === "1" } });
        toast(tr(b.dataset.on === "1" ? "list_enabled_ok" : "list_disabled_ok")); setTimeout(() => location.reload(), b.dataset.on === "1" ? 2500 : 400);
      } else if (a === "list-del") {
        if (!await confirm(tr("del_src_confirm", { name: b.dataset.name }), { danger: true, ok: tr("delete") })) return;
        await api("/api/iocs/lists/delete", { body: { id: b.dataset.id } }); location.reload();
      } else if (a === "allow-del") {
        await api("/api/allowlist", { body: { kind: b.dataset.kind, key: b.dataset.key, action: "del" } });
        b.closest(".ioc-src")?.remove();
      } else if (a === "logout") {
        await api("/logout"); location.href = "/login";
      }
    } catch (err) { b.disabled = false; alert(err.message, { title: tr("error_title") }); }
  });

  function pollStatus() {
    const tick = async () => {
      try {
        const s = await api("/api/status", { method: "GET" });
        if (s.state.busy.length) { setTimeout(tick, 2500); return; }
        toast(tr("done_toast")); setTimeout(() => location.reload(), 500);
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
      const bpf = document.getElementById("f-bpf")?.value.trim();
      if (bpf) fd.append("bpf", bpf);
      for (const [id, key] of [["f-from", "t_from"], ["f-to", "t_to"]]) {
        const v = document.getElementById(id)?.value;
        if (v) { const t = new Date(v).getTime() / 1000; if (isFinite(t)) fd.append(key, String(t)); }
      }
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload"); xhr.setRequestHeader("X-Requested-With", "TrafficLens");
      bar.style.display = "block"; fill.style.width = "0";
      xhr.upload.onprogress = e => { if (e.lengthComputable) fill.style.width = (e.loaded / e.total * 100).toFixed(1) + "%"; };
      xhr.onload = () => {
        bar.style.display = "none"; input.value = "";
        let d = {}; try { d = JSON.parse(xhr.responseText); } catch (e) { }
        if (xhr.status === 413) { alert(tr("too_large"), { title: tr("not_uploaded") }); return; }
        if (d.errors && d.errors.length) alert(d.errors.join("\n"), { title: d.ok ? tr("partial_errors") : tr("not_uploaded") });
        if (d.ok) { toast(tr("queued_n", { n: d.jobs.length })); refreshJobs(); }
      };
      xhr.onerror = () => { bar.style.display = "none"; alert(tr("net_err"), { title: tr("upload_err") }); };
      xhr.send(fd);
    }
  }

  // ---------- автообновление списка задач
  let refreshing = false;
  async function refreshJobs() {
    const tb = document.getElementById("jobs-body"); if (!tb || refreshing) return;
    refreshing = true;
    try {
      const r = await fetch("/" + location.search, { headers: { "X-Partial": "1" } });
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
        const st = document.getElementById("job-stage"); if (st) st.textContent = (j.stage && (I["stage_" + j.stage] || j.stage)) || j.status;
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
        if (d.errors.length) await alert(`${tr("saved_n", { n: d.count })}.\n\n${tr("not_recognized")}\n` + d.errors.map(x => typeof x === "string" ? x : tr(x.k || "parse_line", x)).join("\n"), { title: tr("list_saved") });
        else toast(tr("saved_n", { n: d.count }));
        location.reload();
      } catch (err) { alert(err.message, { title: tr("error_title") }); }
    });
    document.getElementById("custom-delete")?.addEventListener("click", async () => {
      if (sel.value === "__new") return;
      if (!await confirm(tr("del_list_confirm", { name: sel.value }), { danger: true, ok: tr("delete") })) return;
      try { await api(`/api/iocs/custom/${sel.value}/delete`); location.reload(); } catch (err) { alert(err.message, { title: tr("error_title") }); }
    });
  }
  function initLookup() {
    const f = document.getElementById("lookup-form"); if (!f) return;
    f.addEventListener("submit", async e => {
      e.preventDefault();
      const q = document.getElementById("lookup-q").value.trim(); if (!q) return;
      const out = document.getElementById("lookup-out"); out.textContent = tr("searching");
      try {
        const d = await api("/api/iocs/lookup?q=" + encodeURIComponent(q), { method: "GET" });
        out.innerHTML = "";
        if (!d.results.length) { out.appendChild(el("div", "badge ok", tr("not_in_db"))); return; }
        const t = el("table"); t.innerHTML = `<thead><tr><th>${tr("col_type")}</th><th>${tr("col_value")}</th><th>${tr("col_source")}</th><th>${tr("col_desc")}</th></tr></thead>`;
        const tb = el("tbody");
        d.results.forEach(r => { const tr = el("tr"); [r.type, r.value, r.source, r.info].forEach(v => tr.appendChild(el("td", null, v))); tb.appendChild(tr); });
        t.appendChild(tb); out.appendChild(t);
      } catch (err) { out.textContent = err.message; }
    });
  }

  function initRuleSources() {
    const f = document.getElementById("rulesrc-form"); if (!f) return;
    f.addEventListener("submit", async e => {
      e.preventDefault();
      try {
        await api("/api/rules/sources", { body: { url: document.getElementById("rulesrc-url").value.trim(), note: document.getElementById("rulesrc-note").value.trim() } });
        location.reload();
      } catch (err) { alert(err.message, { title: tr("error_title") }); }
    });
  }

  function initListFeeds() {
    const f = document.getElementById("list-form"); if (!f) return;
    f.addEventListener("submit", async e => {
      e.preventDefault();
      try {
        await api("/api/iocs/lists", { body: {
          url: document.getElementById("list-url").value.trim(), name: document.getElementById("list-name").value.trim(),
          type: document.getElementById("list-type").value || null, conf: parseInt(document.getElementById("list-conf").value, 10) || 60 } });
        toast(tr("list_added_ok")); setTimeout(() => location.reload(), 2500);
      } catch (err) { alert(err.message, { title: tr("error_title") }); }
    });
  }

  document.addEventListener("DOMContentLoaded", () => { initUpload(); autoRefresh(); autoJob(); initCustom(); initLookup(); initRuleSources(); initListFeeds(); });
  return { confirm, alert, toast, api };
})();

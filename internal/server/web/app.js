"use strict";

const state = { lang: "en", dict: {}, meta: {}, inv: null, poll: null, wasRunning: false };
const view = document.getElementById("view");
const dialog = document.getElementById("dialog");

function storeGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function storeSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ } }

function t(key, ...args) {
  let s = state.dict[key] ?? key;
  let i = 0;
  return s.replace(/%(\.\d+f|v|d|s)/g, (m, spec) => {
    const a = args[i++];
    if (spec.endsWith("f") && spec.length > 1) return Number(a).toFixed(Number(spec.slice(1, -1)));
    return a === undefined ? "" : String(a);
  });
}

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: {} };
  if (o.method !== "GET") o.headers["X-Farol-Request"] = "1";
  if (opts.body !== undefined) {
    o.headers["Content-Type"] = "application/json";
    o.body = JSON.stringify(opts.body);
  }
  const r = await fetch(path, o);
  if (opts.raw) return r;
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

function langParam() { return "lang=" + encodeURIComponent(state.lang); }

async function loadLang(lang) {
  state.lang = lang;
  state.dict = await api("/api/i18n?" + langParam());
  document.documentElement.lang = lang;
  document.getElementById("lang-toggle").textContent = lang === "pt-BR" ? "EN" : "PT";
  updateThemeButton();
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(state.lang === "pt-BR" ? "pt-BR" : "en-GB", { dateStyle: "short", timeStyle: "short" });
}

function route() {
  const h = location.hash.replace(/^#\/?/, "");
  const [name, ...rest] = h.split("/");
  return { name: name || "fleet", arg: decodeURIComponent(rest.join("/")) };
}

async function render() {
  const r = route();
  document.querySelectorAll(".nav-links a").forEach(a => {
    a.classList.toggle("active", a.dataset.route === (r.name === "host" ? "fleet" : r.name));
  });
  try {
    if (r.name === "host") await renderHost(r.arg);
    else if (r.name === "inventory") await renderInventory();
    else if (r.name === "reports") await renderReports();
    else if (r.name === "keys") await renderKeys();
    else await renderFleet();
  } catch (e) {
    view.innerHTML = `<div class="notice err">${esc(t("ui.error", e.message))}</div>`;
  }
  window.scrollTo(0, 0);
}

function agentNotice() {
  return state.meta.agent ? "" : `<div class="notice">${esc(t("ui.agent.missing"))}</div>`;
}

async function runnerHTML(fixedHost) {
  if (!state.inv) state.inv = await api("/api/inventory");
  const scopeField = fixedHost
    ? `<label class="field" style="min-width:220px">${esc(t("ui.scope"))}<input type="text" value="${esc(t("ui.scope.host", fixedHost))}" disabled data-fixed-host="${esc(fixedHost)}"></label>`
    : `<details class="scope-pop" id="scope-pop">
        <summary><span class="meta">${esc(t("ui.scope"))}</span><span class="scope-pop-value" data-scope-pop-value>${esc(t("ui.scope.all"))}</span></summary>
        <div class="scope-pop-panel">${scopePickerHTML()}</div>
      </details>`;
  return `
  <section class="card runner reveal" style="--i:1">
    <div class="opts">
      ${scopeField}
      <label class="check"><input type="checkbox" id="opt-refresh">${esc(t("ui.refresh"))}</label>
      <label class="check"><input type="checkbox" id="opt-nocve">${esc(t("ui.nocve"))}</label>
    </div>
    <div class="run-actions">
      <button id="run-btn" type="button">${esc(t("ui.run"))}</button>
      <button id="cancel-btn" class="danger" type="button" hidden>${esc(t("ui.cancel"))}</button>
    </div>
    <div class="progress" id="progress">
      <div class="job-result" id="job-result" hidden></div>
      <div class="meta" id="progress-text"></div>
      <div class="bar"><span id="progress-bar"></span></div>
      <div class="job-hosts" id="job-hosts"></div>
      <details class="activity" id="activity"${storeGet("farol.activity") === "open" ? " open" : ""}>
        <summary><span class="label">${esc(t("ui.activity"))}</span><span class="activity-last mono" id="activity-last">${esc(t("ui.activity.empty"))}</span></summary>
        <pre class="activity-log" id="activity-log"></pre>
      </details>
    </div>
  </section>`;
}

function appendActivity(job) {
  const box = document.getElementById("activity-log");
  const last = document.getElementById("activity-last");
  if (!box) return;
  if (state.logJob !== job.started) {
    state.logJob = job.started;
    state.logNext = 0;
    box.textContent = "";
  }
  const lines = job.log || [];
  if (!lines.length) return;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.textContent += lines.map(l => `${l.t}  ${l.m}`).join("\n") + "\n";
  if (nearBottom) box.scrollTop = box.scrollHeight;
  last.textContent = lines[lines.length - 1].m;
  state.logNext = job.log_next;
}

function targetKey(h) {
  return `${String(h.address).toLowerCase().replace(/\.$/, "")}:${h.port}`;
}

function duplicates(hosts) {
  const by = new Map();
  for (const h of hosts) {
    const k = targetKey(h);
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(h.name);
  }
  return [...by.entries()].filter(([, names]) => names.length > 1).map(([target, names]) => ({ target, names }));
}

function scopeHosts(body) {
  const all = state.inv.hosts || [];
  if (!body.groups.length && !body.hosts.length) return all;
  return all.filter(h => body.groups.includes(h.group) || body.hosts.includes(h.name));
}

function confirmDuplicates(dups) {
  return new Promise(resolve => {
    const rows = dups.map(d => `<tr><td class="mono nowrap">${esc(d.target)}</td><td><div class="chips">${d.names.map(n => `<span class="chip">${esc(n)}</span>`).join("")}</div></td></tr>`).join("");
    dialog.innerHTML = `<div class="dlg"><h2>${esc(t("ui.dup.title"))}</h2><p class="meta">${esc(t("ui.dup.body"))}</p>
      <div class="table-wrap"><table><tbody>${rows}</tbody></table></div>
      <div class="foot"><button class="ghost" id="dup-fix">${esc(t("ui.dup.fix"))}</button>
      <button id="dup-run">${esc(t("ui.dup.run"))}</button></div></div>`;
    const done = v => { dialog.close(); resolve(v); };
    document.getElementById("dup-fix").addEventListener("click", () => { done(false); location.hash = "#/inventory"; });
    document.getElementById("dup-run").addEventListener("click", () => done(true));
    dialog.addEventListener("cancel", () => resolve(false), { once: true });
    dialog.showModal();
  });
}

function bindRunner(onDone) {
  state.logNext = 0;
  state.logJob = null;
  const cancelBtn = document.getElementById("cancel-btn");
  cancelBtn.addEventListener("click", async () => {
    cancelBtn.disabled = true;
    cancelBtn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${esc(t("ui.cancelling"))}`;
    try { await api("/api/check/cancel", { method: "POST" }); } catch (e) { showProgressError(e.message); }
  });
  const pop = document.getElementById("scope-pop");
  let getScope = null;
  if (pop) {
    getScope = bindScopePicker(pop);
    const all = pop.querySelector("[data-scope-all]");
    if (!pop.dataset.init) {
      all.checked = true;
      all.dispatchEvent(new Event("change"));
      pop.dataset.init = "1";
    }
    const val = pop.querySelector("[data-scope-pop-value]");
    const sync = () => {
      const sc = getScope();
      const allOn = all.checked;
      val.textContent = allOn ? t("ui.scope.all") : (sc.groups.length || sc.hosts.length) ? t("ui.scope.summary", sc.groups.length, sc.hosts.length) : t("ui.scope.none");
    };
    pop.addEventListener("change", sync);
    sync();
    document.addEventListener("click", ev => { if (pop.open && !pop.contains(ev.target)) pop.open = false; });
  }
  const act = document.getElementById("activity");
  act.addEventListener("toggle", () => {
    storeSet("farol.activity", act.open ? "open" : "closed");
    if (act.open) { const b = document.getElementById("activity-log"); b.scrollTop = b.scrollHeight; }
  });
  document.getElementById("run-btn").addEventListener("click", async () => {
    const fixed = document.querySelector("[data-fixed-host]");
    const sc = fixed ? { groups: [], hosts: [fixed.dataset.fixedHost] } : getScope();
    if (!sc.groups.length && !sc.hosts.length) { showProgressError(t("ui.scope.required")); return; }
    const body = {
      refresh: document.getElementById("opt-refresh").checked,
      no_cve: document.getElementById("opt-nocve").checked,
      groups: sc.groups, hosts: sc.hosts,
    };
    state.inv = await api("/api/inventory").catch(() => state.inv);
    const dups = duplicates(scopeHosts(body));
    if (dups.length && !(await confirmDuplicates(dups))) return;
    try {
      await api("/api/check", { method: "POST", body });
      startPolling(onDone);
    } catch (e) {
      showProgressError(e.message);
    }
  });
  startPolling(onDone);
}

function showProgressError(msg) {
  const p = document.getElementById("progress");
  if (!p) return;
  p.classList.add("on");
  document.getElementById("progress-text").innerHTML = `<span class="lvl-critical">${esc(t("ui.error", msg))}</span>`;
}

function startPolling(onDone) {
  clearInterval(state.poll);
  const tick = async () => {
    let job;
    try { job = await api("/api/job?since=" + (state.logNext || 0)); } catch (e) { return; }
    const p = document.getElementById("progress");
    const btn = document.getElementById("run-btn");
    const cancel = document.getElementById("cancel-btn");
    if (!p || !btn) { clearInterval(state.poll); return; }
    btn.hidden = !!job.running;
    btn.disabled = false;
    cancel.hidden = !job.running;
    if (!job.running) {
      cancel.disabled = false;
      cancel.textContent = t("ui.cancel");
    }
    if (!job.started) return;
    btn.textContent = t(job.running ? "ui.run" : "ui.run.again");
    p.classList.add("on");
    if (state.logJob !== job.started && state.logNext) {
      state.logNext = 0;
      job = await api("/api/job?since=0");
    }
    appendActivity(job);
    const hostsDone = (job.hosts || []).length;
    let frac = job.total ? hostsDone / job.total * 0.7 : 0;
    let text = t("ui.running", hostsDone, job.total);
    if (job.cve_total) {
      frac = 0.7 + 0.3 * job.cve_done / job.cve_total;
      text += " &middot; " + esc(t("ui.cve", job.cve_done, job.cve_total));
    }
    const result = document.getElementById("job-result");
    const bar = document.getElementById("progress-bar");
    bar.classList.remove("done", "cancelled");
    result.hidden = true;
    if (!job.running) {
      frac = 1;
      const hosts = job.hosts || [];
      const ok = hosts.filter(h => h.ok).length;
      const pend = hosts.filter(h => h.pending).length;
      const fail = hosts.length - ok - pend;
      result.hidden = false;
      if (job.cancelled) {
        bar.classList.add("cancelled");
        result.className = "job-result notice";
        result.textContent = t("ui.done.cancelled", fmtTime(job.finished));
      } else {
        bar.classList.add("done");
        result.className = "job-result notice " + (fail || job.error ? "warn" : "ok");
        result.textContent = t("ui.done.summary", fmtTime(job.finished), hosts.length, ok, fail, pend) + (job.error ? " · " + job.error : "");
      }
      text = "";
    }
    document.getElementById("progress-text").innerHTML = text;
    document.getElementById("progress-bar").style.transform = `scaleX(${frac})`;
    document.getElementById("job-hosts").innerHTML = (job.hosts || []).map(h =>
      `<span class="badge ${h.ok ? "ok" : h.pending ? "medium" : "critical"}" title="${esc(h.pending ? t("report.untrusted") : h.reason ? jobReason(h) : (h.error || h.os))}">${esc(h.name)}</span>`).join("");
    if (job.running) {
      state.wasRunning = true;
    } else {
      clearInterval(state.poll);
      if (state.wasRunning) {
        state.wasRunning = false;
        await (onDone && onDone());
        if ((job.hosts || []).some(h => h.pending)) {
          const pending = await api("/api/hostkeys/pending").catch(() => []);
          if (pending.length && !dialog.open) trustDialog(pending);
        }
      }
    }
  };
  tick();
  state.poll = setInterval(tick, 1000);
}

async function renderFleet() {
  view.innerHTML = `
    <header class="page-head reveal">
      <div class="eyebrow">farol-guard ${esc(state.meta.version || "")}</div>
      <h1>${esc(t("ui.nav.fleet"))}</h1>
      <div class="meta" id="report-meta"></div>
    </header>
    ${agentNotice()}
    ${await runnerHTML()}
    <div id="pending-keys"></div>
    <div id="fleet"></div>`;
  bindRunner(loadFleet);
  await loadFleet();
}

async function loadFleet() {
  const r = await api("/ui/fleet?" + langParam(), { raw: true });
  const box = document.getElementById("fleet");
  if (!box) return;
  if (r.status === 204) {
    box.innerHTML = `<div class="empty"><h2>${esc(t("ui.empty.title"))}</h2><p class="meta">${esc(t("ui.empty.body"))}</p>
      <a class="btn ghost" href="#/inventory">${esc(t("ui.inv.add"))}</a></div>`;
    return;
  }
  if (!r.ok) throw new Error(r.statusText);
  box.innerHTML = await r.text();
  loadPendingKeys();
  const id = r.headers.get("X-Report-ID");
  const gen = r.headers.get("X-Report-Generated");
  document.getElementById("report-meta").innerHTML =
    `${esc(t("ui.lastreport", fmtTime(gen)))} &middot; <a href="/api/reports/${esc(id)}?format=html&${langParam()}">HTML</a>
     &middot; <a data-download href="/api/reports/${esc(id)}?format=html&download=1&${langParam()}">${esc(t("ui.dl.html"))}</a>
     &middot; <a data-download href="/api/reports/${esc(id)}?format=json&download=1">JSON</a>
     &middot; <a data-download href="/api/reports/${esc(id)}?format=md&download=1&${langParam()}">Markdown</a>`;
}

async function loadPendingKeys() {
  const box = document.getElementById("pending-keys");
  if (!box) return;
  const pending = await api("/api/hostkeys/pending").catch(() => []);
  if (!pending.length) { box.innerHTML = ""; return; }
  box.innerHTML = `<div class="notice pending-notice"><span>${esc(t("ui.trust.pending", pending.length))}</span>
    <button class="small" id="review-keys" type="button">${esc(t("ui.trust.review"))}</button></div>`;
  document.getElementById("review-keys").addEventListener("click", () => trustDialog(pending));
}

function trustDialog(pending) {
  const rows = pending.map((p, i) => `
    <li class="trust-item">
      <label class="check"><input type="checkbox" data-i="${i}" checked>
        <span><strong>${esc(p.name)}</strong> <span class="meta mono">${esc(p.address)}:${esc(p.port)}</span></span></label>
      <div class="fp">${esc(p.type)}<br>${esc(p.fingerprint)}</div>
      <div class="status-line" data-res="${i}"></div>
    </li>`).join("");
  dialog.innerHTML = `
    <div class="dlg dlg-wide">
      <h2>${esc(t("ui.trust.bulk.title"))}</h2>
      <p class="meta">${esc(t("ui.trust.bulk.body"))}</p>
      <ul class="trust-list">${rows}</ul>
      <div class="status-line" id="trust-summary"></div>
      <div class="foot"><button class="ghost" id="trust-close">${esc(t("ui.close"))}</button>
        <button class="ghost" id="trust-check" hidden>${esc(t("ui.trust.checknow"))}</button>
        <button id="trust-run">${esc(t("ui.trust.bulk.ok"))}</button></div>
    </div>`;
  dialog.showModal();
  document.getElementById("trust-close").addEventListener("click", () => { dialog.close(); loadPendingKeys(); });
  document.getElementById("trust-run").addEventListener("click", async ev => {
    const runBtn = ev.currentTarget;
    runBtn.disabled = true;
    runBtn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${esc(t("ui.busy.running"))}`;
    let ok = 0, fail = 0;
    const trusted = [];
    for (const cb of dialog.querySelectorAll("input[data-i]:checked")) {
      const p = pending[Number(cb.dataset.i)];
      const cell = dialog.querySelector(`[data-res="${cb.dataset.i}"]`);
      try {
        await api(`/api/hosts/${encodeURIComponent(p.name)}/trust`, { method: "POST", body: { fingerprint: p.fingerprint } });
        cell.className = "status-line ok";
        cell.textContent = t("ui.trust.done");
        trusted.push(p.name);
        ok++;
      } catch (e) {
        cell.className = "status-line err";
        cell.textContent = e.message;
        fail++;
      }
      cb.disabled = true;
    }
    runBtn.hidden = true;
    const sum = document.getElementById("trust-summary");
    sum.className = "status-line " + (fail ? "err" : "ok");
    sum.textContent = t("ui.trust.bulk.done", ok, fail);
    loadPendingKeys();
    if (trusted.length) {
      const chk = document.getElementById("trust-check");
      chk.hidden = false;
      chk.onclick = async () => {
        dialog.close();
        if (route().name !== "fleet") location.hash = "#/";
        try {
          await api("/api/check", { method: "POST", body: { hosts: trusted, groups: [], refresh: false, no_cve: false } });
        } catch (e) { showProgressError(e.message); }
        startPolling(loadFleet);
      };
    }
  });
}

async function renderHost(name) {
  view.innerHTML = `<a class="back" href="#/">&larr; ${esc(t("ui.back"))}</a>
    ${await runnerHTML(name)}
    <div id="host-body"></div>`;
  const load = async () => {
    const r = await api(`/ui/host/${encodeURIComponent(name)}?` + langParam(), { raw: true });
    const box = document.getElementById("host-body");
    if (!box) return;
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      box.innerHTML = `<div class="empty"><p class="meta">${esc(data.error || r.statusText)}</p></div>`;
      return;
    }
    box.innerHTML = await r.text();
    const sec = box.querySelector(".host");
    if (sec) sec.style.paddingTop = "48px";
    box.querySelectorAll(".fix-panel > summary").forEach(s => s.addEventListener("click", ev => {
      ev.preventDefault();
      fixDialog(s.parentElement.querySelector(".fix-body"));
    }));
  };
  bindRunner(load);
  await load();
}

state.invFilter = state.invFilter || { q: "", group: "", tag: "", issue: "", status: "" };

function hostStatusBadge(st) {
  if (!st) return `<span class="badge">${esc(t("ui.inv.nocheck"))}</span>`;
  if (st.pending) return `<span class="badge medium">${esc(t("report.untrusted"))}</span>`;
  if (!st.reachable) return `<span class="badge critical">${esc(t("report.unreachable"))}</span>`;
  return `<span class="badge ${esc(st.worst)}">${esc(t("sev." + st.worst))}</span>`;
}

function statusKey(st) {
  if (!st) return "none";
  if (st.pending) return "pending";
  if (!st.reachable) return "unreachable";
  return st.worst;
}

async function renderInventory() {
  state.inv = await api("/api/inventory");
  const statuses = await api("/api/hosts/status").catch(() => ({}));
  const inv = state.inv;
  const hosts = inv.hosts || [];
  const dupOf = {};
  for (const d of duplicates(hosts)) {
    for (const n of d.names) dupOf[n] = d.names.filter(x => x !== n).join(", ");
  }
  const groups = [...inv.groups].sort((a, b) => a.localeCompare(b));
  const tags = [...new Set(hosts.flatMap(h => h.tags || []))].sort();
  const collapsed = new Set(JSON.parse(storeGet("farol.inv.collapsed") || "[]"));
  const f = state.invFilter;

  const row = h => {
    const st = statuses[h.name];
    const search = [h.name, h.address, h.user, h.group, ...(h.tags || [])].join(" ").toLowerCase();
    return `
    <tr data-host="${esc(h.name)}" data-group="${esc(h.group)}" data-search="${esc(search)}" data-tags="${esc((h.tags || []).join("\n"))}"
        data-status="${esc(statusKey(st))}" data-dup="${dupOf[h.name] ? "1" : ""}">
      <td>${esc(h.name)}
        ${dupOf[h.name] ? `<div style="margin-top:6px"><span class="badge medium">${esc(t("ui.dup.badge", dupOf[h.name]))}</span></div>` : ""}</td>
      <td class="mono nowrap">${esc(h.user)}@${esc(h.address)}:${esc(h.port)}</td>
      <td>${(h.tags || []).length ? `<div class="chips">${h.tags.map(tg => `<span class="chip">${esc(tg)}</span>`).join("")}</div>` : `<span class="meta">&mdash;</span>`}</td>
      <td class="nowrap">${hostStatusBadge(st)}</td>
      <td class="mono nowrap" title="${esc(h.identity)}">${esc(String(h.identity).split("/").pop())}</td>
      <td class="nowrap"><div class="actions">
        <button class="ghost small" data-act="test">${esc(t("ui.inv.test"))}</button>
        <button class="ghost small" data-act="edit">${esc(t("ui.inv.edit"))}</button>
        <button class="ghost small" data-act="clone">${esc(t("ui.inv.clone"))}</button>
        <button class="danger small" data-act="delete">${esc(t("ui.inv.delete"))}</button>
      </div></td>
    </tr>
    <tr class="status-row" data-status-for="${esc(h.name)}" hidden><td colspan="6"><div class="status-line" data-status></div></td></tr>`;
  };

  const sections = groups.map(g => {
    const list = hosts.filter(h => h.group === g);
    const gs = (inv.group_settings || {})[g] || {};
    const overrides = [gs.user && `user ${gs.user}`, gs.port && `port ${gs.port}`, gs.identity && String(gs.identity).split("/").pop()].filter(Boolean).join(" · ");
    return `
    <tbody class="inv-group${collapsed.has(g) ? " collapsed" : ""}" data-group="${esc(g)}">
      <tr class="group-row"><td colspan="6"><div class="group-head">
        <button class="group-toggle" type="button" aria-expanded="${collapsed.has(g) ? "false" : "true"}">
          <span class="chev">${collapsed.has(g) ? "+" : "&minus;"}</span><span class="group-name">${esc(g)}</span><span class="count" data-count>${list.length}</span>
          ${overrides ? `<span class="meta mono group-ov">${esc(overrides)}</span>` : ""}</button>
        <button class="ghost small" data-test-group="${esc(g)}" type="button">${esc(t("ui.inv.testgroup"))}</button>
      </div></td></tr>
      ${list.map(row).join("")}
    </tbody>`;
  }).join("");

  view.innerHTML = `
    <header class="page-head reveal">
      <div class="eyebrow">${esc(t("ui.inv.path", inv.path))}</div>
      <h1>${esc(t("ui.nav.inventory"))}</h1>
    </header>
    ${agentNotice()}
    <div class="section-head"><div class="meta" id="inv-count"></div>
      <button id="add-host" type="button">${esc(t("ui.inv.add"))}</button></div>
    ${hosts.length ? `
    <div class="filters card">
      <label class="field grow">${esc(t("ui.filter.search"))}<input type="search" id="f-q" value="${esc(f.q)}" placeholder="${esc(t("ui.filter.searchph"))}"></label>
      <label class="field">${esc(t("ui.f.group"))}<select id="f-group"><option value="">${esc(t("ui.filter.all"))}</option>${groups.map(g => `<option value="${esc(g)}"${f.group === g ? " selected" : ""}>${esc(g)}</option>`).join("")}</select></label>
      <label class="field">Tag<select id="f-tag"><option value="">${esc(t("ui.filter.all"))}</option>${tags.map(tg => `<option value="${esc(tg)}"${f.tag === tg ? " selected" : ""}>${esc(tg)}</option>`).join("")}</select></label>
      <label class="field">${esc(t("report.status"))}<select id="f-status">
        <option value="">${esc(t("ui.filter.all"))}</option>
        ${["critical", "high", "medium", "low", "info", "pending", "unreachable", "none"].map(k => `<option value="${k}"${f.status === k ? " selected" : ""}>${esc(k === "pending" ? t("report.untrusted") : k === "unreachable" ? t("report.unreachable") : k === "none" ? t("ui.inv.nocheck") : t("sev." + k))}</option>`).join("")}
      </select></label>
      <label class="field">${esc(t("ui.filter.issue"))}<select id="f-issue">
        <option value="">${esc(t("ui.filter.all"))}</option>
        <option value="problem"${f.issue === "problem" ? " selected" : ""}>${esc(t("ui.filter.problem"))}</option>
        <option value="dup"${f.issue === "dup" ? " selected" : ""}>${esc(t("ui.dup.title"))}</option>
      </select></label>
      <button class="ghost small" id="f-clear" type="button">${esc(t("ui.filter.clear"))}</button>
    </div>
    <div class="table-wrap inv-wrap"><table class="inv-table">
      <thead><tr><th>${esc(t("ui.f.name"))}</th><th>${esc(t("ui.f.target"))}</th><th>Tags</th><th>${esc(t("report.status"))}</th><th>${esc(t("ui.f.identity.short"))}</th><th></th></tr></thead>
      ${sections}
    </table></div>
    <div class="empty" id="inv-none" hidden><p class="meta">${esc(t("ui.filter.none"))}</p></div>`
    : `<div class="empty"><p class="meta">${esc(t("ui.inv.empty"))}</p></div>`}`;

  document.getElementById("add-host").addEventListener("click", () => hostForm(null));
  view.querySelectorAll("tr[data-host]").forEach(tr => {
    const name = tr.dataset.host;
    const host = hosts.find(h => h.name === name);
    tr.querySelector('[data-act="edit"]').addEventListener("click", () => hostForm(host));
    tr.querySelector('[data-act="clone"]').addEventListener("click", () => hostForm(host, true));
    tr.querySelector('[data-act="delete"]').addEventListener("click", () => deleteHost(name));
    const statusRow = tr.nextElementSibling;
    tr.querySelector('[data-act="test"]').addEventListener("click", () => {
      statusRow.hidden = false;
      return testHost(name, statusRow.querySelector("[data-status]"));
    });
  });
  view.querySelectorAll("tbody.inv-group .group-toggle").forEach(btn => btn.addEventListener("click", () => {
    const tb = btn.closest("tbody");
    const isCollapsed = tb.classList.toggle("collapsed");
    btn.setAttribute("aria-expanded", isCollapsed ? "false" : "true");
    btn.querySelector(".chev").innerHTML = isCollapsed ? "+" : "&minus;";
    const set = new Set(JSON.parse(storeGet("farol.inv.collapsed") || "[]"));
    if (isCollapsed) set.add(tb.dataset.group); else set.delete(tb.dataset.group);
    storeSet("farol.inv.collapsed", JSON.stringify([...set]));
  }));
  view.querySelectorAll("[data-test-group]").forEach(b => b.addEventListener("click", async ev => {
    ev.preventDefault();
    ev.stopPropagation();
    const det = b.closest("tbody");
    if (det.classList.contains("collapsed")) det.querySelector(".group-toggle").click();
    b.disabled = true;
    for (const tr of det.querySelectorAll("tr[data-host]")) {
      if (tr.hidden) continue;
      const statusRow = tr.nextElementSibling;
      statusRow.hidden = false;
      await testHost(tr.dataset.host, statusRow.querySelector("[data-status]"));
    }
    b.disabled = false;
  }));

  const apply = () => {
    const q = f.q.trim().toLowerCase();
    let visible = 0;
    view.querySelectorAll("tbody.inv-group").forEach(d => {
      let n = 0;
      d.querySelectorAll("tr[data-host]").forEach(tr => {
        const st = tr.dataset.status;
        const problem = tr.dataset.dup === "1" || ["critical", "high", "pending", "unreachable"].includes(st);
        const ok = (!q || tr.dataset.search.includes(q))
          && (!f.group || tr.dataset.group === f.group)
          && (!f.tag || tr.dataset.tags.split("\n").includes(f.tag))
          && (!f.status || st === f.status)
          && (!f.issue || (f.issue === "dup" ? tr.dataset.dup === "1" : problem));
        tr.hidden = !ok;
        if (!ok) tr.nextElementSibling.hidden = true;
        if (ok) n++;
      });
      d.hidden = n === 0;
      d.querySelector("[data-count]").textContent = n;
      visible += n;
    });
    const none = document.getElementById("inv-none");
    if (none) none.hidden = visible > 0;
    document.getElementById("inv-count").textContent = t("ui.inv.count", visible, hosts.length, groups.length);
  };
  const bind = (id, key, ev = "change") => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(ev, () => { f[key] = el.value; apply(); });
  };
  bind("f-q", "q", "input");
  bind("f-group", "group");
  bind("f-tag", "tag");
  bind("f-status", "status");
  bind("f-issue", "issue");
  const clear = document.getElementById("f-clear");
  if (clear) clear.addEventListener("click", () => { Object.assign(f, { q: "", group: "", tag: "", issue: "", status: "" }); renderInventory(); });
  apply();
}

function identityLabel(id) {
  const parts = [id.path, id.type.replace(/^ssh-/, ""), id.comment, t(id.in_agent ? "ui.id.agent" : "ui.id.noagent")];
  if (id.source === "farol") parts.push(t("ui.id.farol"));
  return parts.filter(Boolean).join("  ·  ");
}

function nextName(value, taken) {
  if (!value) return "";
  const bump = v => {
    const m = v.match(/^(.*?)(\d+)(\D*)$/);
    if (!m) return v + "-2";
    const n = String(Number(m[2]) + 1).padStart(m[2].length, "0");
    return m[1] + n + m[3];
  };
  let next = bump(value);
  for (let i = 0; i < 100 && taken.has(next); i++) next = bump(next);
  return next;
}

async function hostForm(source, clone = false) {
  const inv = state.inv;
  const taken = new Set((inv.hosts || []).map(h => h.name));
  let host = source;
  const followName = !!(source && clone && source.address === source.name);
  if (source && clone) {
    const name = nextName(source.name, taken);
    const address = followName ? name : nextName(source.address, new Set());
    host = { ...source, name, address };
  }
  const raw = host ? host.raw : {};
  const d = inv.defaults || {};
  const ids = await api("/api/identities").catch(() => []);
  const known = ids.some(i => i.path === raw.identity);
  const inherited = group => {
    const gs = (inv.group_settings || {})[group] || {};
    return gs.identity || d.identity || "";
  };
  const inheritText = group => {
    const path = inherited(group);
    const id = ids.find(i => i.path === path);
    return t("ui.id.inherit", id ? identityLabel(id) : path);
  };
  dialog.innerHTML = `
    <form method="dialog" id="host-form">
      <h2>${esc(clone ? t("ui.inv.clonetitle", source.name) : host ? host.name : t("ui.inv.add"))}</h2>
      <div class="grid2">
        <label class="field">${esc(t("ui.f.name"))}<input type="text" name="name" required value="${esc(host?.name)}"></label>
        <label class="field">${esc(t("ui.f.group"))}
          ${inv.groups.length ? `<select name="group_sel" id="group-sel">
            ${[...inv.groups].sort().map(g => `<option value="${esc(g)}"${g === host?.group ? " selected" : ""}>${esc(g)}</option>`).join("")}
            <option value="__new">${esc(t("ui.group.new"))}</option>
          </select>` : ""}
          <input type="text" name="group_new" id="group-new" placeholder="production"${inv.groups.length ? " hidden" : " required"}>
        </label>
        <label class="field">${esc(t("ui.f.address"))}<input type="text" name="address" required value="${esc(host?.address)}"></label>
        <label class="field">${esc(t("ui.f.port"))}<input type="number" name="port" min="1" max="65535" placeholder="${esc(t("ui.f.inherit", d.port))}" value="${esc(raw.port || "")}"></label>
        <label class="field">${esc(t("ui.f.user"))}<input type="text" name="user" placeholder="${esc(t("ui.f.inherit", d.user))}" value="${esc(raw.user)}"></label>
        <label class="field">${esc(t("ui.f.tags"))}<input type="text" name="tags" value="${esc((host?.tags || []).join(", "))}"></label>
      </div>
      <label class="field">${esc(t("ui.f.identity"))}
        <select name="identity_sel" id="identity-sel">
          <option value="" id="identity-inherit">${esc(inheritText(host?.group || [...inv.groups].sort()[0] || ""))}</option>
          ${ids.map(i => `<option value="${esc(i.path)}"${i.path === raw.identity ? " selected" : ""}>${esc(identityLabel(i))}</option>`).join("")}
          <option value="__custom"${raw.identity && !known ? " selected" : ""}>${esc(t("ui.id.custom"))}</option>
        </select>
      </label>
      <input type="text" class="mono-input" name="identity_custom" id="identity-custom" placeholder="~/.ssh/id_rsa" value="${esc(raw.identity && !known ? raw.identity : "")}"${raw.identity && !known ? "" : " hidden"}>
      <p class="note" style="margin:0">${esc(t("ui.id.note"))}</p>
      <div class="status-line err" id="form-err"></div>
      <div class="foot">
        <button class="ghost" value="cancel" formnovalidate>${esc(t("ui.inv.cancel"))}</button>
        <button value="save" id="save-btn">${esc(t("ui.inv.save"))}</button>
      </div>
    </form>`;
  dialog.showModal();
  const nameInput = document.querySelector('#host-form input[name="name"]');
  const addrInput = document.querySelector('#host-form input[name="address"]');
  let addrLinked = !host || followName || addrInput.value === nameInput.value;
  addrInput.addEventListener("input", () => { addrLinked = addrInput.value === nameInput.value; });
  nameInput.addEventListener("input", () => { if (addrLinked) addrInput.value = nameInput.value; });
  if (clone) {
    nameInput.focus();
    nameInput.select();
  }
  const sel = document.getElementById("identity-sel");
  const custom = document.getElementById("identity-custom");
  sel.addEventListener("change", () => { custom.hidden = sel.value !== "__custom"; });
  const groupSel = document.getElementById("group-sel");
  const groupNew = document.getElementById("group-new");
  const currentGroup = () => (groupSel && groupSel.value !== "__new" ? groupSel.value : groupNew.value).trim();
  const refreshInherit = () => { document.getElementById("identity-inherit").textContent = inheritText(currentGroup()); };
  if (groupSel) groupSel.addEventListener("change", () => {
    const isNew = groupSel.value === "__new";
    groupNew.hidden = !isNew;
    groupNew.required = isNew;
    if (isNew) groupNew.focus();
    refreshInherit();
  });
  groupNew.addEventListener("input", refreshInherit);
  document.getElementById("host-form").addEventListener("submit", async (ev) => {
    if (ev.submitter && ev.submitter.value === "cancel") return;
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = {
      original: host && !clone ? host.name : "",
      group: currentGroup(),
      host: {
        name: f.get("name").trim(),
        address: f.get("address").trim(),
        port: Number(f.get("port")) || 0,
        user: f.get("user").trim(),
        identity: (f.get("identity_sel") === "__custom" ? f.get("identity_custom") : f.get("identity_sel")).trim(),
        tags: f.get("tags").split(",").map(s => s.trim()).filter(Boolean),
      },
    };
    try {
      await api("/api/inventory/hosts", { method: "PUT", body });
      dialog.close();
      state.inv = null;
      await renderInventory();
      if (!host || clone || body.host.address !== host.address || body.host.port !== (raw.port || 0)) {
        const row = view.querySelector(`tr[data-host="${CSS.escape(body.host.name)}"]`);
        if (row) row.querySelector('[data-act="test"]').click();
      }
    } catch (e) {
      document.getElementById("form-err").textContent = e.message;
    }
  });
}

function confirmDialog(title, bodyHTML, okLabel, danger) {
  return new Promise(resolve => {
    dialog.innerHTML = `<div class="dlg"><h2>${esc(title)}</h2>${bodyHTML}
      <div class="foot"><button class="ghost" id="dlg-cancel">${esc(t("ui.inv.cancel"))}</button>
      <button class="${danger ? "danger" : ""}" id="dlg-ok">${esc(okLabel)}</button></div></div>`;
    const done = v => { dialog.close(); resolve(v); };
    document.getElementById("dlg-cancel").addEventListener("click", () => done(false));
    document.getElementById("dlg-ok").addEventListener("click", () => done(true));
    dialog.addEventListener("cancel", () => resolve(false), { once: true });
    dialog.showModal();
  });
}

async function deleteHost(name) {
  const ok = await confirmDialog(t("ui.inv.delete"), `<p>${esc(t("ui.inv.confirmdelete", name))}</p>`, t("ui.inv.delete"), true);
  if (!ok) return;
  await api(`/api/inventory/hosts/${encodeURIComponent(name)}`, { method: "DELETE" });
  state.inv = null;
  renderInventory();
}

function jobReason(h) {
  const inv = (state.inv && state.inv.hosts || []).find(x => x.name === h.name) || {};
  return connError(h.reason, inv.address || h.name, inv.port || 22, h.error);
}

function connError(reason, address, port, raw) {
  if (reason && state.dict["conn_" + reason]) return t("conn_" + reason, address, port);
  return t("ui.test.fail", raw);
}

async function testHost(name, line) {
  line.className = "status-line meta";
  line.textContent = t("ui.test.running");
  try {
    const r = await api(`/api/hosts/${encodeURIComponent(name)}/test`, { method: "POST" });
    if (r.ok) {
      line.className = "status-line ok";
      line.textContent = t("ui.test.ok", r.user, t("ui.priv." + r.privileges), r.os);
      return;
    }
    if (r.unknown_host) {
      line.className = "status-line err";
      line.textContent = t("ui.trust.title");
      const ok = await confirmDialog(t("ui.trust.title"),
        `<p>${esc(t("ui.trust.body", name))}</p><div class="fp">${esc(r.type)}<br>${esc(r.fingerprint)}</div>`, t("ui.trust.ok"));
      if (!ok) return;
      await api(`/api/hosts/${encodeURIComponent(name)}/trust`, { method: "POST", body: { fingerprint: r.fingerprint } });
      line.className = "status-line ok";
      line.textContent = t("ui.trust.done");
      return testHost(name, line);
    }
    line.className = "status-line err";
    line.textContent = connError(r.reason, r.address, r.port, r.error);
    line.title = r.error;
  } catch (e) {
    line.className = "status-line err";
    line.textContent = t("ui.test.fail", e.message);
  }
}

async function renderReports() {
  const list = await api("/api/reports");
  const rows = list.map(m => `
    <tr>
      <td class="mono">${esc(fmtTime(m.generated_at))}</td>
      <td class="num">${m.reachable} / ${m.hosts}</td>
      <td class="num${m.critical ? " lvl-critical" : ""}">${m.critical}</td>
      <td class="num${m.high ? " lvl-critical" : ""}">${m.high}</td>
      <td class="num">${m.medium}</td>
      <td><div class="actions">
        <a class="btn ghost small" href="/api/reports/${esc(m.id)}?format=html&from=reports&${langParam()}">HTML</a>
        <a class="btn ghost small" data-download href="/api/reports/${esc(m.id)}?format=html&download=1&${langParam()}" title="${esc(t("ui.dl.html"))}">HTML &darr;</a>
        <a class="btn ghost small" data-download href="/api/reports/${esc(m.id)}?format=json&download=1">JSON</a>
        <a class="btn ghost small" data-download href="/api/reports/${esc(m.id)}?format=md&download=1&${langParam()}">MD</a>
        <button class="danger small" data-del="${esc(m.id)}">${esc(t("ui.inv.delete"))}</button>
      </div></td>
    </tr>`).join("");
  view.innerHTML = `
    <header class="page-head reveal"><div class="eyebrow">farol-guard</div><h1>${esc(t("ui.reports.title"))}</h1></header>
    ${rows ? `<div class="section-head"><div class="meta">${esc(t("ui.reports.count", list.length))}</div>
      <button class="danger" id="clear-reports" type="button">${esc(t("ui.reports.clear"))}</button></div>` : ""}
    ${rows ? `<div class="table-wrap reveal" style="--i:1"><table>
      <thead><tr><th>${esc(t("ui.reports.when"))}</th><th class="num">${esc(t("report.hosts"))}</th><th class="num">${esc(t("sev.critical"))}</th><th class="num">${esc(t("sev.high"))}</th><th class="num">${esc(t("sev.medium"))}</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>` : `<div class="empty"><p class="meta">${esc(t("ui.reports.empty"))}</p></div>`}`;

  view.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
    const m = list.find(x => x.id === b.dataset.del);
    const ok = await confirmDialog(t("ui.reports.deltitle"), `<p>${esc(t("ui.reports.delbody", fmtTime(m.generated_at)))}</p>`, t("ui.inv.delete"), true);
    if (!ok) return;
    await api(`/api/reports/${encodeURIComponent(m.id)}`, { method: "DELETE" });
    renderReports();
  }));
  const clear = document.getElementById("clear-reports");
  if (clear) clear.addEventListener("click", () => {
    dialog.innerHTML = `<div class="dlg"><h2>${esc(t("ui.reports.clear"))}</h2>
      <p>${esc(t("ui.reports.clearbody", list.length))}</p>
      <label class="check"><input type="checkbox" id="keep-latest" checked>${esc(t("ui.reports.keeplatest"))}</label>
      <div class="status-line err" id="clear-err"></div>
      <div class="foot"><button class="ghost" id="clear-cancel">${esc(t("ui.inv.cancel"))}</button>
      <button class="danger" id="clear-ok">${esc(t("ui.reports.clear"))}</button></div></div>`;
    dialog.showModal();
    document.getElementById("clear-cancel").addEventListener("click", () => dialog.close());
    document.getElementById("clear-ok").addEventListener("click", async () => {
      const keep = document.getElementById("keep-latest").checked ? "1" : "0";
      try {
        await api(`/api/reports?keep_latest=${keep}`, { method: "DELETE" });
        dialog.close();
        renderReports();
      } catch (e) { document.getElementById("clear-err").textContent = e.message; }
    });
  });
}

function scopeOptions() {
  const groups = [...(state.inv.groups || [])].sort();
  const hosts = (state.inv.hosts || []).map(h => h.name);
  return `<option value="">-</option>` +
    `<option value="all">${esc(t("ui.scope.all"))}</option>` +
    groups.map(g => `<option value="group:${esc(g)}">${esc(t("ui.scope.group", g))}</option>`).join("") +
    hosts.map(h => `<option value="host:${esc(h)}">${esc(t("ui.scope.host", h))}</option>`).join("");
}

function scopePickerHTML() {
  const groups = [...(state.inv.groups || [])].sort((a, b) => a.localeCompare(b));
  const hosts = (state.inv.hosts || []).map(h => h.name);
  return `
  <div class="field scope-picker" id="scope-picker">
    <span>${esc(t("ui.scope"))} <span class="meta" data-scope-summary></span></span>
    <input type="search" data-scope-search placeholder="${esc(t("ui.filter.searchph"))}">
    <div class="scope-list">
      <label class="check scope-all"><input type="checkbox" data-scope-all>${esc(t("ui.scope.all"))}</label>
      <div class="scope-head">${esc(t("ui.f.group"))}</div>
      ${groups.map(g => `<label class="check" data-scope-item="${esc(g.toLowerCase())}"><input type="checkbox" data-scope-group="${esc(g)}">${esc(g)} <span class="meta">${(state.inv.hosts || []).filter(h => h.group === g).length}</span></label>`).join("")}
      <div class="scope-head">Hosts</div>
      ${hosts.map(h => `<label class="check" data-scope-item="${esc(h.toLowerCase())}"><input type="checkbox" data-scope-host="${esc(h)}">${esc(h)}</label>`).join("")}
    </div>
  </div>`;
}

function bindScopePicker(root) {
  const el = root.querySelector("#scope-picker");
  const all = el.querySelector("[data-scope-all]");
  const boxes = [...el.querySelectorAll("[data-scope-group], [data-scope-host]")];
  const summary = el.querySelector("[data-scope-summary]");
  const update = () => {
    const g = boxes.filter(b => b.checked && b.dataset.scopeGroup).length;
    const h = boxes.filter(b => b.checked && b.dataset.scopeHost).length;
    summary.textContent = all.checked ? `· ${t("ui.scope.all")}` : (g || h) ? `· ${t("ui.scope.summary", g, h)}` : "";
  };
  all.addEventListener("change", () => { boxes.forEach(b => { b.checked = false; b.disabled = all.checked; }); update(); });
  boxes.forEach(b => b.addEventListener("change", update));
  el.querySelector("[data-scope-search]").addEventListener("input", ev => {
    const q = ev.target.value.trim().toLowerCase();
    el.querySelectorAll("[data-scope-item]").forEach(l => { l.hidden = q && !l.dataset.scopeItem.includes(q); });
  });
  update();
  return () => {
    if (all.checked) return { groups: [...state.inv.groups], hosts: [] };
    return {
      groups: boxes.filter(b => b.checked && b.dataset.scopeGroup).map(b => b.dataset.scopeGroup),
      hosts: boxes.filter(b => b.checked && b.dataset.scopeHost).map(b => b.dataset.scopeHost),
    };
  };
}

function scopeBody(value) {
  const body = { groups: [], hosts: [] };
  if (value === "all") body.groups = [...state.inv.groups];
  if (value.startsWith("group:")) body.groups.push(value.slice(6));
  if (value.startsWith("host:")) body.hosts.push(value.slice(5));
  return body;
}

function splitCSV(v) { return String(v || "").split(",").map(s => s.trim()).filter(Boolean); }

async function busy(btn, fn, statusEl, statusText) {
  const label = btn.innerHTML;
  const scope = btn.closest("form, .dlg");
  const ctrls = scope ? [...scope.querySelectorAll("input, select, button, textarea")].filter(c => c !== btn && !c.disabled) : [];
  btn.disabled = true;
  btn.classList.add("is-busy");
  btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${esc(t("ui.busy.running"))}`;
  ctrls.forEach(c => { c.disabled = true; });
  if (statusEl && statusText) { statusEl.className = "status-line meta"; statusEl.textContent = statusText; }
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove("is-busy");
    btn.innerHTML = label;
    ctrls.forEach(c => { c.disabled = false; });
    if (statusEl && statusText && statusEl.textContent === statusText) statusEl.textContent = "";
  }
}

function countHosts(body) {
  return state.inv ? scopeHosts({ groups: body.groups || [], hosts: body.hosts || [] }).length : 0;
}

function allOK(results) {
  return (results || []).length > 0 && results.every(r => r.ok);
}

function resultsHTML(results) {
  if (!results || !results.length) return "";
  const cls = st => st === "ok" ? "ok" : st === "fail" ? "critical" : st === "dry-run" ? "low" : "";
  let ok = 0, fail = 0;
  const rows = [];
  for (const r of results) {
    if (r.ok) ok++; else fail++;
    const byUser = new Map();
    for (const e of r.events || []) {
      if (!byUser.has(e.user)) byUser.set(e.user, []);
      byUser.get(e.user).push(e);
    }
    for (const [user, evs] of byUser) {
      const steps = evs.map(e => `<span class="step"><span class="mono">${esc(e.action)}</span><span class="badge ${cls(e.status)}">${esc(e.status)}</span></span>`).join("");
      const notes = evs.filter(e => e.message).map(e => {
        const m = String(e.message);
        const bk = m.match(/backup (\S+)/);
        const short = bk ? m.replace(bk[1], bk[1].split("/").pop()) : m;
        return `<div title="${esc(m)}">${esc(short)}</div>`;
      }).join("");
      rows.push(`<tr><td class="nowrap">${esc(r.host)}</td><td class="mono nowrap">${esc(user)}</td><td><div class="steps">${steps}</div></td><td class="result-notes mono">${notes}</td></tr>`);
    }
  }
  return `<div class="result-summary"><span class="badge ok">${ok} ok</span>${fail ? `<span class="badge critical">${fail} ${esc(t("ui.res.fail"))}</span>` : ""}</div>
    <div class="table-wrap"><table class="result-table"><thead><tr><th>Host</th><th>${esc(t("c.user"))}</th><th>${esc(t("ui.keys.action"))}</th><th></th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

async function renderKeys() {
  state.inv = await api("/api/inventory");
  const data = await api("/api/keys");
  const uses = fp => (data.fleet.find(f => f.fingerprint === fp) || { where: [] }).where.length;
  const localRows = data.local.map(k => `
    <tr>
      <td>${esc(k.name)}<div class="meta mono">${esc(k.comment)}</div></td>
      <td class="mono wrap-any">${esc(k.fingerprint)}</td>
      <td><div class="chips">
        ${k.source === "ssh" ? `<span class="badge low">~/.ssh</span>` : ""}
        ${k.in_agent ? `<span class="badge ok">ssh-agent</span>` : ""}
        ${k.retired ? `<span class="badge medium">${esc(t("ui.keys.retired"))}</span>` : ""}
        <span class="badge ${k.encrypted ? "ok" : ""}">${esc(t(k.managed && k.encrypted ? "ui.keys.keyring" : k.encrypted ? "ui.keys.encrypted" : "ui.keys.plain"))}</span></div></td>
      <td class="num">${uses(k.fingerprint)}</td>
      <td><div class="actions">
        ${k.retired ? "" : `<button class="ghost small" data-deploy="${esc(k.name)}">${esc(t("ui.keys.deploy"))}</button>`}
        ${k.source !== "ssh" && k.name !== "farol-app" ? `<button class="danger small" data-delkey="${esc(k.name)}">${esc(t("ui.inv.delete"))}</button>` : ""}
      </div></td>
    </tr>`).join("");
  const fleetRows = data.fleet.map((f, i) => `
    <tr>
      <td class="mono nowrap" title="${esc(f.fingerprint)}">${esc(f.fingerprint.slice(0, 22))}&hellip;<div class="meta">${esc(f.type)}</div></td>
      <td>${farolBadge(f)}<div class="meta mono">${esc(f.comment)}</div></td>
      <td><div class="chips">${f.where.map(w => `<span class="chip">${esc(w.host)}:${esc(w.user)}</span>`).join("")}</div></td>
      <td><div class="actions"><button class="danger small" data-remove="${i}">${esc(t("ui.keys.remove"))}</button></div></td>
    </tr>`).join("");
  const app = data.app;
  view.innerHTML = `
    <header class="page-head reveal"><div class="eyebrow">${esc(t("ui.keys.dir", data.dir))}</div><h1>${esc(t("ui.keys.title"))}</h1></header>
    ${agentNotice()}
    <section class="bento" style="margin:0 0 56px">
      <div class="card wide reveal" style="--i:1">
        <h3>${esc(t("ui.keys.app"))}</h3>
        <p class="meta">${esc(t("ui.keys.app.body"))}</p>
        <p class="mono" style="margin:0 0 4px">${app ? esc(app.fingerprint) : esc(t("ui.keys.app.missing"))}</p>
        <p class="meta mono" style="margin:0 0 10px">${esc(t("ui.keys.app.instance", data.instance))}</p>
        ${app ? (app.encrypted
          ? `<p style="margin:0 0 16px"><span class="badge ok">${esc(t("ui.keys.app.protected"))}</span></p>`
          : `<div class="notice" style="margin:0 0 16px">${esc(t(data.secret_store === "unavailable" ? "ui.keys.app.nostore" : "ui.keys.app.unprotected"))}</div>`) : ""}
        <div class="toolbar">
          <button id="app-install" type="button">${esc(t(app ? "ui.keys.app.more" : "ui.keys.app.install"))}</button>
          ${app ? `<button class="ghost" id="app-rotate" type="button">${esc(t("ui.keys.app.rotate"))}</button>` : ""}
          ${app && !app.encrypted && data.secret_store !== "unavailable" ? `<button class="ghost" id="app-protect" type="button">${esc(t("ui.keys.app.protect"))}</button>` : ""}
        </div>
      </div>
      <div class="card wide reveal" style="--i:2">
        <h3>${esc(t("ui.keys.new"))}</h3>
        <form id="new-key" style="display:grid;gap:12px;margin-top:14px">
          <label class="field">${esc(t("ui.keys.name"))}<input type="text" name="name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" placeholder="grp-production-2026"></label>
          <label class="field">${esc(t("ui.keys.passphrase"))}<input type="password" name="passphrase" autocomplete="new-password"></label>
          <label class="field">${esc(t("ui.keys.passphrase2"))}<input type="password" name="passphrase2" autocomplete="new-password"></label>
          <div class="toolbar"><button type="submit">${esc(t("ui.keys.new"))}</button><span class="status-line" id="new-key-status"></span></div>
        </form>
      </div>
    </section>
    <div class="section-head"><h2>${esc(t("ui.keys.local"))}</h2></div>
    ${localRows ? `<div class="table-wrap"><table><thead><tr><th>${esc(t("c.name"))}</th><th>${esc(t("c.fingerprint"))}</th><th></th><th class="num">${esc(t("ui.keys.where"))}</th><th></th></tr></thead><tbody>${localRows}</tbody></table></div>`
      : `<p class="meta">${esc(t("ui.keys.none"))}</p>`}
    <div class="section-head" style="margin-top:72px"><h2>${esc(t("ui.keys.fleet"))}</h2></div>
    <p class="meta">${esc(t("ui.keys.fleetnote", data.report_id || "-"))}</p>
    ${fleetRows ? `<div class="table-wrap"><table><thead><tr><th>${esc(t("c.fingerprint"))}</th><th>${esc(t("c.label"))}</th><th>${esc(t("ui.keys.where"))}</th><th></th></tr></thead><tbody>${fleetRows}</tbody></table></div>` : ""}`;

  document.getElementById("new-key").addEventListener("submit", async ev => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const st = document.getElementById("new-key-status");
    if (f.get("passphrase") !== f.get("passphrase2")) {
      st.className = "status-line err"; st.textContent = t("ui.keys.passmismatch");
      return;
    }
    try {
      await api("/api/keys", { method: "POST", body: { name: f.get("name").trim(), passphrase: f.get("passphrase") } });
      renderKeys();
    } catch (e) { st.className = "status-line err"; st.textContent = e.message; }
  });
  document.getElementById("app-install").addEventListener("click", () => appDialog());
  const prot = document.getElementById("app-protect");
  if (prot) prot.addEventListener("click", async () => {
    const ok = await confirmDialog(t("ui.keys.app.protect"), `<p>${esc(t("ui.keys.app.protectbody"))}</p>`, t("ui.keys.app.protect"));
    if (!ok) return;
    try {
      await busy(prot, () => api("/api/keys/app-protect", { method: "POST" }));
      renderKeys();
    } catch (e) { alertBox(e.message); }
  });
  const rot = document.getElementById("app-rotate");
  if (rot) rot.addEventListener("click", () => appRotateDialog());
  view.querySelectorAll("[data-deploy]").forEach(b => b.addEventListener("click", () => {
    deployDialog(data.local.find(k => k.name === b.dataset.deploy), data.fleet);
  }));
  view.querySelectorAll("[data-delkey]").forEach(b => b.addEventListener("click", async () => {
    const k = data.local.find(x => x.name === b.dataset.delkey);
    const n = uses(k.fingerprint);
    const ok = await confirmDialog(t("ui.keys.del.title"), `<p>${esc(t(n ? "ui.keys.del.inuse" : "ui.keys.del.body", k.name, n))}</p><div class="fp">${esc(k.fingerprint)}</div>`, t("ui.inv.delete"), true);
    if (!ok) return;
    try {
      await busy(b, () => api(`/api/keys/${encodeURIComponent(k.name)}${n ? "?force=1" : ""}`, { method: "DELETE" }));
      renderKeys();
    } catch (e) { alertBox(e.message); }
  }));
  view.querySelectorAll("[data-remove]").forEach(b => b.addEventListener("click", () => removeDialog(data.fleet[Number(b.dataset.remove)])));
}

function fixDialog(body) {
  dialog.innerHTML = `<div class="dlg dlg-wide"><h2>${esc(t("fix.title"))}</h2><div class="fix-body fix-modal"></div>
    <div class="foot"><button type="button" id="fix-close">${esc(t("ui.close"))}</button></div></div>`;
  const box = dialog.querySelector(".fix-modal");
  box.innerHTML = body.innerHTML;
  box.querySelectorAll(".fix-code").forEach(pre => {
    const wrap = document.createElement("div");
    wrap.className = "fix-cmdbox";
    pre.replaceWith(wrap);
    wrap.appendChild(pre);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "ghost fix-copy";
    b.textContent = t("fix.copy");
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.textContent);
        toast(t("fix.copied"));
      } catch (e) {
        const range = document.createRange();
        range.selectNodeContents(pre);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
    wrap.appendChild(b);
  });
  dialog.showModal();
  document.getElementById("fix-close").addEventListener("click", () => dialog.close());
}

function alertBox(msg) {
  dialog.innerHTML = `<div class="dlg"><div class="notice err">${esc(msg)}</div><div class="foot"><button id="alert-ok">${esc(t("ui.close"))}</button></div></div>`;
  dialog.showModal();
  document.getElementById("alert-ok").addEventListener("click", () => dialog.close());
}

function farolBadge(f) {
  if (f.farol === "this") return `<span class="badge ok">${esc(t("t.farol.this"))}</span>`;
  if (f.farol === "this-retired") return `<span class="badge medium">${esc(t("t.farol.retired"))}</span>`;
  if (f.farol === "other") return `<span class="badge medium">${esc(t("t.farol.other", f.farol_host))}</span>`;
  if (f.label) return `<span class="badge ok">${esc(f.label)}</span>`;
  return `<span class="badge low">${esc(t("t.unknown"))}</span>`;
}

async function appRotateDialog() {
  const hosts = await api("/api/keys/app-hosts").catch(() => []);
  dialog.innerHTML = `
    <form id="rot-form" class="dlg dlg-wide">
      <h2>${esc(t("ui.keys.app.rotate"))}</h2>
      <p class="meta">${esc(t(hosts.length ? "ui.keys.app.rotatebody" : "ui.keys.app.rotatenone"))}</p>
      ${hosts.length ? `<div class="chips">${hosts.map(h => `<span class="chip">${esc(h)}</span>`).join("")}</div>
      <label class="field">${esc(t("ui.keys.op.from"))}<input type="text" name="from" class="mono-input"></label>
      <label class="check"><input type="checkbox" name="dry" checked>${esc(t("ui.keys.op.dry"))}</label>` : ""}
      <div id="rot-results"></div>
      <div class="status-line" id="rot-status"></div>
      <div class="foot"><button type="button" class="ghost" id="rot-close">${esc(t("ui.close"))}</button>
        ${hosts.length ? `<button type="submit" class="danger" id="rot-run">${esc(t("ui.keys.app.rotate"))}</button>` : ""}</div>
    </form>`;
  dialog.showModal();
  document.getElementById("rot-close").addEventListener("click", () => { dialog.close(); renderKeys(); });
  document.getElementById("rot-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const st = document.getElementById("rot-status");
    const btn = document.getElementById("rot-run");
    try {
      const res = await busy(btn, () => api("/api/keys/app-rotate", { method: "POST", body: { from: splitCSV(f.get("from")), dry_run: f.get("dry") === "on" } }),
        st, t("ui.busy.connecting", hosts.length));
      document.getElementById("rot-results").innerHTML = resultsHTML(res.deploy) + resultsHTML(res.remove);
      if (f.get("dry") === "on") { st.className = "status-line meta"; st.textContent = ""; }
      else if (res.completed) { st.className = "status-line ok"; st.textContent = t("ui.keys.app.completed", res.retired); btn.hidden = true; }
      else { st.className = "status-line err"; st.textContent = t("ui.keys.app.partial"); }
    } catch (e) { st.className = "status-line err"; st.textContent = e.message; }
  });
}

function deployDialog(key, fleet) {
  const others = fleet.filter(f => f.fingerprint !== key.fingerprint);
  const whereText = f => {
    const list = f.where.map(w => `${w.host}:${w.user}`);
    return t("ui.keys.old.where", list.length) + ": " + list.slice(0, 4).join(", ") + (list.length > 4 ? ", ..." : "");
  };
  const oldItems = others.map(f => `
      <label class="check old-item" data-search="${esc([f.label, f.comment, f.fingerprint, ...f.where.map(w => w.host)].join(" ").toLowerCase())}">
        <input type="radio" name="old" value="fp:${esc(f.fingerprint)}">
        <span class="old-text"><span class="old-name">${esc(f.label || f.comment || f.fingerprint.slice(0, 22))} ${farolBadge(f)}</span>
          <span class="meta mono">${esc(f.fingerprint.slice(0, 26))}&hellip; &middot; ${esc(whereText(f))}</span></span>
      </label>`).join("");
  dialog.innerHTML = `
    <form id="op-form" class="dlg">
      <h2>${esc(t("ui.keys.op.title", key.name))}</h2>
      <div class="fp">${esc(key.fingerprint)}</div>
      ${scopePickerHTML()}
      <label class="field">${esc(t("ui.keys.op.users"))}<input type="text" name="users" placeholder="root"></label>
      <div class="field old-picker">
        <span>${esc(t("ui.keys.op.old"))}</span>
        <label class="check"><input type="radio" name="old" value="keep" checked>${esc(t("ui.keys.op.keep"))}</label>
        <label class="check"><input type="radio" name="old" value="current">${esc(t("ui.keys.op.current"))}</label>
        ${others.length ? `<input type="search" data-old-search placeholder="${esc(t("ui.keys.old.search"))}">
        <div class="scope-list old-list">${oldItems}</div>` : ""}
      </div>
      <label class="field">${esc(t("ui.keys.op.from"))}<input type="text" name="from" class="mono-input" placeholder="203.0.113.10, 10.0.0.0/8"></label>
      ${key.encrypted && !key.managed && !key.in_agent ? `<div class="field">${esc(t("ui.keys.op.pass", key.name))}
        <div class="pass-row"><input type="password" name="passphrase" required autocomplete="off">
          <button type="button" class="ghost" id="pass-test">${esc(t("ui.keys.passtest"))}</button></div>
        <div class="status-line" id="pass-status"></div></div>` : ""}
      <label class="check"><input type="checkbox" name="setid">${esc(t("ui.keys.op.setid"))}</label>
      <label class="check"><input type="checkbox" name="dry" checked>${esc(t("ui.keys.op.dry"))}</label>
      <div id="op-results"></div>
      <div class="status-line" id="op-status"></div>
      <div class="status-line err" id="op-err"></div>
      <div class="foot">
        <button type="button" class="ghost" id="op-close">${esc(t("ui.close"))}</button>
        <button type="button" class="danger" id="op-remove" hidden></button>
        <button type="submit" id="op-run">${esc(t("ui.keys.op.run"))}</button>
      </div>
    </form>`;
  dialog.showModal();
  const form = document.getElementById("op-form");
  const getScope = bindScopePicker(form);
  const passTest = form.querySelector("#pass-test");
  if (passTest) passTest.addEventListener("click", async () => {
    const st = form.querySelector("#pass-status");
    const pass = form.querySelector('input[name="passphrase"]').value;
    try {
      await busy(passTest, () => api(`/api/keys/${encodeURIComponent(key.name)}/check-passphrase`, { method: "POST", body: { passphrase: pass } }));
      st.className = "status-line ok"; st.textContent = t("ui.keys.passok");
    } catch (e) { st.className = "status-line err"; st.textContent = t("ui.keys.passbad"); }
  });
  const oldSearch = form.querySelector("[data-old-search]");
  if (oldSearch) oldSearch.addEventListener("input", () => {
    const q = oldSearch.value.trim().toLowerCase();
    form.querySelectorAll(".old-item").forEach(l => { l.hidden = q && !l.dataset.search.includes(q); });
  });
  const out = document.getElementById("op-results");
  const err = document.getElementById("op-err");
  const rm = document.getElementById("op-remove");
  document.getElementById("op-close").addEventListener("click", () => { dialog.close(); renderKeys(); });
  const base = () => {
    const f = new FormData(form);
    const old = f.get("old") || "keep";
    return {
      ...getScope(),
      key: key.name, passphrase: f.get("passphrase") || "",
      users: splitCSV(f.get("users")), from: splitCSV(f.get("from")),
      dry_run: f.get("dry") === "on", set_identity: f.get("setid") === "on",
      remove_current: old === "current", fingerprint: old.startsWith("fp:") ? old.slice(3) : "",
      old,
    };
  };
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    err.textContent = ""; rm.hidden = true;
    const b = base();
    if (!b.groups.length && !b.hosts.length) { err.textContent = t("ui.scope.required"); return; }
    const runBtn = document.getElementById("op-run");
    const st = document.getElementById("op-status");
    try {
      const res = await busy(runBtn, () => api("/api/keys/deploy", { method: "POST", body: b }), st, t("ui.busy.connecting", countHosts(b)));
      let html = resultsHTML(res.results);
      if (!b.dry_run && allOK(res.results)) runBtn.hidden = true;
      const good = res.results.filter(r => r.ok).map(r => r.host);
      if (b.old !== "keep" && good.length) {
        if (b.dry_run) {
          const res2 = await busy(runBtn, () => api("/api/keys/remove", { method: "POST", body: { ...b, groups: [], hosts: good } }), st, t("ui.busy.connecting", good.length));
          html += resultsHTML(res2.results);
        } else {
          rm.textContent = t("ui.keys.op.removenow", good.length);
          rm.hidden = false;
          runBtn.hidden = true;
          rm.onclick = async () => {
            try {
              const res2 = await busy(rm, () => api("/api/keys/remove", { method: "POST", body: { ...b, groups: [], hosts: good } }), st, t("ui.busy.connecting", good.length));
              out.innerHTML += resultsHTML(res2.results) + `<p class="note">${esc(t("ui.keys.op.done"))}</p>`;
              rm.hidden = true;
            } catch (e) { err.textContent = e.message; }
          };
        }
      }
      out.innerHTML = html;
    } catch (e) {
      err.textContent = e.message;
    }
  });
}

function removeDialog(fk) {
  const hosts = [...new Set(fk.where.map(w => w.host))];
  const users = [...new Set(fk.where.map(w => w.user))];
  dialog.innerHTML = `
    <div class="dlg">
      <h2>${esc(t("ui.keys.rm.title"))}</h2>
      <p>${esc(t("ui.keys.rm.body", fk.label || fk.comment || "", fk.where.length))}</p>
      <div class="fp">${esc(fk.fingerprint)}</div>
      <div class="chips">${fk.where.map(w => `<span class="chip">${esc(w.host)}:${esc(w.user)}</span>`).join("")}</div>
      <label class="check"><input type="checkbox" id="rm-dry" checked>${esc(t("ui.keys.op.dry"))}</label>
      <div id="rm-results"></div>
      <div class="status-line" id="rm-status"></div>
      <div class="status-line err" id="rm-err"></div>
      <div class="foot"><button class="ghost" id="rm-close">${esc(t("ui.close"))}</button>
        <button class="danger" id="rm-run">${esc(t("ui.keys.remove"))}</button></div>
    </div>`;
  dialog.showModal();
  document.getElementById("rm-close").addEventListener("click", () => { dialog.close(); renderKeys(); });
  document.getElementById("rm-run").addEventListener("click", async ev => {
    const btn = ev.currentTarget;
    const dry = document.getElementById("rm-dry").checked;
    try {
      const res = await busy(btn, () => api("/api/keys/remove", { method: "POST", body: { hosts, users, fingerprint: fk.fingerprint, dry_run: dry } }),
        document.getElementById("rm-status"), t("ui.busy.connecting", hosts.length));
      document.getElementById("rm-results").innerHTML = resultsHTML(res.results);
      if (!dry && allOK(res.results)) btn.hidden = true;
    } catch (e) { document.getElementById("rm-err").textContent = e.message; }
  });
}

function appDialog() {
  dialog.innerHTML = `
    <form id="app-form" class="dlg">
      <h2>${esc(t("ui.keys.app"))}</h2>
      <p class="meta">${esc(t("ui.keys.app.body"))}</p>
      ${scopePickerHTML()}
      <label class="field">${esc(t("ui.keys.op.from"))}<input type="text" name="from" class="mono-input"></label>
      <label class="check"><input type="checkbox" name="setdefault">${esc(t("ui.keys.app.setdefault"))}</label>
      <label class="check"><input type="checkbox" name="dry" checked>${esc(t("ui.keys.op.dry"))}</label>
      <div id="app-results"></div>
      <div class="status-line" id="app-status"></div>
      <div class="status-line err" id="app-err"></div>
      <div class="foot"><button type="button" class="ghost" id="app-close">${esc(t("ui.close"))}</button>
        <button type="submit" id="app-run">${esc(t("ui.keys.app.install"))}</button></div>
    </form>`;
  dialog.showModal();
  document.getElementById("app-close").addEventListener("click", () => { dialog.close(); renderKeys(); });
  const getAppScope = bindScopePicker(document.getElementById("app-form"));
  document.getElementById("app-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const scope = getAppScope();
    if (!scope.groups.length && !scope.hosts.length) { document.getElementById("app-err").textContent = t("ui.scope.required"); return; }
    const body = { ...scope, from: splitCSV(f.get("from")),
      set_default: f.get("setdefault") === "on", dry_run: f.get("dry") === "on" };
    const btn = document.getElementById("app-run");
    const st = document.getElementById("app-status");
    document.getElementById("app-err").textContent = "";
    try {
      const res = await busy(btn, () => api("/api/keys/app-init", { method: "POST", body }), st, t("ui.busy.connecting", countHosts(body)));
      document.getElementById("app-results").innerHTML =
        (res.will_create ? `<p class="note">${esc(t(body.dry_run ? "ui.keys.app.willcreate" : "ui.keys.app.created"))}</p>` : "") + resultsHTML(res.results);
      if (!body.dry_run && allOK(res.results)) {
        btn.hidden = true;
        st.className = "status-line ok";
        st.textContent = t("ui.res.done");
      }
    } catch (e) { document.getElementById("app-err").textContent = e.message; }
  });
}

let connOK = null;

async function checkBackend() {
  let ok = false;
  try {
    const r = await fetch("/api/ping", { cache: "no-store", credentials: "same-origin" });
    ok = r.ok;
  } catch (e) { ok = false; }
  if (ok === connOK) return;
  connOK = ok;
  const el = document.getElementById("conn");
  el.classList.toggle("down", !ok);
  const label = t(ok ? "ui.conn.ok" : "ui.conn.down");
  el.title = label;
  el.setAttribute("aria-label", label);
}

function startConnWatch() {
  checkBackend();
  setInterval(checkBackend, 5000);
  window.addEventListener("focus", checkBackend);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) checkBackend(); });
}

function toast(msg, kind = "ok") {
  let box = document.getElementById("toasts");
  if (!box) {
    box = document.createElement("div");
    box.id = "toasts";
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    document.body.appendChild(box);
  }
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 300); }, 6000);
}

const saveTypes = {
  json: { description: "JSON", accept: { "application/json": [".json"] } },
  md: { description: "Markdown", accept: { "text/markdown": [".md"] } },
  html: { description: "HTML", accept: { "text/html": [".html"] } },
};

async function downloadReport(a) {
  const r = await fetch(a.href, { credentials: "same-origin", cache: "no-store" });
  if (!r.ok) throw new Error(r.statusText);
  const cd = r.headers.get("Content-Disposition") || "";
  const m = cd.match(/filename="([^"]+)"/);
  const name = m ? m[1] : "farol-report";
  const ext = name.split(".").pop();
  const blob = await r.blob();
  if (window.showSaveFilePicker) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: name, types: saveTypes[ext] ? [saveTypes[ext]] : undefined });
    } catch (e) {
      if (e.name === "AbortError") return;
      throw e;
    }
    const w = await handle.createWritable();
    await w.write(blob);
    await w.close();
    toast(t("ui.dl.saved", handle.name || name));
    return;
  }
  const url = URL.createObjectURL(blob);
  const tmp = document.createElement("a");
  tmp.href = url;
  tmp.download = name;
  document.body.appendChild(tmp);
  tmp.click();
  tmp.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast(t("ui.dl.started", name));
}

document.addEventListener("click", ev => {
  const a = ev.target.closest && ev.target.closest("a[data-download]");
  if (!a) return;
  ev.preventDefault();
  downloadReport(a).catch(e => toast(t("ui.error", e.message), "err"));
});

const themes = ["auto", "light", "dark"];

function currentTheme() {
  const t = storeGet("farol.theme");
  return themes.includes(t) ? t : "auto";
}

const themeIcons = {
  auto: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 3.5a8.5 8.5 0 0 1 0 17Z" fill="currentColor"/></svg>',
  light: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><g stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.55 1.55M17.15 17.15l1.55 1.55M5.3 18.7l1.55-1.55M17.15 6.85l1.55-1.55"/></g></svg>',
  dark: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
};

function updateThemeButton() {
  const b = document.getElementById("theme-toggle");
  const cur = currentTheme();
  b.innerHTML = themeIcons[cur];
  b.title = t("ui.theme." + cur) + " - " + t("ui.theme.title");
  b.setAttribute("aria-label", t("ui.theme." + cur));
}

document.getElementById("theme-toggle").addEventListener("click", () => {
  const next = themes[(themes.indexOf(currentTheme()) + 1) % themes.length];
  storeSet("farol.theme", next);
  if (next === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", next);
  updateThemeButton();
});

document.getElementById("lang-toggle").addEventListener("click", async () => {
  const next = state.lang === "pt-BR" ? "en" : "pt-BR";
  storeSet("farol.lang", next);
  await loadLang(next);
  connOK = null;
  checkBackend();
  render();
});

window.addEventListener("hashchange", render);

(async () => {
  const saved = storeGet("farol.lang");
  const lang = saved || ((navigator.language || "").toLowerCase().startsWith("pt") ? "pt-BR" : "en");
  state.meta = await api("/api/meta").catch(() => ({}));
  await loadLang(lang);
  startConnWatch();
  render();
})();

"use strict";
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = { config: null, data: null, certs: [], accessLists: [], filter: "all", search: "", editing: null };

// ------------------------------------------------------------------ api
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  if (res.status === 401 && path !== "/api/login") { showLogin(); throw new Error("Not authenticated"); }
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    let msg = data?.detail ?? res.statusText;
    if (Array.isArray(msg)) msg = msg.map((e) => e.msg.replace(/^Value error, /, "")).join("; ");
    throw new Error(msg);
  }
  return data;
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), err ? 6000 : 2500);
}

// ------------------------------------------------------------------ auth
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); $("#login-password").focus(); }

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("POST", "/api/login", { password: $("#login-password").value });
    $("#login-password").value = "";
    start();
  } catch (err) { $("#login-error").textContent = err.message; }
});

$("#btn-logout").addEventListener("click", async () => { await api("POST", "/api/logout"); showLogin(); });

// ------------------------------------------------------------------ data
async function start() {
  const s = await api("GET", "/api/session");
  if (s.auth_required && !s.authenticated) return showLogin();
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#btn-logout").classList.toggle("hidden", !s.auth_required);
  state.config = await api("GET", "/api/config");
  refresh();
  loadStatus();
}

async function loadStatus() {
  try {
    const s = await api("GET", "/api/status");
    const pill = (name, ok, err) => `<span class="pill ${ok ? "ok" : "bad"}" title="${esc(err || "Connected")}">${esc(name)}</span>`;
    $("#status-pills").innerHTML = pill("Nginx Proxy Manager", s.npm.ok, s.npm.error) + s.adguard.map((a) => pill(`AdGuard · ${a.name}`, a.ok, a.error)).join("");
  } catch { /* ignore */ }
}

async function refresh() {
  const btn = $("#btn-refresh");
  btn.disabled = true;
  try {
    state.data = await api("GET", "/api/hosts");
    $("#banner").classList.add("hidden");
    const bad = state.data.instances.filter((i) => !i.ok);
    if (bad.length) showBanner(bad.map((i) => i.error).join(" · "));
    render();
  } catch (err) {
    showBanner(err.message);
    $("#rows").innerHTML = `<tr><td colspan="6" class="empty">Could not load hosts.</td></tr>`;
  } finally { btn.disabled = false; }
}

function showBanner(msg) { const b = $("#banner"); b.textContent = msg; b.classList.remove("hidden"); }

async function loadLookups() {
  const [certs, acl] = await Promise.all([api("GET", "/api/certificates"), api("GET", "/api/access-lists")]);
  state.certs = certs; state.accessLists = acl;
}

// ------------------------------------------------------------------ rendering
function dnsCell(dns) {
  // dns: [{instance, ok, answers, wildcard}]
  return dns.map((d) => {
    let badge;
    if (!d.ok) badge = `<span class="badge neutral">unknown</span>`;
    else if (d.answers.length) badge = d.answers.map((a) => `<span class="badge ok">${esc(a)}</span>`).join("");
    else if (d.wildcard) badge = `<span class="badge info" title="Covered by wildcard ${esc(d.wildcard.domain)}">${esc(d.wildcard.answer)} (${esc(d.wildcard.domain)})</span>`;
    else badge = `<span class="badge warn">missing</span>`;
    return dns.length > 1 ? `<span class="sub">${esc(d.instance)}</span> ${badge}` : badge;
  }).join(" ");
}

const domainMissingDns = (d) => d.dns.some((x) => x.ok && !x.answers.length && !x.wildcard);
const hostHasIssue = (h) => !h.enabled || h.online === false || h.domains.some(domainMissingDns);

function matches(text) { return !state.search || text.toLowerCase().includes(state.search); }

function render() {
  const { hosts, dns_only } = state.data;
  const rows = [];
  if (state.filter !== "dns") {
    for (const h of hosts) {
      const hay = h.domains.map((d) => d.name).join(" ") + ` ${h.forward_host}:${h.forward_port}`;
      if (!matches(hay)) continue;
      if (state.filter === "issues" && !hostHasIssue(h)) continue;
      rows.push(hostRow(h));
    }
  }
  // "issues" only lists rewrites that are missing on some AdGuard instance
  const orphans = dns_only.filter((o) => matches(o.domain) && (state.filter !== "issues" || o.dns.some((d) => d.ok && !d.answers.length)));
  if (orphans.length) {
    rows.push(`<tr class="section-row"><td colspan="6">DNS rewrites without a proxy host (${orphans.length})</td></tr>`);
    rows.push(...orphans.map(orphanRow));
  }
  $("#rows").innerHTML = rows.join("") || `<tr><td colspan="6" class="empty">${hosts.length || dns_only.length ? "Nothing matches." : "No hosts yet — click “Add host”."}</td></tr>`;
}

function hostRow(h) {
  const https = h.certificate_id ? "https" : "http";
  const domains = h.domains.map((d) => `<span class="domain"><a href="${https}://${esc(d.name)}" target="_blank" rel="noopener">${esc(d.name)}</a></span>`).join("");
  const dns = h.domains.map((d) => `<div class="dnsline">${h.domains.length > 1 ? `<span class="sub">${esc(d.name)}:</span>` : ""}${dnsCell(d.dns)}</div>`).join("");
  const ssl = h.certificate_id
    ? `<span class="badge ok">${esc(h.certificate_name || "Certificate #" + h.certificate_id)}</span>${h.ssl_forced ? `<div class="sub">Forced</div>` : ""}`
    : `<span class="badge neutral">HTTP only</span>`;
  let status = h.enabled ? `<span class="badge ok">Enabled</span>` : `<span class="badge neutral">Disabled</span>`;
  if (h.online === false) status += `<span class="badge bad" title="${esc(h.error || "")}">Nginx error</span>`;
  const missing = h.domains.some(domainMissingDns);
  return `<tr class="${h.enabled ? "" : "disabled"}">
    <td>${domains}</td>
    <td><span class="mono">${esc(h.forward_scheme)}://${esc(h.forward_host)}:${esc(h.forward_port)}</span>
      ${h.allow_websocket_upgrade ? `<div class="sub">websockets</div>` : ""}</td>
    <td>${ssl}</td>
    <td>${dns}</td>
    <td>${status}</td>
    <td><div class="actions">
      ${missing ? `<button class="btn sm primary" data-act="fixdns" data-id="${h.id}">Fix DNS</button>` : ""}
      <button class="btn sm" data-act="edit" data-id="${h.id}">Edit</button>
      <button class="btn sm" data-act="toggle" data-id="${h.id}">${h.enabled ? "Disable" : "Enable"}</button>
      <button class="btn sm" data-act="delete" data-id="${h.id}">Delete</button>
    </div></td></tr>`;
}

function orphanRow(o) {
  const answers = [...new Set(o.dns.flatMap((d) => d.answers))];
  return `<tr>
    <td><span class="domain">${esc(o.domain)}</span>${o.wildcard ? `<span class="sub">wildcard rewrite</span>` : ""}</td>
    <td><span class="muted">—</span></td>
    <td><span class="muted">—</span></td>
    <td><div class="dnsline">${dnsCell(o.dns)}</div></td>
    <td><span class="badge warn">No proxy host</span></td>
    <td><div class="actions">
      ${o.wildcard ? "" : `<button class="btn sm primary" data-act="adopt" data-domain="${esc(o.domain)}" data-answer="${esc(answers[0] || "")}">Create proxy</button>`}
      ${o.dns.some((d) => d.ok && !d.answers.length) ? `<button class="btn sm" data-act="syncdns" data-domain="${esc(o.domain)}" data-answer="${esc(answers[0] || "")}">Sync</button>` : ""}
      <button class="btn sm" data-act="deldns" data-domain="${esc(o.domain)}">Delete</button>
    </div></td></tr>`;
}

// ------------------------------------------------------------------ toolbar
$("#search").addEventListener("input", (e) => { state.search = e.target.value.trim().toLowerCase(); render(); });
$("#filter").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  state.filter = b.dataset.f;
  $("#filter").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
  render();
});
$("#btn-refresh").addEventListener("click", () => { refresh(); loadStatus(); });
$("#btn-add").addEventListener("click", () => openEditor(null));

// ------------------------------------------------------------------ row actions
$("#rows").addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-act]"); if (!b) return;
  const host = state.data.hosts.find((h) => h.id === Number(b.dataset.id));
  const act = b.dataset.act;
  try {
    if (act === "edit") return openEditor(host);
    if (act === "adopt") return openEditor(null, { domains: [b.dataset.domain], dns_answer: b.dataset.answer });
    if (act === "delete") return confirmDelete(host);
    b.disabled = true;
    if (act === "toggle") {
      await api("POST", `/api/hosts/${host.id}/enabled?enabled=${!host.enabled}`);
      toast(host.enabled ? "Host disabled" : "Host enabled");
    } else if (act === "fixdns") {
      const answer = await askAnswer();
      if (answer === null) return;
      for (const d of host.domains.filter(domainMissingDns)) await api("POST", "/api/dns", { domain: d.name, answer });
      toast("DNS rewrites created");
    } else if (act === "syncdns") {
      await api("POST", "/api/dns", { domain: b.dataset.domain, answer: b.dataset.answer || null });
      toast("DNS synced across instances");
    } else if (act === "deldns") {
      if (!confirm(`Delete DNS rewrite(s) for ${b.dataset.domain} on all AdGuard instances?`)) return;
      await api("POST", "/api/dns/delete", { domain: b.dataset.domain });
      toast("DNS rewrite deleted");
    }
    await refresh();
  } catch (err) { toast(err.message, true); }
  finally { b.disabled = false; }
});

async function askAnswer() {
  if (state.config.default_dns_answer) return state.config.default_dns_answer;
  const v = prompt("IP address the rewrite should point to (your Nginx Proxy Manager):");
  return v && v.trim() ? v.trim() : null;
}

function confirmDelete(host) {
  const dlg = $("#confirm-dialog");
  $("#confirm-title").textContent = "Delete proxy host?";
  $("#confirm-text").innerHTML = `This removes <strong>${esc(host.domains.map((d) => d.name).join(", "))}</strong> from Nginx Proxy Manager.`;
  $("#confirm-dns").checked = true;
  dlg.returnValue = "";
  dlg.showModal();
  dlg.addEventListener("close", async () => {
    if (dlg.returnValue !== "ok") return;
    try {
      await api("DELETE", `/api/hosts/${host.id}?dns=${$("#confirm-dns").checked}`);
      toast("Host deleted");
      refresh();
    } catch (err) { toast(err.message, true); }
  }, { once: true });
}

// ------------------------------------------------------------------ editor
const form = $("#host-form");
const dialog = $("#host-dialog");
const CHECKS = ["ssl_forced", "http2_support", "hsts_enabled", "hsts_subdomains", "allow_websocket_upgrade", "block_exploits", "caching_enabled", "manage_dns"];

async function openEditor(host, prefill = {}) {
  try { await loadLookups(); } catch (err) { return toast(err.message, true); }
  state.editing = host;
  $("#host-title").textContent = host ? "Edit host" : "Add host";
  $("#form-error").textContent = "";
  $("#suffix-hint").textContent = state.config.default_domain_suffix ? ` · bare names get “.${state.config.default_domain_suffix}”` : "";

  form.certificate_id.innerHTML = `<option value="0">None (HTTP only)</option><option value="new">Request new Let's Encrypt certificate</option>` +
    state.certs.map((c) => `<option value="${c.id}">${esc(c.name)}${c.provider ? ` (${esc(c.provider)})` : ""}</option>`).join("");
  form.access_list_id.innerHTML = `<option value="0">Publicly accessible</option>` + state.accessLists.map((a) => `<option value="${a.id}">${esc(a.name)}</option>`).join("");

  const v = host || {
    domains: (prefill.domains || []).map((name) => ({ name })),
    forward_scheme: "http", forward_host: "", forward_port: "",
    certificate_id: 0, allow_websocket_upgrade: true, block_exploits: true, access_list_id: 0, advanced_config: "",
  };
  form.domains.value = v.domains.map((d) => d.name).join("\n");
  form.forward_scheme.value = v.forward_scheme;
  form.forward_host.value = v.forward_host;
  form.forward_port.value = v.forward_port;
  form.certificate_id.value = String(v.certificate_id || 0);
  if (!form.certificate_id.value) form.certificate_id.value = "0";
  form.access_list_id.value = String(v.access_list_id || 0);
  form.advanced_config.value = v.advanced_config || "";
  for (const k of CHECKS) form[k].checked = k === "manage_dns" ? true : !!v[k];

  // DNS answer: current rewrite of the first domain, else prefill, else default
  const current = host?.domains.flatMap((d) => d.dns.flatMap((x) => x.answers))[0];
  form.dns_answer.value = current || prefill.dns_answer || "";
  form.dns_answer.placeholder = state.config.default_dns_answer || "192.168.1.10";
  form.letsencrypt_email.value = state.config.letsencrypt_email || "";
  syncCertUi();
  dialog.showModal();
  (host ? form.forward_host : form.domains).focus();
}

function syncCertUi() {
  $("#le-email-wrap").classList.toggle("hidden", form.certificate_id.value !== "new");
  form.dns_answer.disabled = !form.manage_dns.checked;
}
form.certificate_id.addEventListener("change", () => {
  if (form.certificate_id.value !== "0") { form.ssl_forced.checked = true; form.http2_support.checked = true; }
  syncCertUi();
});
form.manage_dns.addEventListener("change", syncCertUi);
$("#host-cancel").addEventListener("click", () => dialog.close());

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const cert = form.certificate_id.value;
  const body = {
    domains: form.domains.value.split(/[\s,]+/).filter(Boolean),
    forward_scheme: form.forward_scheme.value,
    forward_host: form.forward_host.value,
    forward_port: Number(form.forward_port.value),
    certificate_id: cert === "new" ? "new" : Number(cert),
    access_list_id: Number(form.access_list_id.value),
    advanced_config: form.advanced_config.value,
    dns_answer: form.dns_answer.value.trim() || null,
    letsencrypt_email: form.letsencrypt_email.value.trim() || null,
  };
  for (const k of CHECKS) body[k] = form[k].checked;
  const btn = $("#host-save");
  btn.disabled = true; btn.textContent = cert === "new" ? "Requesting certificate…" : "Saving…";
  $("#form-error").textContent = "";
  try {
    if (state.editing) await api("PUT", `/api/hosts/${state.editing.id}`, body);
    else await api("POST", "/api/hosts", body);
    dialog.close();
    toast(state.editing ? "Host updated" : "Host created");
    refresh();
  } catch (err) {
    $("#form-error").textContent = err.message;
  } finally { btn.disabled = false; btn.textContent = "Save"; }
});

start().catch((err) => showBanner(err.message));

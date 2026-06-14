/* ============================================================
   GraphRaider — frontend controller
   ============================================================ */
const BACKEND_HTTP = "http://localhost:8000";
const BACKEND_WS   = "ws://localhost:8000/ws";

/* ── State ──────────────────────────────────────────────── */
let ws = null, tests = [], selectedId = null, currentRunId = null, running = false, runQueue = [];
let results = {}, testLogs = {};
let history = [], histSelected = null;
let repeater = [], repActive = null;
let repShowHeaders = true;      // true = Burp-style (headers + body); false = body only
let repHeadersObj = {};         // current request headers
let repBodyStr = "";            // current request body
let lastRepResp = null;         // last response, kept so the toggle can re-render it
let checklistState = {};
let pendingReq = null;          // last "request" msg awaiting its response (for history capture)
let runRequests = {};           // test_id -> [request msgs sent during the run]

const cfg = {
  endpoint: "", agent_mode: "rule_based", api_key: "",
  proxy_enabled: false, proxy: "http://127.0.0.1:8080",
  primary:   blankSession("Session A"),
  secondary: blankSession("Session B"),
};
function blankSession(label) {
  return { label, auth_type: "bearer", bearer_token: "", cookie_name: "session",
           cookie_value: "", header_name: "X-API-Key", header_value: "" };
}

const $  = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

/* ── View / nav switching ───────────────────────────────── */
document.querySelectorAll(".rail-btn").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".rail-btn").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  b.classList.add("active");
  $("view-" + b.dataset.view).classList.add("active");
}));
document.querySelectorAll(".subtab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".subtab").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".subview").forEach(v => v.classList.remove("active"));
  t.classList.add("active");
  $("sub-" + t.dataset.sub).classList.add("active");
}));

/* ── Auth type segmented control ────────────────────────── */
document.querySelectorAll(".seg-btn").forEach(btn => btn.addEventListener("click", () => {
  const seg = btn.closest(".seg"), session = seg.dataset.session, type = btn.dataset.type;
  seg.querySelectorAll(".seg-btn").forEach(x => x.classList.toggle("active", x === btn));
  document.querySelectorAll(`.auth-fields[data-session="${session}"]`)
    .forEach(f => f.classList.toggle("active", f.dataset.type === type));
  cfg[session].auth_type = type;
}));

/* ── Config form <-> object ─────────────────────────────── */
const MODE_DESC = {
  rule_based:  "Deterministic checks only — HTTP status, regex, and response timing. Fully offline, no API key required. Fastest and completely reproducible.",
  hybrid:      "Rule-based agents send the requests; Claude writes the final PASS/FAIL verdict for nuanced reasoning. Requires an Anthropic API key.",
  full_claude: "Claude assists transport-error diagnosis and writes the verdict — maximum LLM assistance. Requires an Anthropic API key; falls back to rules if a call fails.",
};
function getMode() { const el = document.querySelector('input[name="cfgMode"]:checked'); return el ? el.value : "rule_based"; }
function setMode(v) { const el = document.querySelector(`input[name="cfgMode"][value="${v}"]`); if (el) el.checked = true; }
function onModeChange() {
  const m = getMode();
  $("apiKeyField").style.display = m !== "rule_based" ? "block" : "none";
  const d = $("modeDesc"); if (d) d.textContent = MODE_DESC[m] || "";
  document.querySelectorAll(".radio-card").forEach(c => c.classList.toggle("selected", c.dataset.mode === m));
}

function readForm() {
  cfg.endpoint     = $("cfgEndpoint").value.trim();
  cfg.agent_mode   = getMode();
  cfg.api_key      = $("cfgApiKey").value.trim();
  cfg.proxy_enabled = $("proxyEnabled").checked;
  cfg.proxy        = $("proxyUrl").value.trim();
  for (const [s, p] of [["primary", "pri"], ["secondary", "sec"]]) {
    cfg[s].bearer_token = $(p + "-bearer").value.trim();
    cfg[s].cookie_name  = $(p + "-cookie-name").value.trim();
    cfg[s].cookie_value = $(p + "-cookie-value").value.trim();
    cfg[s].header_name  = $(p + "-header-name").value.trim();
    cfg[s].header_value = $(p + "-header-value").value.trim();
  }
}
function writeForm() {
  $("cfgEndpoint").value = cfg.endpoint || "";
  setMode(cfg.agent_mode || "rule_based");
  $("cfgApiKey").value   = cfg.api_key || "";
  $("proxyEnabled").checked = !!cfg.proxy_enabled;
  $("proxyUrl").value    = cfg.proxy || "http://127.0.0.1:8080";
  for (const [s, p] of [["primary", "pri"], ["secondary", "sec"]]) {
    const o = cfg[s];
    $(p + "-bearer").value       = o.bearer_token || "";
    $(p + "-cookie-name").value  = o.cookie_name || "";
    $(p + "-cookie-value").value = o.cookie_value || "";
    $(p + "-header-name").value  = o.header_name || "";
    $(p + "-header-value").value = o.header_value || "";
    // restore segmented control
    const seg = document.querySelector(`.seg[data-session="${s}"]`);
    seg.querySelectorAll(".seg-btn").forEach(b => b.classList.toggle("active", b.dataset.type === (o.auth_type || "bearer")));
    document.querySelectorAll(`.auth-fields[data-session="${s}"]`)
      .forEach(f => f.classList.toggle("active", f.dataset.type === (o.auth_type || "bearer")));
  }
  onModeChange();
  previewToken("primary"); previewToken("secondary");
}

function saveConfig(flash) {
  readForm();
  persist();
  if (flash) { ["cfgSaved", "evalSaved", "proxySaved"].forEach(id => { const e = $(id); if (!e) return; e.classList.add("show"); setTimeout(() => e.classList.remove("show"), 1600); }); }
  connectWS();
}

/* ── Token preview (client-side JWT decode) ─────────────── */
function previewToken(which) {
  const el = $(which === "primary" ? "pri-bearer" : "sec-bearer");
  const meta = $(which === "primary" ? "pri-meta" : "sec-meta");
  const tok = el.value.trim();
  if (!tok) { meta.classList.remove("show"); return; }
  const parts = tok.split(".");
  if (parts.length !== 3) { meta.innerHTML = `<span class="badge-bad">Opaque token (not a JWT) — sent verbatim.</span>`; meta.classList.add("show"); return; }
  try {
    const pad = s => s + "=".repeat((4 - s.length % 4) % 4);
    const dec = s => JSON.parse(atob(pad(s).replace(/-/g,"+").replace(/_/g,"/")));
    const hdr = dec(parts[0]), pl = dec(parts[1]);
    const exp = pl.exp ? new Date(pl.exp * 1000) : null;
    const expired = exp && exp < new Date();
    meta.innerHTML =
      `alg <b>${hdr.alg || "?"}</b> &nbsp;·&nbsp; sub <b>${pl.sub || "—"}</b><br>` +
      `scope <b>${pl.scope || pl.scp || "—"}</b><br>` +
      `exp <b class="${expired ? "badge-bad" : "badge-ok"}">${exp ? exp.toLocaleString() + (expired ? " (EXPIRED)" : "") : "—"}</b>`;
    meta.classList.add("show");
  } catch { meta.innerHTML = `<span class="badge-bad">Could not decode token.</span>`; meta.classList.add("show"); }
}

/* ── Persistence (memory) ───────────────────────────────── */
async function persist() {
  const body = { ...cfg, results, testLogs, history, repeater, checklist: checklistState };
  try { await fetch(`${BACKEND_HTTP}/config`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch (e) { console.warn("persist failed", e); }
}
async function loadPersisted() {
  try {
    const r = await fetch(`${BACKEND_HTTP}/config`);
    const d = await r.json();
    if (!d || typeof d !== "object") return;
    cfg.endpoint = d.endpoint || ""; cfg.agent_mode = d.agent_mode || "rule_based";
    cfg.api_key = d.api_key || ""; cfg.proxy_enabled = !!d.proxy_enabled; cfg.proxy = d.proxy || "http://127.0.0.1:8080";
    if (d.primary)   Object.assign(cfg.primary, d.primary);
    if (d.secondary) Object.assign(cfg.secondary, d.secondary);
    results = d.results || {}; testLogs = d.testLogs || {};
    history = d.history || []; repeater = d.repeater || []; checklistState = d.checklist || {};
  } catch (e) { console.log("no persisted config", e.message); }
}

/* ============================================================
   WebSocket / Runner
   ============================================================ */
function connectWS() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "list_tests" }));
    return;
  }
  ws = new WebSocket(BACKEND_WS);
  ws.onopen = () => { setWs(true); ws.send(JSON.stringify({ type: "list_tests" })); };
  ws.onclose = () => { setWs(false); setTimeout(connectWS, 3000); };
  ws.onerror = () => setWs(false);
  ws.onmessage = e => { try { handleMsg(JSON.parse(e.data)); } catch (err) { console.error(err); } };
}
function setWs(ok) { $("wsDot").className = "ws-dot" + (ok ? " connected" : ""); $("wsLabel").textContent = ok ? "Connected" : "Reconnecting…"; }

function handleMsg(m) {
  switch (m.type) {
    case "test_list": tests = m.tests; renderTests(); break;
    case "test_start":
      currentRunId = m.test_id; testLogs[m.test_id] = []; runRequests[m.test_id] = []; setRunning(true); markRunning(m.test_id);
      $("logTag").textContent = `${m.test_id} — ${m.name}`; hideVerdict();
      if (selectedId === m.test_id) $("logOut").innerHTML = "";
      logLine("info", `━━ ${m.test_id}: ${m.name}`, m.timestamp);
      logLine("info", `Category: ${m.category}  ·  Refs: ${m.refs}  ·  Mode: ${m.mode}`, m.timestamp);
      if (m.description) logLine("info", `Why: ${m.description}`, m.timestamp);
      if (m.expected_pass) logLine("success", `PASS if: ${m.expected_pass}`, m.timestamp);
      if (m.expected_fail) logLine("warn", `FAIL if: ${m.expected_fail}`, m.timestamp);
      break;
    case "log":   logLine(m.level || "info", m.message, m.timestamp); break;
    case "error": logLine("error", m.message, m.timestamp); break;
    case "agent": {
      const map = { "Agent 1": "agent1", "Agent 2": "agent2", "Agent 3 (Critic)": "agent3" };
      logLine(map[m.agent] || "info", `[${m.agent}] ${m.message}`, m.timestamp); break;
    }
    case "baseline": {
      const ok = m.status === 200;
      logCollapse("base", `BASELINE  ${ok ? "🟢" : "🟡"} HTTP ${m.status} (${m.latency_ms} ms)`,
        m.error ? `ERROR: ${m.error}` : (m.body_preview || "(empty)"), m.timestamp);
      break;
    }
    case "request": {
      pendingReq = m;
      if (currentRunId) (runRequests[currentRunId] = runRequests[currentRunId] || []).push(m);
      const body = [`${m.method}  ${m.url}`, Object.entries(m.headers || {}).map(([k, v]) => `  ${k}: ${v}`).join("\n"),
        m.body ? `\n  ${m.body.slice(0, 900)}` : ""].join("\n");
      logCollapse("req", `REQUEST  [${m.label}]`, body, m.timestamp);
      break;
    }
    case "response": {
      const dot = m.status >= 400 ? "🔴" : "🟢";
      const hdrs = Object.entries(m.headers || {}).map(([k, v]) => `  ${k}: ${v}`).join("\n");
      logCollapse("resp", `RESPONSE  ${dot} HTTP ${m.status} (${m.latency_ms} ms)  [${m.label}]`,
        m.error ? `  ERROR: ${m.error}` : `${hdrs}\n\n  ${(m.body || "").slice(0, 1500)}`, m.timestamp);
      // capture into history
      if (pendingReq) {
        addHistory({ method: pendingReq.method, url: pendingReq.url, status: m.status, latency: m.latency_ms,
          source: currentRunId || "runner", reqHeaders: pendingReq.headers, reqBody: pendingReq.body,
          respHeaders: m.headers, respBody: m.body, error: m.error });
        pendingReq = null;
      }
      break;
    }
    case "test_complete": {
      results[m.test_id] = { status: m.status, confidence: m.confidence, reason: m.reason, findings: m.findings || [] };
      setStatus(m.test_id, m.status); showVerdict(m.status, m.confidence, m.reason, m.findings || []);
      logLine(m.status === "pass" ? "success" : m.status === "fail" ? "error" : "warn",
        `[Verdict] ${m.status.toUpperCase()} — ${m.reason}`, m.timestamp);
      (m.findings || []).forEach(f => logLine("warn", `  ↳ ${f}`, m.timestamp));
      currentRunId = null; setRunning(false); updateProgress(); persist();
      if (runQueue.length) { const n = runQueue.shift(); setTimeout(() => runTest(n), 350); }
      break;
    }
  }
}

/* ── Test list ──────────────────────────────────────────── */
const CAT_ICON = { "Discovery": "🔍", "Denial of Service": "💥", "Injection": "💉",
  "Information Disclosure": "📄", "CSRF": "🎭", "Transport": "🔒", "Authentication": "🔑", "Authorization": "🛡️" };
const CAT_ORDER = ["Discovery", "Denial of Service", "Injection", "Information Disclosure", "CSRF", "Transport", "Authentication", "Authorization"];

function renderTests() {
  const list = $("tcList"); list.innerHTML = "";
  $("tcCount").textContent = `(${tests.length})`;
  $("btnRun").disabled = false; $("btnRunAll").disabled = false;
  const groups = {}; tests.forEach(t => (groups[t.category] = groups[t.category] || []).push(t));
  CAT_ORDER.filter(c => groups[c]).forEach(cat => {
    const g = document.createElement("div"); g.className = "tc-group"; g.textContent = `${CAT_ICON[cat] || ""} ${cat}`; list.appendChild(g);
    groups[cat].forEach(t => {
      const el = document.createElement("div"); el.className = "tc-item"; el.dataset.id = t.id;
      el.innerHTML = `<div class="tc-ico" id="ico-${t.id}">○</div>
        <div class="tc-meta"><div class="tc-id">${t.id}</div><div class="tc-name">${esc(t.name)}</div><div class="tc-refs">${esc(t.refs || "")}</div></div>
        ${t.requires_secondary ? '<div class="badge-2nd">B</div>' : ""}`;
      el.onclick = () => selectTc(t.id); list.appendChild(el);
    });
  });
  Object.entries(results).forEach(([id, r]) => setStatus(id, r.status));
  const sel = (selectedId && tests.find(t => t.id === selectedId)) ? selectedId : (tests[0] && tests[0].id);
  if (sel) selectTc(sel);
  updateProgress();
}
function selectTc(id) {
  selectedId = id;
  document.querySelectorAll(".tc-item").forEach(el => el.classList.toggle("selected", el.dataset.id === id));
  const tc = tests.find(t => t.id === id);
  if (tc) $("logTag").textContent = `${id} — ${tc.name}`;
  if (id !== currentRunId) restoreLogs(id);
}
const ICONS = { pending: "○", running: "◌", pass: "✓", fail: "✗", skipped: "–", error: "!" };
function markRunning(id) {
  const el = $("ico-" + id); if (el) el.textContent = ICONS.running;
  document.querySelectorAll(".tc-item").forEach(el => { if (el.dataset.id === id) { el.classList.remove("pass","fail","skipped","error"); el.classList.add("running"); } });
}
function setStatus(id, st) {
  const el = $("ico-" + id); if (el) el.textContent = ICONS[st] || "?";
  document.querySelectorAll(".tc-item").forEach(el => { if (el.dataset.id === id) { el.classList.remove("running","pass","fail","skipped","error"); if (st && st !== "pending") el.classList.add(st); } });
}
function updateProgress() {
  const done = Object.values(results).filter(r => r.status !== "running").length, total = tests.length;
  $("progFill").style.width = (total ? done / total * 100 : 0) + "%";
  $("progTxt").textContent = `${done} / ${total} completed`;
}

/* ── Log rendering + persistence ────────────────────────── */
function logLine(level, msg, ts) {
  const out = $("logOut"); const e = out.querySelector(".empty"); if (e) e.remove();
  if (currentRunId && currentRunId !== selectedId) { store({ c: false, level, msg, ts }); return; }
  const bc = { info:"b-info",warn:"b-warn",error:"b-error",success:"b-success",agent1:"b-agent1",agent2:"b-agent2",agent3:"b-agent3" }[level] || "b-info";
  const lbl = { info:"INFO",warn:"WARN",error:"ERROR",success:"PASS",agent1:"AGENT 1",agent2:"AGENT 2",agent3:"CRITIC" }[level] || level.toUpperCase();
  const row = document.createElement("div"); row.className = "log-entry";
  row.innerHTML = `<span class="log-ts">${ts || ""}</span><span class="log-badge ${bc}">${lbl}</span><span class="log-msg">${esc(msg)}</span>`;
  out.appendChild(row); out.scrollTop = out.scrollHeight; store({ c: false, level, msg, ts });
}
function logCollapse(level, title, detail, ts) {
  const out = $("logOut"); const e = out.querySelector(".empty"); if (e) e.remove();
  if (currentRunId && currentRunId !== selectedId) { store({ c: true, level, title, detail, ts }); return; }
  const bc = { req:"b-req", base:"b-base", resp:"b-resp" }[level] || "b-resp";
  const lbl = { req:"REQUEST", base:"BASELINE", resp:"RESPONSE" }[level] || "RESP";
  const did = "d" + Math.random().toString(36).slice(2);
  const row = document.createElement("div"); row.className = "log-entry";
  row.innerHTML = `<span class="log-ts">${ts || ""}</span><span class="log-badge ${bc}">${lbl}</span><span class="log-msg collapse" onclick="toggleDetail('${did}',this)">${esc(title)}</span>`;
  const d = document.createElement("div"); d.className = "detail"; d.id = did; d.textContent = detail;
  out.appendChild(row); out.appendChild(d); out.scrollTop = out.scrollHeight; store({ c: true, level, title, detail, ts });
}
function store(e) { if (!currentRunId) return; const a = testLogs[currentRunId] = testLogs[currentRunId] || []; a.push(e); if (a.length > 400) a.splice(0, 60); }
function toggleDetail(id, btn) { $(id).classList.toggle("open"); btn.classList.toggle("open"); }
function restoreLogs(id) {
  const out = $("logOut"); out.innerHTML = ""; hideVerdict();
  const s = testLogs[id] || [];
  if (!s.length) { out.innerHTML = `<div class="empty"><div class="ico">📋</div><div>Select a test case and click <b>Run Selected</b></div></div>`;
    if (results[id]) showVerdict(results[id].status, results[id].confidence, results[id].reason, results[id].findings || []); return; }
  const prev = currentRunId; currentRunId = null;
  s.forEach(e => e.c ? logCollapse(e.level, e.title, e.detail, e.ts) : logLine(e.level, e.msg, e.ts));
  currentRunId = prev;
  if (results[id]) showVerdict(results[id].status, results[id].confidence, results[id].reason, results[id].findings || []);
}
function clearLogs() { $("logOut").innerHTML = `<div class="empty"><div class="ico">📋</div><div>Select a test case and click <b>Run Selected</b></div></div>`; hideVerdict(); }
function resetFinding() { if (!selectedId) return; delete results[selectedId]; delete testLogs[selectedId]; setStatus(selectedId, "pending"); clearLogs(); updateProgress(); persist(); }

function showVerdict(status, conf, reason, findings) {
  const b = $("verdict"); b.className = `verdict show ${status}`;
  const cc = { high:"conf-high", medium:"conf-medium", low:"conf-low" }[conf] || "conf-low";
  const icon = status === "pass" ? "✓ SECURE (PASS)" : status === "fail" ? "✗ VULNERABLE (FAIL)" : status === "skipped" ? "– SKIPPED" : "! ERROR";
  const fl = (findings && findings.length) ? `<div class="findings">↳ ${findings.map(esc).join(" · ")}</div>` : "";
  b.innerHTML = `<span>${icon}</span>${conf ? `<span class="conf ${cc}">${conf}</span>` : ""}<span style="flex:1">${esc(reason)}</span>${fl}`;
}
function hideVerdict() { const b = $("verdict"); b.className = "verdict"; b.innerHTML = ""; }

function setRunning(s) { running = s; $("btnRun").disabled = s; $("btnRunAll").disabled = s; }
function runSelected() { if (running) return; if (!preRunCheck()) return; if (selectedId) runTest(selectedId); }
function runAll() { if (running) return; if (!preRunCheck()) return; runQueue = tests.map(t => t.id); if (runQueue.length) runTest(runQueue.shift()); }

/* Block a run if the tool isn't configured, and say what's missing. */
function configIssues() {
  readForm();
  const issues = [];
  if (!cfg.endpoint) issues.push("GraphQL endpoint is not set — add it in Settings → Configuration.");
  if ((cfg.agent_mode === "hybrid" || cfg.agent_mode === "full_claude") && !cfg.api_key)
    issues.push(`Evaluation mode “${cfg.agent_mode === "hybrid" ? "Hybrid" : "Full Claude"}” needs an Anthropic API key — add one in Settings → Evaluation, or switch to Rule-Based.`);
  return issues;
}
function preRunCheck() {
  const issues = configIssues();
  if (!issues.length) return true;
  hideVerdict();
  const b = $("verdict"); b.className = "verdict show error";
  b.innerHTML = `<span>! NOT CONFIGURED</span><span style="flex:1">Fix the item(s) below in Settings, then run again.</span>
    <button class="btn btn-sm" onclick="document.querySelector('.rail-btn[data-view=&quot;settings&quot;]').click()">Open Settings</button>`;
  const out = $("logOut"); out.innerHTML = "";
  logLine("error", "Cannot run — GraphRaider is not configured:");
  issues.forEach(i => logLine("warn", `  ↳ ${i}`));
  return false;
}
function runTest(id) {
  if (!ws || ws.readyState !== WebSocket.OPEN) { logLine("error", "Not connected to backend — is start.ps1 / start.sh running?"); return; }
  readForm(); selectTc(id);
  ws.send(JSON.stringify({ type: "run_test", test_id: id, config: { ...cfg } }));
}

/* ============================================================
   History
   ============================================================ */
function addHistory(e) {
  e.id = "h" + Date.now() + Math.random().toString(36).slice(2, 6);
  e.ts = new Date().toLocaleTimeString();
  history.unshift(e); if (history.length > 500) history.pop();
  renderHistory(); persist();
}
function renderHistory() {
  const tb = $("histBody"), empty = $("histEmpty");
  $("histSub").textContent = `${history.length} request${history.length === 1 ? "" : "s"}`;
  const badge = $("histBadge");
  if (history.length) { badge.style.display = "grid"; badge.textContent = history.length > 99 ? "99+" : history.length; }
  else badge.style.display = "none";
  tb.innerHTML = ""; empty.style.display = history.length ? "none" : "flex";
  history.forEach(e => {
    const tr = document.createElement("tr"); tr.dataset.id = e.id; if (e.id === histSelected) tr.classList.add("active");
    const sc = e.error ? "ERR" : e.status; const scls = (e.status >= 400 || e.error) ? "status-bad" : "status-ok";
    tr.innerHTML = `<td style="color:var(--faint)">${e.ts}</td><td class="hist-m" style="color:var(--cyan)">${e.method}</td>
      <td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.url)}</td>
      <td class="${scls}" style="font-family:var(--mono)">${sc}</td><td style="font-family:var(--mono);color:var(--muted)">${e.latency ?? "—"}</td>
      <td class="hist-src">${esc(String(e.source || ""))}</td>`;
    tr.onclick = () => showHistDetail(e.id); tb.appendChild(tr);
  });
}
function showHistDetail(id) {
  histSelected = id; renderHistory();
  const e = history.find(x => x.id === id); if (!e) return;
  $("histDetail").style.display = "flex";
  const hd = (o) => Object.entries(o || {}).map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)";
  $("histDetailBody").innerHTML =
    `<div class="hd-section"><h4>${e.method} ${esc(e.url)}</h4></div>
     <div class="hd-section"><h4>Request headers</h4><div class="hd-pre">${esc(hd(e.reqHeaders))}</div></div>
     <div class="hd-section"><h4>Request body</h4><div class="hd-pre">${esc(e.reqBody || "(empty)")}</div></div>
     <div class="hd-section"><h4>Response — HTTP ${e.error ? "error" : e.status} · ${e.latency ?? "?"} ms</h4>
       <div class="hd-pre">${esc(e.error || hd(e.respHeaders))}</div></div>
     <div class="hd-section"><h4>Response body</h4><div class="hd-pre">${esc(e.respBody || "(empty)")}</div></div>`;
}
function clearHistory() { history = []; histSelected = null; $("histDetail").style.display = "none"; renderHistory(); persist(); }
/* Shared: load a request into the Repeater and switch to it.
   Strips redacted auth headers (logged requests hide them) and re-attaches
   Session A so the request is replayable with real credentials. */
function loadIntoRepeater(method, url, headers, body) {
  repNew();
  const clean = {}; let hadRedacted = false;
  for (const [k, v] of Object.entries(headers || {})) {
    if (String(v).includes("[redacted]")) { hadRedacted = true; continue; }   // logged auth is hidden
    clean[k] = v;
  }
  if (!Object.keys(clean).some(k => k.toLowerCase() === "content-type")) clean["Content-Type"] = "application/json";
  repHeadersObj = clean; repBodyStr = body || "";
  $("repMethod").value = method || "POST";
  $("repUrl").value = url || cfg.endpoint || "";
  // Runner requests redact auth → re-attach Session A so the header is visible (same as History).
  $("repSession").value = hadRedacted ? "primary" : "none";
  injectSessionAuth();
  renderRequestEditor();
  document.querySelector('.rail-btn[data-view="repeater"]').click();
}
function runnerToRepeater() {
  if (!selectedId) { logLine("warn", "Select a test case first."); return; }
  const reqs = runRequests[selectedId] || [];
  if (!reqs.length) { logLine("warn", "No request captured yet — run this test first, then send it to the Repeater."); return; }
  const r = reqs[reqs.length - 1];        // most representative attack request
  loadIntoRepeater(r.method, r.url, r.headers, r.body);
}
function histToRepeater() {
  const e = history.find(x => x.id === histSelected); if (!e) return;
  loadIntoRepeater(e.method, e.url, e.reqHeaders, e.reqBody);
}

/* ============================================================
   Repeater
   ============================================================ */
function authHeadersFor(which) {
  if (which === "none") return {};
  const s = cfg[which]; if (!s) return {};
  if (s.auth_type === "bearer" && s.bearer_token) return { Authorization: `Bearer ${s.bearer_token}` };
  if (s.auth_type === "cookie" && s.cookie_name && s.cookie_value) return { Cookie: `${s.cookie_name}=${s.cookie_value}` };
  if (s.auth_type === "header" && s.header_name && s.header_value) return { [s.header_name]: s.header_value };
  return {};
}

/* ── Combined-editor helpers (Burp-style raw view) ──────── */
function headersToText(o) { return Object.entries(o || {}).map(([k, v]) => `${k}: ${v}`).join("\n"); }
function textToHeaders(t) {
  const o = {};
  (t || "").split("\n").forEach(line => { const i = line.indexOf(":"); if (i > 0) { const k = line.slice(0, i).trim(); if (k) o[k] = line.slice(i + 1).trim(); } });
  return o;
}
function coerceHeaders(h) {                       // saved requests may hold an object or a string
  if (h && typeof h === "object") return { ...h };
  if (typeof h === "string") { try { return JSON.parse(h); } catch { return textToHeaders(h); } }
  return {};
}
function renderRequestEditor() {
  const h = headersToText(repHeadersObj);
  $("repRequest").value = repShowHeaders ? ((h ? h + "\n\n" : "") + (repBodyStr || "")) : (repBodyStr || "");
}
function syncFromEditor() {                       // pull edits back into repHeadersObj / repBodyStr
  const raw = $("repRequest").value;
  if (!repShowHeaders) { repBodyStr = raw; return; }
  const m = raw.match(/\n[ \t]*\n/);              // first blank line separates headers from body
  if (m) { repHeadersObj = textToHeaders(raw.slice(0, m.index)); repBodyStr = raw.slice(m.index + m[0].length); }
  else {
    const tr = raw.trim();
    if (tr.startsWith("{") || tr.startsWith("[")) { repBodyStr = raw; repHeadersObj = {}; }
    else { repHeadersObj = textToHeaders(raw); repBodyStr = ""; }
  }
}
function injectSessionAuth() {                    // make the chosen session's auth visible in the headers
  const which = $("repSession").value;
  if (which === "none") return;                   // keep whatever auth is already present (e.g. from History)
  for (const k of Object.keys(repHeadersObj)) if (["authorization", "cookie"].includes(k.toLowerCase())) delete repHeadersObj[k];
  [cfg.primary, cfg.secondary].forEach(s => { if (s.auth_type === "header" && s.header_name) delete repHeadersObj[s.header_name]; });
  Object.assign(repHeadersObj, authHeadersFor(which));
}
function toggleRepHeaders() {
  syncFromEditor();
  repShowHeaders = !repShowHeaders;
  $("repHdrToggle").textContent = repShowHeaders ? "Hide Headers" : "Show Headers";
  $("repReqHint").textContent = repShowHeaders ? "raw — header lines, blank line, then body" : "body only — headers hidden";
  renderRequestEditor(); renderResponse();
}
function onRepSessionChange() { readForm(); syncFromEditor(); injectSessionAuth(); renderRequestEditor(); }

function renderRepList() {
  const l = $("repList"); l.innerHTML = "";
  repeater.forEach((r, i) => {
    const el = document.createElement("div"); el.className = "rep-saved-item" + (i === repActive ? " active" : "");
    el.innerHTML = `<span class="m">${r.method || "POST"}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.name || r.url || "request")}</span>`;
    el.onclick = () => repLoad(i); l.appendChild(el);
  });
}
function repNew() {
  readForm();
  repActive = null; renderRepList();
  $("repMethod").value = "POST"; $("repUrl").value = cfg.endpoint || "";
  repHeadersObj = { "Content-Type": "application/json" };
  repBodyStr = `{ "query": "{ __typename }" }`;
  $("repSession").value = "primary"; injectSessionAuth(); renderRequestEditor();
  lastRepResp = null; renderResponse();
}
function repLoad(i) {
  repActive = i; renderRepList(); const r = repeater[i];
  $("repMethod").value = r.method || "POST"; $("repUrl").value = r.url || "";
  repHeadersObj = coerceHeaders(r.headers); repBodyStr = r.body || "";
  $("repSession").value = r.session || "primary";
  renderRequestEditor();
}
function repSave() {
  syncFromEditor();
  const r = { name: (repBodyStr.match(/(query|mutation)\s+(\w+)/) || [])[2] || $("repUrl").value,
    method: $("repMethod").value, url: $("repUrl").value, headers: repHeadersObj, body: repBodyStr, session: $("repSession").value };
  if (repActive != null && repeater[repActive]) repeater[repActive] = r; else { repeater.unshift(r); repActive = 0; }
  renderRepList(); persist();
}
let lastRepResult = null;
async function repSend() {
  readForm(); syncFromEditor();
  const method = $("repMethod").value;
  const headers = { ...repHeadersObj };           // headers are the single source of truth (auth already injected)
  const payload = { method, url: $("repUrl").value, headers,
    body: method === "GET" ? null : repBodyStr,
    params: method === "GET" && repBodyStr ? safeParams(repBodyStr) : null,
    proxy_enabled: cfg.proxy_enabled, proxy: cfg.proxy };
  $("repMeta").innerHTML = `<span style="color:var(--muted)">Sending…</span>`; $("repResp").textContent = "";
  try {
    const r = await fetch(`${BACKEND_HTTP}/repeater/send`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const d = await r.json();
    lastRepResult = { payload, d };
    lastRepResp = { status_code: d.status_code, headers: d.headers, body: d.body, latency_ms: d.latency_ms, error: d.error };
    renderResponse();
  } catch (e) { lastRepResp = null; $("repMeta").innerHTML = `<span class="status-bad">Backend error</span>`; $("repResp").textContent = e.message; }
}
function renderResponse() {                        // honours the Show/Hide Headers toggle
  const r = lastRepResp;
  if (!r) { $("repMeta").innerHTML = `<span style="color:var(--faint)">No response yet</span>`; $("repResp").textContent = ""; return; }
  if (r.error) { $("repMeta").innerHTML = `<span class="status-bad">ERROR</span>`; $("repResp").textContent = r.error; return; }
  const scls = r.status_code >= 400 ? "status-bad" : "status-ok";
  $("repMeta").innerHTML = `<span class="${scls}">HTTP ${r.status_code}</span><span style="color:var(--muted)">${r.latency_ms} ms</span><span style="color:var(--faint)">${(r.body || "").length} bytes</span>`;
  const body = prettyMaybe(r.body || "");
  $("repResp").textContent = repShowHeaders ? (`HTTP ${r.status_code}\n${headersToText(r.headers)}\n\n${body}`) : body;
}
function safeParams(b) { try { return JSON.parse(b); } catch { return { query: b }; } }
function prettyMaybe(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } }
function repToHistory() {
  if (!lastRepResult) return; const { payload, d } = lastRepResult;
  addHistory({ method: payload.method, url: payload.url, status: d.status_code, latency: d.latency_ms,
    source: "repeater", reqHeaders: payload.headers, reqBody: payload.body || JSON.stringify(payload.params || {}),
    respHeaders: d.headers, respBody: d.body, error: d.error });
}

/* ============================================================
   Checklist  (generic GraphQL methodology)
   ============================================================ */
const CHECKLIST = [
  { group: "🔍 Reconnaissance", items: [
    ["recon-detect", "Fingerprint the GraphQL engine", "Identify Apollo / Hasura / graphql-php / etc. from error formats, headers, and field-suggestion behaviour.", "OWASP GraphQL CS"],
    ["recon-endpoints", "Discover alternate endpoints", "Probe /graphql, /api, /graphiql, /v1/graphql, /query, /console; check GET vs POST handling.", "WSTG-CONF-05"],
    ["recon-introspect", "Attempt full introspection", "Pull the schema via __schema; if blocked, try field-stuffing and suggestion-based inference.", "WSTG-APIT-01"],
    ["recon-playground", "Look for exposed IDE / playground", "GraphiQL, Apollo Sandbox, Playground left enabled in production.", "WSTG-CONF-05"],
  ]},
  { group: "🔑 Authentication & Session", items: [
    ["auth-unauth", "Test unauthenticated access", "Send queries with no token / cookie — sensitive resolvers should reject.", "API2:2023"],
    ["auth-jwt", "Attack the JWT", "alg=none, signature strip, weak secret brute-force, kid path traversal, expired/forged claims.", "JWT best practices"],
    ["auth-token-loc", "Check token placement handling", "Does the server accept the token from query string, body, or alternate headers (loggable / cacheable)?", "API2:2023"],
    ["auth-logout", "Verify session invalidation", "Revoked / logged-out tokens must stop working immediately.", "WSTG-SESS-06"],
  ]},
  { group: "🛡️ Authorization (BOLA / BFLA)", items: [
    ["authz-bola", "Object-level authorization (BOLA)", "Request another tenant's object by ID under your own session; compare with a second account.", "API1:2023"],
    ["authz-bfla", "Function-level authorization (BFLA)", "Call admin-only mutations/queries with a low-priv token.", "API5:2023"],
    ["authz-nested", "Nested-resolver authorization", "Auth enforced on root but not on nested fields — traverse to reach protected data.", "OWASP GraphQL CS"],
    ["authz-aggregate", "Aggregation / count oracles", "Counts/aggregates leaking the existence or size of other tenants' data.", "API1:2023"],
  ]},
  { group: "💥 Denial of Service", items: [
    ["dos-depth", "Unbounded query depth", "Deeply nested / circular queries with no depth limit.", "API4:2023"],
    ["dos-alias", "Alias & field duplication", "Hundreds of aliases multiplying resolver work.", "OWASP GraphQL CS"],
    ["dos-batch", "Query batching abuse", "Array batching to bypass rate limits or amplify load.", "OWASP GraphQL CS"],
    ["dos-directive", "Directive overloading", "Repeated @skip/@include or custom directives inflating parse cost.", "OWASP GraphQL CS"],
    ["dos-cost", "Cost / complexity limits", "Confirm a query-cost analysis or complexity budget is enforced.", "API4:2023"],
  ]},
  { group: "💉 Injection", items: [
    ["inj-sql", "SQL / NoSQL injection", "Inject through arguments reaching a datastore; watch for DB errors or timing.", "WSTG-INPV-05"],
    ["inj-os", "OS command / SSRF", "Arguments flowing into shell calls or server-side fetches.", "WSTG-INPV-12"],
    ["inj-csv", "Export / formula injection", "Payloads surviving into CSV/Excel exports.", "WSTG-CLNT"],
  ]},
  { group: "📄 Information Disclosure", items: [
    ["info-errors", "Verbose errors", "Stack traces, file paths, framework versions in error bodies.", "API8:2023"],
    ["info-debug", "Debug / tracing extensions", "Apollo tracing or extensions blocks leaking timings & internals.", "OWASP GraphQL CS"],
    ["info-pii", "Excessive data exposure", "Resolvers returning more fields than the client needs (PII, internal IDs).", "API3:2023"],
  ]},
  { group: "🎭 CSRF & Transport", items: [
    ["csrf-get", "GET-based mutations / queries", "State-changing operations reachable over GET = CSRF.", "WSTG-CSRF"],
    ["csrf-ct", "Content-type confusion", "Form / text content types accepted, bypassing JSON preflight.", "OWASP GraphQL CS"],
    ["tls-headers", "Security headers", "HSTS, X-Content-Type-Options; no leaked Server/X-Powered-By banners.", "WSTG-CONF-07"],
    ["tls-cors", "CORS policy", "No origin reflection; never wildcard + credentials.", "WSTG-CLNT-07"],
  ]},
  { group: "✏️ Mutations & Business Logic", items: [
    ["mut-mass", "Mass assignment", "Setting protected fields (role, tenantId, isAdmin) via mutation input.", "API6:2023"],
    ["mut-rate", "Rate limiting on sensitive mutations", "Login / OTP / password-reset mutations brute-forceable.", "API4:2023"],
    ["mut-idempotency", "Business-logic abuse", "Race conditions, negative quantities, replayed operations.", "API6:2023"],
  ]},
];
let clActiveGroup = 0;
function renderChecklist() {
  let total = 0, done = 0;
  const stats = CHECKLIST.map(g => {
    let gt = 0, gd = 0;
    g.items.forEach(([key]) => { gt++; total++; if ((checklistState[key] || {}).checked) { gd++; done++; } });
    return { gt, gd };
  });
  // left tabs
  const tabs = $("clTabs"); tabs.innerHTML = "";
  CHECKLIST.forEach((g, i) => {
    const s = stats[i]; const complete = s.gt > 0 && s.gd === s.gt;
    const el = document.createElement("div");
    el.className = "cl-tab" + (i === clActiveGroup ? " active" : "");
    el.innerHTML = `<span class="cl-tab-name">${esc(g.group)}</span><span class="cl-tab-count ${complete ? "done" : ""}">${complete ? "✓ " : ""}${s.gd}/${s.gt}</span>`;
    el.onclick = () => { clActiveGroup = i; renderChecklist(); };
    tabs.appendChild(el);
  });
  // overall progress
  const pct = total ? Math.round(done / total * 100) : 0;
  $("clRing").textContent = pct + "%"; $("clFill").style.width = pct + "%"; $("clTxt").textContent = `${done} of ${total} checked`;
  // right pane
  renderClPane(stats[clActiveGroup]);
}
function renderClPane(stat) {
  const g = CHECKLIST[clActiveGroup]; const pane = $("clPane"); pane.innerHTML = "";
  if (!g) return;
  const head = document.createElement("div"); head.className = "cl-pane-head";
  head.innerHTML = `<span class="cl-pane-title">${esc(g.group)}</span><span class="cl-pane-sub">${stat ? `${stat.gd}/${stat.gt} done` : ""}</span>`;
  pane.appendChild(head);
  g.items.forEach(([key, title, desc, refs]) => {
    const st = checklistState[key] || {};
    const item = document.createElement("div"); item.className = "cl-item" + (st.checked ? " done" : "");
    item.innerHTML = `<input type="checkbox" class="cl-cb" ${st.checked ? "checked" : ""} onchange="toggleCheck('${key}',this.checked)">
      <div class="cl-body"><div class="cl-title ${st.checked ? "done" : ""}">${esc(title)}</div>
        <div class="cl-desc">${esc(desc)}</div><div class="cl-refs">${esc(refs)}</div>
        <textarea class="cl-note" placeholder="Notes / evidence…" oninput="noteCheck('${key}',this.value)">${esc(st.note || "")}</textarea></div>`;
    pane.appendChild(item);
  });
}
function toggleCheck(key, v) { checklistState[key] = { ...(checklistState[key] || {}), checked: v }; renderChecklist(); persist(); }
function noteCheck(key, v) { checklistState[key] = { ...(checklistState[key] || {}), note: v }; clearTimeout(noteCheck._t); noteCheck._t = setTimeout(persist, 600); }
function resetChecklist() { checklistState = {}; renderChecklist(); persist(); }

/* ============================================================
   Init
   ============================================================ */
window.addEventListener("load", async () => {
  await loadPersisted();
  writeForm(); renderHistory(); renderRepList(); renderChecklist(); repNew();
  connectWS();
});

//! The single embedded HTML page for the testbed web UI.
//!
//! The page is self-contained: inline CSS, inline JavaScript, a system font stack,
//! and no external CDN or font. It renders with no network as soon as the server
//! answers `GET /`. The design tokens live in `:root`, and transitions animate only
//! `transform` and `opacity`, which the browser can animate without a relayout.

/// The whole page. One `&str`, served verbatim from `GET /`.
pub const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>MMP.OAuth Testbed</title>
<style>
  :root {
    /* Surfaces — a deep, calm slate, layered so panels read as stacked planes. */
    --bg: #0d1117;            /* page floor */
    --surface-1: #151b24;     /* card */
    --surface-2: #1c2531;     /* raised control / list row */
    --surface-3: #232f3d;     /* hover plane */
    --border: #2a3543;
    --border-strong: #38465a;

    /* Ink */
    --text: #e6edf3;
    --text-dim: #9aa7b4;
    --text-faint: #6b7886;

    /* One confident accent: a trustworthy teal for "authorized". */
    --accent: #2dd4bf;
    --accent-strong: #14b8a6;
    --accent-ink: #04221d;
    --accent-glow: rgba(45, 212, 191, 0.18); /* #2dd4bf teal @ 18% */

    /* Semantic state */
    --ok: #2dd4bf;            /* #2dd4bf teal — active/authorized */
    --ok-bg: rgba(45, 212, 191, 0.12);
    --warn: #f0b429;          /* #f0b429 amber — running */
    --warn-bg: rgba(240, 180, 41, 0.12);
    --err: #f87171;           /* #f87171 soft red — failure (calm, not alarming) */
    --err-bg: rgba(248, 113, 113, 0.10);

    /* Rhythm — a deliberate spacing scale, not uniform padding. */
    --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px;
    --s-5: 24px; --s-6: 32px; --s-7: 48px;

    --radius: 12px;
    --radius-sm: 8px;
    --radius-pill: 999px;

    --shadow-1: 0 1px 2px rgba(0,0,0,0.3);
    --shadow-2: 0 8px 24px rgba(0,0,0,0.35);

    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, Consolas, monospace;

    --dur: 180ms;
    --ease: cubic-bezier(0.16, 1, 0.3, 1);
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    background:
      radial-gradient(1200px 600px at 80% -10%, var(--accent-glow), transparent 60%),
      var(--bg);
    color: var(--text);
    font-family: var(--font);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  header.site {
    padding: var(--s-7) var(--s-6) var(--s-5);
    max-width: 1100px;
    margin: 0 auto;
  }
  .brand {
    display: flex; align-items: center; gap: var(--s-3);
    font-weight: 700; letter-spacing: -0.01em;
  }
  .brand .dot {
    width: 12px; height: 12px; border-radius: var(--radius-pill);
    background: var(--accent);
    box-shadow: 0 0 0 4px var(--accent-glow);
  }
  header.site h1 {
    font-size: clamp(1.6rem, 1rem + 2vw, 2.4rem);
    margin: var(--s-3) 0 var(--s-2);
    letter-spacing: -0.02em;
  }
  header.site p.lede {
    color: var(--text-dim); margin: 0; font-size: 1.05rem; max-width: 60ch;
  }

  main {
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 var(--s-6) var(--s-7);
    display: grid;
    grid-template-columns: minmax(300px, 360px) 1fr;
    gap: var(--s-6);
    align-items: start;
  }
  @media (max-width: 820px) {
    main { grid-template-columns: 1fr; }
  }

  section.panel {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow-2);
    overflow: hidden;
  }
  .panel-head {
    padding: var(--s-4) var(--s-5);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .panel-head h2 {
    font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-dim); margin: 0; font-weight: 600;
  }
  .panel-body { padding: var(--s-4); }

  /* --- App picker list --- */
  ul.apps { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .app-row {
    display: flex; align-items: center; gap: var(--s-3);
    width: 100%; text-align: left;
    padding: var(--s-3) var(--s-4);
    background: var(--surface-2);
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    color: var(--text); cursor: pointer;
    transition: transform var(--dur) var(--ease), background var(--dur) var(--ease), border-color var(--dur) var(--ease);
  }
  .app-row:hover { background: var(--surface-3); transform: translateX(2px); }
  .app-row:focus-visible { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .app-row[aria-selected="true"] {
    border-color: var(--accent-strong);
    background: var(--surface-3);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .app-row .avatar {
    width: 34px; height: 34px; flex: none;
    border-radius: var(--radius-sm);
    display: grid; place-items: center;
    font-weight: 700; font-size: 0.95rem;
    background: linear-gradient(135deg, var(--accent), var(--accent-strong));
    color: var(--accent-ink);
  }
  .app-row .meta { min-width: 0; }
  .app-row .name { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .app-row .sub { font-size: 0.8rem; color: var(--text-faint); font-family: var(--mono);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .muted-empty { color: var(--text-faint); padding: var(--s-4); font-size: 0.9rem; }

  /* --- Buttons --- */
  button { font-family: inherit; font-size: 0.95rem; }
  .btn {
    appearance: none; border: 1px solid var(--border-strong);
    background: var(--surface-2); color: var(--text);
    padding: var(--s-3) var(--s-4); border-radius: var(--radius-sm);
    cursor: pointer; font-weight: 600;
    transition: transform var(--dur) var(--ease), background var(--dur) var(--ease), border-color var(--dur) var(--ease), opacity var(--dur) var(--ease);
  }
  .btn:hover { background: var(--surface-3); }
  .btn:active { transform: translateY(1px); }
  .btn:focus-visible { outline: none; box-shadow: 0 0 0 3px var(--accent-glow); }
  .btn[disabled] { opacity: 0.5; cursor: not-allowed; }
  .btn.ghost { background: transparent; }
  .btn.accent {
    background: linear-gradient(135deg, var(--accent), var(--accent-strong));
    color: var(--accent-ink); border-color: transparent;
    box-shadow: 0 6px 18px var(--accent-glow);
  }
  .btn.accent:hover { filter: brightness(1.05); }
  .btn.block { width: 100%; }
  .picker-actions { display: flex; gap: var(--s-2); margin-top: var(--s-4); }

  /* --- Run + results --- */
  .run-bar { display: flex; align-items: center; gap: var(--s-4); margin-bottom: var(--s-5); }
  .run-target { min-width: 0; }
  .run-target .label { font-size: 0.78rem; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.06em; }
  .run-target .value { font-weight: 700; font-size: 1.15rem; letter-spacing: -0.01em; }

  /* --- Progress trail --- */
  ol.trail { list-style: none; display: flex; gap: var(--s-2); margin: 0 0 var(--s-5); padding: 0; }
  ol.trail li {
    flex: 1; display: flex; flex-direction: column; gap: var(--s-2);
    font-size: 0.78rem; color: var(--text-faint);
  }
  ol.trail .bar {
    height: 5px; border-radius: var(--radius-pill); background: var(--surface-2);
    overflow: hidden; position: relative;
  }
  ol.trail .bar::after {
    content: ""; position: absolute; inset: 0; transform: scaleX(0); transform-origin: left;
    background: var(--accent); transition: transform 320ms var(--ease);
  }
  ol.trail li[data-state="done"] .bar::after { transform: scaleX(1); }
  ol.trail li[data-state="active"] .bar::after { transform: scaleX(0.5); background: var(--warn); }
  ol.trail li[data-state="done"] { color: var(--accent); }
  ol.trail li[data-state="active"] { color: var(--warn); }
  ol.trail li[data-state="fail"] .bar::after { transform: scaleX(1); background: var(--err); }
  ol.trail li[data-state="fail"] { color: var(--err); }

  /* --- Status pill --- */
  .pill {
    display: inline-flex; align-items: center; gap: var(--s-2);
    padding: var(--s-2) var(--s-4); border-radius: var(--radius-pill);
    font-weight: 700; font-size: 0.85rem; letter-spacing: 0.02em;
    background: var(--surface-2); color: var(--text-dim);
    border: 1px solid var(--border);
  }
  .pill .ind { width: 9px; height: 9px; border-radius: var(--radius-pill); background: currentColor; }
  .pill.ok { color: var(--ok); background: var(--ok-bg); border-color: transparent; }
  .pill.ok .ind { box-shadow: 0 0 0 4px var(--ok-bg); }
  .pill.warn { color: var(--warn); background: var(--warn-bg); border-color: transparent; }
  .pill.err { color: var(--err); background: var(--err-bg); border-color: transparent; }

  /* --- Result detail grid --- */
  dl.result { display: grid; grid-template-columns: 160px 1fr; gap: var(--s-3) var(--s-4); margin: var(--s-5) 0 0; }
  dl.result dt { color: var(--text-faint); font-size: 0.85rem; }
  dl.result dd { margin: 0; font-family: var(--mono); font-size: 0.9rem; word-break: break-all; }
  dl.result dd .token { color: var(--accent); }

  .error-box {
    margin-top: var(--s-5); padding: var(--s-4);
    background: var(--err-bg); border: 1px solid rgba(248,113,113,0.3);
    border-radius: var(--radius-sm); color: var(--text);
    font-family: var(--mono); font-size: 0.88rem; white-space: pre-wrap; word-break: break-word;
  }
  .placeholder { color: var(--text-faint); padding: var(--s-5) var(--s-4); text-align: center; }

  /* --- Add form --- */
  form.add { display: none; flex-direction: column; gap: var(--s-4); margin-top: var(--s-4);
    padding-top: var(--s-4); border-top: 1px dashed var(--border); }
  form.add.open { display: flex; }
  .field { display: flex; flex-direction: column; gap: var(--s-2); }
  .field label { font-size: 0.82rem; color: var(--text-dim); font-weight: 600; }
  .field input, .field select {
    font-family: inherit; font-size: 0.95rem; color: var(--text);
    background: var(--surface-2); border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm); padding: var(--s-3) var(--s-4);
    transition: border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease);
  }
  .field input:focus, .field select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .field input::placeholder { color: var(--text-faint); }
  .field .hint { font-size: 0.78rem; color: var(--text-faint); font-family: var(--mono); }
  .form-actions { display: flex; gap: var(--s-2); margin-top: var(--s-2); }

  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
</style>
</head>
<body>
<header class="site" id="page-header">
  <div class="brand"><span class="dot" aria-hidden="true"></span> MMP.OAuth Testbed</div>
  <h1>The OAuth front door, tested live.</h1>
  <p class="lede">Pick a saved app, run the real consent dance against the provider, and read the token's shape — never its bytes. Add a new app and its config is written to <code>keys/</code>.</p>
</header>

<main>
  <section class="panel" id="picker-panel" aria-labelledby="picker-h">
    <div class="panel-head"><h2 id="picker-h">Saved apps</h2></div>
    <div class="panel-body">
      <ul class="apps" id="app-list" role="listbox" aria-label="Saved OAuth apps"></ul>
      <div class="picker-actions">
        <button class="btn ghost block" id="add-toggle" type="button" aria-expanded="false" aria-controls="add-form">+ Add app</button>
      </div>

      <form class="add" id="add-form" autocomplete="off">
        <div class="field">
          <label for="f-name">Name</label>
          <input id="f-name" name="name" type="text" placeholder="Team's App" required />
        </div>
        <div class="field">
          <label for="f-provider">Provider</label>
          <select id="f-provider" name="provider">
            <option value="google">Google</option>
            <option value="microsoft">Microsoft</option>
          </select>
        </div>
        <div class="field">
          <label for="f-client-id">Client ID</label>
          <input id="f-client-id" name="client_id" type="text" placeholder="…apps.googleusercontent.com" required />
        </div>
        <div class="field">
          <label for="f-client-secret">Client secret <span class="hint">(optional — public clients omit it)</span></label>
          <input id="f-client-secret" name="client_secret" type="password" placeholder="GOCSPX-…" />
        </div>
        <div class="field">
          <label for="f-scopes">Scopes <span class="hint">(comma or space separated)</span></label>
          <input id="f-scopes" name="scopes" type="text" placeholder="https://www.googleapis.com/auth/userinfo.email" />
        </div>
        <div class="form-actions">
          <button class="btn accent" id="save-app" type="submit">Save app</button>
          <button class="btn ghost" id="cancel-add" type="button">Cancel</button>
        </div>
      </form>
    </div>
  </section>

  <section class="panel" id="run-panel" aria-labelledby="run-h">
    <div class="panel-head">
      <h2 id="run-h">Live test</h2>
      <span class="pill" id="status-pill" role="status" aria-live="polite"><span class="ind" aria-hidden="true"></span><span id="status-text">Idle</span></span>
    </div>
    <div class="panel-body">
      <div class="run-bar">
        <div class="run-target">
          <div class="label">Selected app</div>
          <div class="value" id="run-target-name">—</div>
        </div>
        <button class="btn accent" id="run-btn" type="button" disabled style="margin-left:auto">Run test</button>
      </div>

      <ol class="trail" id="trail" aria-label="Flow progress">
        <li data-step="authorize"><span class="bar" aria-hidden="true"></span>Authorize</li>
        <li data-step="consent"><span class="bar" aria-hidden="true"></span>Consent</li>
        <li data-step="loopback"><span class="bar" aria-hidden="true"></span>Loopback</li>
        <li data-step="exchange"><span class="bar" aria-hidden="true"></span>Exchange</li>
      </ol>

      <div id="result-region" aria-live="polite">
        <div class="placeholder" id="result-placeholder">Select an app and press <strong>Run test</strong> to start the consent dance.</div>
      </div>
    </div>
  </section>
</main>

<script>
(function () {
  "use strict";
  // A hand-written fetch and render loop, with no framework. The whole UI is one
  // page that calls four endpoints, so a build step or a SPA library adds nothing.

  var state = { apps: [], selected: null, running: false };

  var $ = function (id) { return document.getElementById(id); };
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
  }

  function initials(name) {
    var parts = String(name || "?").trim().split(/\s+/);
    var a = parts[0] ? parts[0][0] : "?";
    var b = parts.length > 1 ? parts[parts.length - 1][0] : "";
    return (a + b).toUpperCase();
  }

  function renderApps() {
    var list = $("app-list");
    if (!state.apps.length) {
      list.innerHTML = '<div class="muted-empty">No saved apps yet. Add one to begin.</div>';
      return;
    }
    list.innerHTML = state.apps.map(function (app) {
      var sel = state.selected === app.slug;
      return '<li role="option" aria-selected="' + sel + '">' +
        '<button class="app-row" data-slug="' + esc(app.slug) + '" aria-selected="' + sel + '">' +
          '<span class="avatar" aria-hidden="true">' + esc(initials(app.name)) + '</span>' +
          '<span class="meta">' +
            '<span class="name">' + esc(app.name) + '</span>' +
            '<span class="sub">' + esc(app.provider) + ' · ' + esc(app.client_id_masked) + '</span>' +
          '</span>' +
        '</button></li>';
    }).join("");
    Array.prototype.forEach.call(list.querySelectorAll(".app-row"), function (btn) {
      btn.addEventListener("click", function () { select(btn.getAttribute("data-slug")); });
    });
  }

  function select(slug) {
    state.selected = slug;
    var app = state.apps.filter(function (a) { return a.slug === slug; })[0];
    $("run-target-name").textContent = app ? app.name : "—";
    $("run-btn").disabled = !app || state.running;
    renderApps();
  }

  function setStatus(kind, text) {
    var pill = $("status-pill");
    pill.className = "pill" + (kind ? " " + kind : "");
    $("status-text").textContent = text;
  }

  function setTrail(map) {
    Array.prototype.forEach.call($("trail").children, function (li) {
      var s = map[li.getAttribute("data-step")];
      if (s) { li.setAttribute("data-state", s); } else { li.removeAttribute("data-state"); }
    });
  }

  function resetTrail() { setTrail({}); }

  async function loadApps() {
    var res = await fetch("/api/apps");
    state.apps = await res.json();
    renderApps();
  }

  async function runTest() {
    if (!state.selected || state.running) return;
    state.running = true;
    $("run-btn").disabled = true;
    $("result-region").innerHTML = "";
    setStatus("warn", "Running…");
    // tiny_http serves one connection at a time, and the run blocks until the
    // exchange returns, so the server cannot stream per-step progress. The page
    // advances the step trail on a timer up to "exchange", then sets it from the
    // final result.
    setTrail({ authorize: "done", consent: "active" });
    setTimeout(function () { if (state.running) setTrail({ authorize: "done", consent: "done", loopback: "active" }); }, 600);

    try {
      var res = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: state.selected })
      });
      var data = await res.json();
      if (data.ok) { renderSuccess(data); } else { renderFailure(data.error || "unknown error"); }
    } catch (e) {
      renderFailure(String(e));
    } finally {
      state.running = false;
      $("run-btn").disabled = !state.selected;
    }
  }

  function renderSuccess(d) {
    var active = (d.status === "Active");
    setStatus(active ? "ok" : "warn", d.status);
    setTrail({ authorize: "done", consent: "done", loopback: "done", exchange: "done" });
    var scopes = (d.granted_scopes || []).map(esc).join("<br>");
    var expiry = d.expires_at_unix ? new Date(d.expires_at_unix * 1000).toLocaleString() : "—";
    $("result-region").innerHTML =
      '<dl class="result">' +
        '<dt>Status</dt><dd>' + esc(d.status) + '</dd>' +
        '<dt>Access token</dt><dd class="token">Secret(&lt;redacted len=' + esc(d.access_token_len) + '&gt;)</dd>' +
        '<dt>Expires</dt><dd>' + esc(expiry) + '</dd>' +
        '<dt>Granted scopes</dt><dd>' + (scopes || "—") + '</dd>' +
      '</dl>';
  }

  function renderFailure(msg) {
    setStatus("err", "Failed");
    setTrail({ authorize: "done", consent: "fail" });
    $("result-region").innerHTML = '<div class="error-box">' + esc(msg) + '</div>';
  }

  // --- Add form ---
  function toggleAdd(open) {
    var form = $("add-form"), btn = $("add-toggle");
    form.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", String(open));
    if (open) { $("f-name").focus(); }
  }

  async function saveApp(ev) {
    ev.preventDefault();
    var body = {
      name: $("f-name").value,
      provider: $("f-provider").value,
      client_id: $("f-client-id").value,
      client_secret: $("f-client-secret").value,
      scopes: $("f-scopes").value
    };
    var btn = $("save-app");
    btn.disabled = true;
    try {
      var res = await fetch("/api/apps", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      var data = await res.json();
      if (!res.ok || data.error) { alert("Could not save: " + (data.error || res.status)); return; }
      $("add-form").reset();
      toggleAdd(false);
      await loadApps();
      select(data.slug);
    } finally {
      btn.disabled = false;
    }
  }

  $("add-toggle").addEventListener("click", function () {
    toggleAdd(!$("add-form").classList.contains("open"));
  });
  $("cancel-add").addEventListener("click", function () { toggleAdd(false); });
  $("add-form").addEventListener("submit", saveApp);
  $("run-btn").addEventListener("click", runTest);

  loadApps().then(function () {
    if (state.apps.length) { select(state.apps[0].slug); }
  });
})();
</script>
</body>
</html>
"#;

// popup.js
// Orchestrates the analysis: gather DOM signals (content script) + response
// data (background), run detection, render. Resolves IP via DNS fallback when
// the page came from cache. Deep scan is opt-in via its own button.

const els = {
  host: document.getElementById("host"),
  serverBody: document.getElementById("serverBody"),
  protectionPanel: document.getElementById("protectionPanel"),
  protectionBody: document.getElementById("protectionBody"),
  wpPanel: document.getElementById("wpPanel"),
  wpBody: document.getElementById("wpBody"),
  deepBtn: document.getElementById("deepBtn"),
  techBody: document.getElementById("techBody"),
  techCount: document.getElementById("techCount"),
  rescanBtn: document.getElementById("rescanBtn"),
  settingsBtn: document.getElementById("settingsBtn"),
  logBtn: document.getElementById("logBtn"),
  shotBtn: document.getElementById("shotBtn"),
  // Network tab
  dnsBtn: document.getElementById("dnsBtn"),
  dnsExportBtn: document.getElementById("dnsExportBtn"),
  dnsBody: document.getElementById("dnsBody"),
  subBtn: document.getElementById("subBtn"),
  subBody: document.getElementById("subBody"),
  // WHOIS tab
  whoisBtn: document.getElementById("whoisBtn"),
  whoisBody: document.getElementById("whoisBody"),
  // Headers tab
  headersBody: document.getElementById("headersBody"),
};

let currentTab = null;
let currentSignals = null;
let currentTechs = [];
let currentHeaders = null; // { configured, missing, misconfigured } from analyzeHeaders
let currentDnsExport = null; // { zone, byType } for the BIND export

// --- Helpers -------------------------------------------------------------

// Copy text to the clipboard and flash the source element as feedback.
function copyToClipboard(text, sourceEl) {
  if (!text) return;
  const flash = () => {
    if (!sourceEl) return;
    sourceEl.classList.add("copied");
    setTimeout(() => sourceEl.classList.remove("copied"), 600);
  };
  // navigator.clipboard works in the extension popup (secure context).
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flash).catch(() => fallbackCopy(text, flash));
  } else {
    fallbackCopy(text, flash);
  }
}

// Fallback for environments where navigator.clipboard is unavailable.
function fallbackCopy(text, done) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    if (done) done();
  } catch (e) {}
}

// Extract the clean text to copy from a clickable item. Prefer an explicit
// data-copy attribute; otherwise use the element's trimmed text content.
function copyValueOf(el) {
  if (el.dataset && el.dataset.copy) return el.dataset.copy;
  // Clone and strip helper widgets (tags, hints, flags) so we copy the value.
  const clone = el.cloneNode(true);
  clone.querySelectorAll(
    ".dns-ttl, .dns-origin, .kv-hint, .ip-flag, .ip-flag-slot, .layer-help, .layer-cat, .layer-version, .implied-tag, .sub-actions, .evidence-tip"
  ).forEach((n) => n.remove());
  return clone.textContent.trim();
}

function confBucket(t) {
  if (t.implied) return "implied";
  if (t.confidence >= 90) return "high";
  if (t.confidence >= 75) return "mid";
  return "low";
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderState(container, message, hint) {
  container.innerHTML = `
    <div class="state">
      <div class="state-mono">${escapeHtml(message)}</div>
      ${hint ? `<div class="state-hint">${escapeHtml(hint)}</div>` : ""}
    </div>`;
}

// --- Renderers -----------------------------------------------------------

function renderServer(summary, behindCdn) {
  const proxyNote = behindCdn
    ? '<span class="kv-hint">(CDN edge, not origin)</span>'
    : summary.fromCache ? '<span class="kv-hint">(via DNS)</span>' : "";
  const ipVal = summary.ip
    ? `${escapeHtml(summary.ip)}<span id="stack-ip-flag" class="ip-flag-slot"></span>${proxyNote}`
    : '<span class="kv-val empty">resolving…</span>';

  const rows = [
    ["IP", summary.ip ? ipVal : null, true],
    ["Server", summary.server, false],
    ["Powered-By", summary.poweredBy, false],
    ["Via", summary.via, false],
    ["Status", summary.statusCode, false],
  ];

  els.serverBody.innerHTML = rows
    .map(([key, val, isHtml]) => {
      const empty = val === null || val === undefined || val === "";
      const content = empty
        ? "not exposed"
        : isHtml ? val : escapeHtml(val);
      return `
        <div class="kv">
          <span class="kv-key">${key}</span>
          <span class="kv-val ${empty ? "empty" : ""}">${content}</span>
        </div>`;
    })
    .join("");

  if (summary.viaFetch) {
    els.serverBody.innerHTML += `
      <div class="kv">
        <span class="kv-key"></span>
        <span class="kv-hint">headers read via direct request — some may be hidden by CORS</span>
      </div>`;
  }

  // Fill the country flag asynchronously (cached per IP in the background).
  if (summary.ip) {
    flagFor(summary.ip).then((flagHtml) => {
      const slot = document.getElementById("stack-ip-flag");
      if (slot && flagHtml) slot.outerHTML = flagHtml;
    });
  }
}

function renderProtection(services) {
  if (!services.length) {
    els.protectionPanel.hidden = true;
    return;
  }
  els.protectionPanel.hidden = false;
  els.protectionBody.innerHTML = services
    .map(
      (s) => `
      <div class="protect-row">
        <span class="protect-dot"></span>
        <span class="protect-name">${escapeHtml(s.name)}</span>
        <span class="protect-type">${escapeHtml(s.type)}</span>
      </div>`
    )
    .join("");
}

function renderWordPress(signals, techs, deep) {
  const isWp = techs.some((t) => t.name === "WordPress");
  if (!isWp) {
    els.wpPanel.hidden = true;
    return;
  }
  els.wpPanel.hidden = false;

  const wp = signals.wordpress || { themes: [], plugins: [] };
  const wpTech = techs.find((t) => t.name === "WordPress");
  const version = (deep && deep.readme) || (wpTech && wpTech.version) || null;

  const chips = (arr, cls) =>
    arr.length
      ? `<div class="wp-chips">${arr
          .map((n) => `<span class="wp-chip ${cls}">${escapeHtml(n)}</span>`)
          .join("")}</div>`
      : `<span class="wp-empty">none visible in page source</span>`;

  // Merge plugins found in HTML with any found via deep scan REST namespaces.
  let plugins = [...wp.plugins];
  if (deep && deep.restPlugins) {
    deep.restPlugins.forEach((p) => {
      const short = p.split("/")[0];
      if (short && !plugins.includes(short)) plugins.push(short);
    });
  }

  els.wpBody.innerHTML = `
    ${version ? `
    <div class="wp-group">
      <div class="wp-group-label">Version</div>
      <div class="wp-chips"><span class="wp-chip">${escapeHtml(version)}</span></div>
    </div>` : ""}
    <div class="wp-group">
      <div class="wp-group-label">Theme${wp.themes.length > 1 ? "s" : ""}</div>
      ${chips(wp.themes, "theme")}
    </div>
    <div class="wp-group">
      <div class="wp-group-label">Plugins (front-end visible)</div>
      ${chips(plugins, "plugin")}
    </div>
    ${deep && deep.restApi ? `
    <div class="wp-group">
      <div class="wp-group-label">REST API</div>
      <div class="wp-chips"><span class="wp-chip">/wp-json/ exposed</span></div>
    </div>` : ""}`;
}

function renderTech(techs) {
  if (!techs.length) {
    renderState(els.techBody, "no technologies detected",
      "This page exposes few public signals, or it loads its stack dynamically.");
    els.techCount.hidden = true;
    return;
  }
  els.techCount.hidden = false;
  els.techCount.textContent = techs.length;

  els.techBody.innerHTML = techs
    .map((t, i) => {
      const bucket = confBucket(t);
      const meta = t.implied
        ? "inferred from related tech"
        : `${t.confidence}% · matched on ${t.matchedOn.join(", ")}`;
      const ver = t.version ? `<span class="layer-version">v${escapeHtml(t.version)}</span>` : "";
      const hasEv = t.evidence && t.evidence.length;
      const help = hasEv
        ? `<button class="layer-help" aria-label="Why ${escapeHtml(t.name)} was detected" data-ev="${i}">?</button>`
        : "";
      return `
        <div class="layer">
          <div class="layer-tick" data-conf="${bucket}"></div>
          <div class="layer-main">
            <div class="layer-name">${escapeHtml(t.name)}${ver}${
        t.implied ? '<span class="implied-tag">inferred</span>' : ""
      }</div>
            <div class="layer-meta">${escapeHtml(meta)}</div>
          </div>
          <span class="layer-cat">${escapeHtml(t.category)}</span>
          ${help}
          ${hasEv ? renderEvidenceTip(t) : ""}
        </div>`;
    })
    .join("");
}

// Build the evidence tooltip shown on hover/focus for a tech.
function renderEvidenceTip(t) {
  const ev = t.evidence || [];
  if (!ev.length) return "";

  const kindLabel = {
    header: "HTTP header",
    meta: "meta tag",
    global: "JS global",
    cookie: "cookie",
    script: "script URL",
    html: "page HTML",
    inference: "inference",
  };

  const items = ev
    .map((e) => {
      const label = kindLabel[e.type] || e.type;
      return `
        <div class="evidence-item">
          <span class="evidence-kind">${escapeHtml(label)}</span>
          <div class="evidence-detail">${highlightDetail(e)}</div>
        </div>`;
    })
    .join("");

  return `
    <div class="evidence-tip" role="tooltip">
      <div class="evidence-tip-head">Why this was detected</div>
      ${items}
    </div>`;
}

// Escape, then highlight the meaningful token inside the evidence detail.
function highlightDetail(e) {
  const safe = escapeHtml(e.detail);
  // Highlight the matched source token when we can locate it.
  if (e.source && e.type !== "inference" && e.type !== "html") {
    const token = escapeHtml(e.source);
    return safe.replace(token, `<span class="hl">${token}</span>`);
  }
  return safe;
}

// --- Headers tab ---------------------------------------------------------

// Map a header status to the confidence-tick color buckets reused from Stack:
// good -> green (high), warning -> amber, bad -> red.
function headerTickConf(status) {
  if (status === "good") return "high";
  if (status === "bad") return "bad";
  if (status === "missing") return "missing";
  return "warn";
}

// One row in a Headers section. `nameHtml` is already-safe markup; `ariaName`
// is plain text for the help button. `tip` holds the {head, body} of the
// ? tooltip (omit for no tooltip).
function headerRow(nameHtml, ariaName, status, detailHtml, tip) {
  const help = tip
    ? `<button class="layer-help" aria-label="About ${escapeHtml(ariaName)}" tabindex="0">?</button>
       <div class="evidence-tip" role="tooltip">
         <div class="evidence-tip-head">${escapeHtml(tip.head)}</div>
         ${tip.body}
       </div>`
    : "";
  return `
    <div class="header-row layer">
      <div class="layer-tick" data-conf="${headerTickConf(status)}"></div>
      <div class="layer-main">
        <div class="header-name">${nameHtml}</div>
        ${detailHtml}
      </div>
      <span class="header-status" data-status="${escapeHtml(status)}">${escapeHtml(status)}</span>
      ${help}
    </div>`;
}

// A labelled section ("Configured 3", etc.) wrapping its rows.
function headerSection(label, count, rowsHtml) {
  return `
    <div class="hsec">
      <div class="hsec-head"><span class="hsec-title">${escapeHtml(label)}</span><span class="hsec-count">${count}</span></div>
      ${rowsHtml}
    </div>`;
}

function renderHeaders(analysis) {
  currentHeaders = analysis;
  if (!analysis) {
    renderState(els.headersBody, "no headers captured",
      "Could not read response headers for this page. Try Rescan, or reload the page.");
    return;
  }

  const { configured, missing, misconfigured } = analysis;

  // Misconfigured first (most actionable), then missing (to-do), then the
  // headers that are already in good shape.
  const valueHtml = (v) =>
    `<div class="header-value" data-copy="${escapeHtml(v)}" title="Click to copy">${escapeHtml(v)}</div>`;

  const misRows = misconfigured
    .map((h) =>
      headerRow(
        escapeHtml(h.name),
        h.name,
        h.status,
        valueHtml(h.value),
        {
          head: "What's wrong",
          body: `<div class="evidence-item"><div class="evidence-detail">${escapeHtml(h.issue)}</div></div>
                 <div class="evidence-item"><span class="evidence-kind">fix</span><div class="evidence-detail">${escapeHtml(h.fix)}</div></div>`,
        }
      )
    )
    .join("");

  const missRows = missing
    .map((h) =>
      headerRow(
        `${escapeHtml(h.name)} <span class="header-imp" data-imp="${escapeHtml(h.importance)}">${escapeHtml(h.importance)}</span>`,
        h.name,
        "missing",
        `<div class="layer-meta">${escapeHtml(h.why)}</div>`,
        {
          head: "Why it matters",
          body: `<div class="evidence-item"><div class="evidence-detail">${escapeHtml(h.why)}</div></div>
                 <div class="evidence-item"><span class="evidence-kind">add</span><div class="evidence-detail">${escapeHtml(h.recommendation)}</div></div>`,
        }
      )
    )
    .join("");

  const confRows = configured
    .map((h) =>
      headerRow(
        escapeHtml(h.name),
        h.name,
        h.status,
        valueHtml(h.value),
        { head: "What this does", body: `<div class="evidence-item"><div class="evidence-detail">${escapeHtml(h.explanation)}</div></div>` }
      )
    )
    .join("");

  const sections = [];
  if (misconfigured.length) sections.push(headerSection("Misconfigured", misconfigured.length, misRows));
  if (missing.length) sections.push(headerSection("Recommended (missing)", missing.length, missRows));
  if (configured.length) sections.push(headerSection("Configured", configured.length, confRows));

  els.headersBody.innerHTML = sections.join("") ||
    `<div class="state"><div class="state-mono">no security headers to report</div></div>`;
}

// --- Data flow -----------------------------------------------------------

const getActiveTab = () =>
  new Promise((res) =>
    chrome.tabs.query({ active: true, currentWindow: true }, (t) => res(t[0]))
  );

const getHeaders = (tabId, url) =>
  new Promise((res) =>
    chrome.runtime.sendMessage({ action: "getHeaders", tabId, url }, (r) => res(r || null))
  );

const getPageSignals = (tabId) =>
  new Promise((res) =>
    chrome.tabs.sendMessage(tabId, { action: "getPageSignals" }, (r) =>
      res(chrome.runtime.lastError ? null : r || null)
    )
  );

const resolveIp = (hostname) =>
  new Promise((res) =>
    chrome.runtime.sendMessage({ action: "resolveIp", hostname }, (r) =>
      res(chrome.runtime.lastError ? null : (r && r.ip) || null)
    )
  );

const geoLookup = (ip) =>
  new Promise((res) =>
    chrome.runtime.sendMessage(
      { action: "geoLookup", ip, tabId: currentTab && currentTab.id },
      (r) => res(chrome.runtime.lastError ? null : r || null)
    )
  );

// Helper: given an IP, return an HTML flag span (with country tooltip), or "".
async function flagFor(ip) {
  if (!ip) return "";
  const geo = await geoLookup(ip);
  if (!geo || !geo.cc) return "";
  const flag = NetworkTools.flagEmoji(geo.cc);
  if (!flag) return "";
  return `<span class="ip-flag" title="${escapeHtml(geo.country)}">${flag}</span>`;
}

const runDeepScan = (tabId) =>
  new Promise((res) =>
    chrome.tabs.sendMessage(tabId, { action: "deepScan" }, (r) =>
      res(chrome.runtime.lastError ? null : r || null)
    )
  );

async function run() {
  const tab = await getActiveTab();
  currentTab = tab;

  if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
    els.host.textContent = "—";
    renderState(els.serverBody, "unsupported page",
      "Open a normal http(s) website to analyze its stack.");
    els.protectionPanel.hidden = true;
    els.wpPanel.hidden = true;
    renderState(els.techBody, "nothing to analyze");
    els.techCount.hidden = true;
    return;
  }

  let hostname = "—";
  try { hostname = new URL(tab.url).hostname; } catch (e) {}
  els.host.textContent = hostname;

  const [signals, headerData] = await Promise.all([
    getPageSignals(tab.id),
    getHeaders(tab.id, tab.url),
  ]);
  currentSignals = signals;

  const summary = TechDetector.serverSummary(headerData);
  const protectionServices = TechDetector.protection(headerData);
  const behindCdn = protectionServices.length > 0;
  renderServer(summary, behindCdn);
  renderProtection(protectionServices);

  // Prefer IPv4. Resolve via DNS when the IP is missing, came from cache,
  // or Chrome connected over IPv6 (contains ':').
  const needsIpv4 = !summary.ip || summary.fromCache || String(summary.ip).includes(":");
  if (needsIpv4 && hostname !== "—") {
    resolveIp(hostname).then((ip) => {
      if (ip) renderServer({ ...summary, ip, fromCache: true }, behindCdn);
    });
  }

  const safeSignals = signals || {
    html: "", scripts: [], stylesheets: [], meta: {}, globals: [], cookies: [],
    wordpress: { themes: [], plugins: [] },
  };

  if (!signals && !headerData) {
    renderState(els.techBody, "could not read page",
      "Try rescanning, or reload the page and reopen this panel.");
    els.techCount.hidden = true;
    els.wpPanel.hidden = true;
    return;
  }

  const techs = TechDetector.detect(safeSignals, headerData);
  currentTechs = techs;
  renderTech(techs);
  renderWordPress(safeSignals, techs, null);

  // Security headers analysis — uses the headers already captured above, so
  // no extra request or cache key is needed. Renders eagerly even though the
  // Headers tab may not be open yet (same as Stack).
  renderHeaders(headerData ? TechDetector.analyzeHeaders(headerData.headers) : null);
}

// --- Events --------------------------------------------------------------

els.rescanBtn.addEventListener("click", () => {
  renderState(els.serverBody, "reading headers…");
  renderState(els.techBody, "analyzing page…");
  renderState(els.headersBody, "reading headers…");
  els.protectionPanel.hidden = true;
  els.wpPanel.hidden = true;
  run();
});

els.settingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());

// --- Diagnostic log download ---------------------------------------------

const getLog = (tabId) =>
  new Promise((res) =>
    chrome.runtime.sendMessage({ action: "getLog", tabId }, (r) =>
      res(chrome.runtime.lastError ? { entries: [] } : r || { entries: [] })
    )
  );

function buildLogText(meta, entries) {
  const lines = [];
  lines.push("WebAnalyzer diagnostic log");
  lines.push("=".repeat(40));
  lines.push(`Generated: ${meta.generated}`);
  lines.push(`URL:       ${meta.url}`);
  lines.push(`Host:      ${meta.host}`);
  lines.push(`Version:   ${meta.version}`);
  lines.push("");
  lines.push(`Entries: ${entries.length}`);
  lines.push("-".repeat(40));
  entries.forEach((e) => {
    lines.push(`[${e.t}] (${e.category}) ${e.message}`);
    if (e.data !== null && e.data !== undefined) {
      const dataStr = typeof e.data === "string" ? e.data : JSON.stringify(e.data);
      lines.push(`    ${dataStr}`);
    }
  });
  return lines.join("\n");
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportLog(format) {
  const tab = currentTab;
  const host = currentHostname() || "unknown";
  const { entries } = await getLog(tab && tab.id);

  const manifest = chrome.runtime.getManifest();
  const meta = {
    generated: new Date().toISOString(),
    url: (tab && tab.url) || "—",
    host,
    version: manifest.version,
  };

  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeHost = host.replace(/[^a-z0-9.-]/gi, "_");

  if (format === "json") {
    const payload = { meta, entries };
    downloadFile(
      `webanalyzer_${safeHost}_${stamp}.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
  } else {
    downloadFile(
      `webanalyzer_${safeHost}_${stamp}.txt`,
      buildLogText(meta, entries),
      "text/plain"
    );
  }
  hideLogMenu();
}

// Small format chooser shown above the Log button.
let logMenuEl = null;
function showLogMenu() {
  if (logMenuEl) return hideLogMenu();
  logMenuEl = document.createElement("div");
  logMenuEl.className = "log-menu";
  logMenuEl.innerHTML = `
    <button data-fmt="json">Download JSON</button>
    <button data-fmt="txt">Download TXT</button>`;
  document.body.appendChild(logMenuEl);
  const r = els.logBtn.getBoundingClientRect();
  logMenuEl.style.left = `${Math.round(r.left)}px`;
  logMenuEl.style.bottom = `${Math.round(window.innerHeight - r.top + 6)}px`;
  logMenuEl.querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", () => exportLog(b.dataset.fmt))
  );
}
function hideLogMenu() {
  if (logMenuEl) {
    logMenuEl.remove();
    logMenuEl = null;
  }
}

els.logBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  showLogMenu();
});
document.addEventListener("click", (e) => {
  if (logMenuEl && !logMenuEl.contains(e.target) && e.target !== els.logBtn) {
    hideLogMenu();
  }
});

// --- Screenshot capture --------------------------------------------------
// Renders the current popup DOM into a canvas via an SVG <foreignObject>,
// then offers to copy the PNG to the clipboard or download it. No external
// library needed — this is a native browser capability.

// Inline computed styles onto a clone so the serialized SVG looks identical
// to what's on screen (SVG foreignObject won't pull in our stylesheet).
function inlineStyles(src, dest) {
  const cs = getComputedStyle(src);
  let styleStr = "";
  for (let i = 0; i < cs.length; i++) {
    const prop = cs[i];
    styleStr += `${prop}:${cs.getPropertyValue(prop)};`;
  }
  dest.setAttribute("style", styleStr);
  const srcChildren = src.children;
  const destChildren = dest.children;
  for (let i = 0; i < srcChildren.length; i++) {
    inlineStyles(srcChildren[i], destChildren[i]);
  }
}

async function capturePopup() {
  const node = document.body;
  const width = Math.ceil(node.getBoundingClientRect().width);

  // Clone the body and inline all computed styles (SVG foreignObject won't
  // pull in our external stylesheet).
  const clone = node.cloneNode(true);
  inlineStyles(node, clone);
  clone.querySelectorAll(".shot-menu, .log-menu").forEach((n) => n.remove());

  // Expand the clone so the FULL content is captured, not just the visible
  // 600px viewport. We drop the height caps and inner scroll, then measure the
  // natural height off-screen.
  clone.style.maxHeight = "none";
  clone.style.height = "auto";
  clone.style.overflow = "visible";
  const scrollAreas = clone.querySelectorAll(".app-body, .tab-view");
  scrollAreas.forEach((el) => {
    el.style.maxHeight = "none";
    el.style.height = "auto";
    el.style.overflow = "visible";
    el.style.flex = "none";
  });

  // Mount off-screen to measure true height, then remove.
  clone.style.position = "fixed";
  clone.style.left = "-99999px";
  clone.style.top = "0";
  clone.style.width = `${width}px`;
  document.body.appendChild(clone);
  const height = Math.ceil(clone.scrollHeight);
  document.body.removeChild(clone);
  // Reset positioning so the serialized markup lays out normally in the SVG.
  clone.style.position = "static";
  clone.style.left = "";
  clone.style.top = "";

  const serialized = new XMLSerializer().serializeToString(clone);
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">` +
    `<foreignObject width="100%" height="100%">` +
    `<div xmlns="http://www.w3.org/1999/xhtml">${serialized}</div>` +
    `</foreignObject></svg>`;

  // Same-origin data URL (base64) — does not taint the canvas in Chrome.
  const dataUrl =
    "data:image/svg+xml;base64," +
    btoa(unescape(encodeURIComponent(svg)));

  const scale = 2; // crisp on high-DPI displays
  const canvas = document.createElement("canvas");
  canvas.width = width * scale;
  canvas.height = height * scale;
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);

  await new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      ctx.fillStyle = getComputedStyle(node).backgroundColor || "#0d1117";
      ctx.fillRect(0, 0, width, height);
      ctx.drawImage(img, 0, 0);
      resolve();
    };
    img.onerror = () => reject(new Error("could not render the SVG snapshot"));
    img.src = dataUrl;
  });

  return new Promise((resolve) => canvas.toBlob((b) => resolve(b), "image/png"));
}

async function copyImageToClipboard(blob) {
  try {
    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
    return true;
  } catch (e) {
    return false;
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function doCapture(action) {
  hideShotMenu();
  const prevText = els.shotBtn.textContent;
  els.shotBtn.textContent = "capturing…";
  els.shotBtn.disabled = true;
  try {
    const blob = await capturePopup();
    if (!blob) throw new Error("capture failed");
    if (action === "copy") {
      const ok = await copyImageToClipboard(blob);
      els.shotBtn.textContent = ok ? "copied ✓" : "copy failed";
    } else {
      const host = (currentHostname() || "tab").replace(/[^a-z0-9.-]/gi, "_");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      downloadBlob(blob, `webanalyzer_${host}_${stamp}.png`);
      els.shotBtn.textContent = "saved ✓";
    }
  } catch (e) {
    els.shotBtn.textContent = "failed";
  }
  setTimeout(() => {
    els.shotBtn.textContent = prevText;
    els.shotBtn.disabled = false;
  }, 1400);
}

// Small chooser (copy vs download) above the Shot button.
let shotMenuEl = null;
function showShotMenu() {
  if (shotMenuEl) return hideShotMenu();
  shotMenuEl = document.createElement("div");
  shotMenuEl.className = "log-menu shot-menu";
  shotMenuEl.innerHTML = `
    <button data-act="copy">Copy to clipboard</button>
    <button data-act="download">Download PNG</button>`;
  document.body.appendChild(shotMenuEl);
  const r = els.shotBtn.getBoundingClientRect();
  shotMenuEl.style.left = `${Math.round(r.left)}px`;
  shotMenuEl.style.bottom = `${Math.round(window.innerHeight - r.top + 6)}px`;
  shotMenuEl.querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", () => doCapture(b.dataset.act))
  );
}
function hideShotMenu() {
  if (shotMenuEl) {
    shotMenuEl.remove();
    shotMenuEl = null;
  }
}

els.shotBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  showShotMenu();
});
document.addEventListener("click", (e) => {
  if (shotMenuEl && !shotMenuEl.contains(e.target) && e.target !== els.shotBtn) {
    hideShotMenu();
  }
});

els.deepBtn.addEventListener("click", async () => {
  if (!currentTab) return;
  els.deepBtn.disabled = true;
  els.deepBtn.textContent = "scanning…";
  const deep = await runDeepScan(currentTab.id);
  // Reuse the techs computed during the main run (which had headers),
  // so the WordPress panel doesn't disappear.
  renderWordPress(
    currentSignals || { wordpress: { themes: [], plugins: [] } },
    currentTechs,
    deep
  );
  els.deepBtn.textContent = "Deep scan ✓";
});

document.addEventListener("DOMContentLoaded", run);

// --- Tab navigation ------------------------------------------------------
let networkLoaded = false; // run the Network lookups only once, on first open
let whoisLoaded = false; // run the WHOIS lookup only once, on first open

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    document.querySelectorAll(".tab-btn").forEach((b) => {
      const on = b === btn;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    document.querySelectorAll(".tab-view").forEach((v) => {
      v.classList.toggle("active", v.id === `view-${target}`);
    });

    // First time the Network tab is opened in this popup session: load DNS +
    // subdomains. These read from the persistent cache first, so they only hit
    // the network if there's no saved result for the current domain.
    if (target === "network" && !networkLoaded) {
      networkLoaded = true;
      runDnsLookup();
      runSubdomainLookup();
    }

    // First time the WHOIS tab is opened: load registration data (cached).
    if (target === "whois" && !whoisLoaded) {
      whoisLoaded = true;
      runWhoisLookup();
    }
  });
});

// --- Network: DNS + subdomains -------------------------------------------

// Persistent cache (chrome.storage.local) keyed by domain. Survives popup
// close and browser restart. Cleared per-section only via the Refresh button.
const cacheGet = (key) =>
  new Promise((res) =>
    chrome.storage.local.get(key, (r) =>
      res(chrome.runtime.lastError ? null : r[key] || null)
    )
  );

const cacheSet = (key, value) =>
  new Promise((res) =>
    chrome.storage.local.set({ [key]: value }, () => res())
  );

const dnsCacheKey = (base) => `netcache:dns:${base}`;
const subCacheKey = (base) => `netcache:sub:${base}`;
// Note: the v2 suffix invalidates any WHOIS results cached by older versions
// of the extension, whose normalized shape differed and could render empty.
const whoisCacheKey = (base) => `netcache:whois:v2:${base}`;

const dnsLookup = (hostname, types) =>
  new Promise((res) =>
    chrome.runtime.sendMessage(
      { action: "dnsLookup", hostname, types, tabId: currentTab && currentTab.id },
      (r) => res(chrome.runtime.lastError ? null : r || null)
    )
  );

const subdomainLookup = (baseDomain) =>
  new Promise((res) =>
    chrome.runtime.sendMessage(
      { action: "subdomains", baseDomain, tabId: currentTab && currentTab.id },
      (r) => res(chrome.runtime.lastError ? null : r || null)
    )
  );

const whoisRequest = (domain) =>
  new Promise((res) =>
    chrome.runtime.sendMessage(
      { action: "whois", domain, tabId: currentTab && currentTab.id },
      (r) => res(chrome.runtime.lastError ? null : r || null)
    )
  );

// Record an event into the diagnostic log from the popup side (e.g. cache hits
// that don't involve the background's network functions).
function logEvent(category, message, data) {
  try {
    chrome.runtime.sendMessage({
      action: "logEvent",
      tabId: currentTab && currentTab.id,
      category,
      message,
      data: data === undefined ? null : data,
    });
  } catch (e) {}
}

function currentHostname() {
  if (!currentTab || !currentTab.url) return null;
  try {
    return new URL(currentTab.url).hostname;
  } catch (e) {
    return null;
  }
}

// Merge DNS records from the hostname and root domain into one view per type,
// de-duplicating shared values and tagging which level a value came from when
// it appears at only one of them.
function renderDns(hostname, base, hostResults, baseResults) {
  if (!hostResults && !baseResults) {
    renderState(els.dnsBody, "lookup failed", "Could not reach the DNS resolver. Try again.");
    return;
  }

  const sameLevel = hostname === base;
  const types = NetworkTools.RECORD_TYPES;
  hostResults = hostResults || {};
  baseResults = baseResults || {};

  els.dnsBody.innerHTML = types
    .map(({ type, label }) => {
      const hostEntries = NetworkTools.parseAnswers(hostResults[type] || [], type);
      const baseEntries = sameLevel
        ? []
        : NetworkTools.parseAnswers(baseResults[type] || [], type);

      // Index by value to merge. Track which scope(s) each value came from.
      const byValue = new Map();
      hostEntries.forEach((e) => {
        byValue.set(e.value, { value: e.value, ttl: e.ttl, host: true, base: false });
      });
      baseEntries.forEach((e) => {
        if (byValue.has(e.value)) {
          byValue.get(e.value).base = true;
        } else {
          byValue.set(e.value, { value: e.value, ttl: e.ttl, host: false, base: true });
        }
      });

      const merged = Array.from(byValue.values());
      const isIpType = type === "A" || type === "AAAA";
      const values = merged.length
        ? merged
            .map((e) => {
              // Only show an origin tag when the value is exclusive to one level
              // (and the two levels actually differ).
              let tag = "";
              if (!sameLevel && !(e.host && e.base)) {
                const where = e.host ? "host" : "domain";
                tag = `<span class="dns-origin">${where}</span>`;
              }
              // For IP records, add a flag slot to be filled asynchronously.
              const flagSlot = isIpType
                ? `<span class="ip-flag-slot" data-ip="${escapeHtml(e.value)}"></span>`
                : "";
              return `<div class="dns-value">${escapeHtml(e.value)}${flagSlot}${
                e.ttl ? `<span class="dns-ttl">TTL ${e.ttl}</span>` : ""
              }${tag}</div>`;
            })
            .join("")
        : `<div class="dns-value none">no records</div>`;

      return `
        <div class="dns-group">
          <div class="dns-group-head">
            <span class="dns-type">${type}</span>
            <span class="dns-type-label">${escapeHtml(label)}</span>
          </div>
          <div class="dns-values">${values}</div>
        </div>`;
    })
    .join("");

  // Fill country flags for all IP records asynchronously (cached per IP).
  els.dnsBody.querySelectorAll(".ip-flag-slot[data-ip]").forEach((slot) => {
    const ip = slot.dataset.ip;
    flagFor(ip).then((flagHtml) => {
      if (flagHtml) slot.outerHTML = flagHtml;
    });
  });

  // Build the merged record set for BIND export (exportable types only),
  // de-duplicating values across host + root domain.
  const exportTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "CAA"];
  const byType = {};
  let total = 0;
  exportTypes.forEach((type) => {
    const seen = new Set();
    const merged = [];
    [hostResults, baseResults].forEach((res) => {
      NetworkTools.parseAnswers(res[type] || [], type).forEach((e) => {
        if (!seen.has(e.value)) {
          seen.add(e.value);
          merged.push(e);
        }
      });
    });
    if (merged.length) {
      byType[type] = merged;
      total += merged.length;
    }
  });

  if (total > 0) {
    currentDnsExport = { zone: base, byType };
    els.dnsExportBtn.hidden = false;
  } else {
    currentDnsExport = null;
    els.dnsExportBtn.hidden = true;
  }
}

function renderSubdomains(base, data) {
  if (!data || data.error) {
    renderState(els.subBody, "discovery failed",
      (data && data.error) || "Could not reach the Certificate Transparency log.");
    return;
  }
  const subs = NetworkTools.normalizeSubdomains(data.names || [], base);
  if (!subs.length) {
    renderState(els.subBody, "no subdomains found",
      "No certificates referencing subdomains of this domain were found in CT logs.");
    return;
  }
  const via = data.source ? ` (via ${escapeHtml(data.source)})` : "";
  els.subBody.innerHTML = `
    <div class="sub-summary"><span class="count">${subs.length}</span> subdomain${
    subs.length === 1 ? "" : "s"
  } found via Certificate Transparency${via}</div>
    <div class="sub-list">
      ${subs
        .map(
          (s) =>
            `<div class="sub-item">
              <span class="sub-name" data-copy="${escapeHtml(s)}" title="Click to copy">${escapeHtml(s)}</span>
              <span class="sub-actions">
                <button class="sub-act sub-open" data-host="${escapeHtml(s)}" title="Open in a new tab" aria-label="Open ${escapeHtml(s)}">↗</button>
              </span>
            </div>`
        )
        .join("")}
    </div>`;
}

async function runDnsLookup(forceRefresh = false) {
  const hostname = currentHostname();
  if (!hostname) {
    renderState(els.dnsBody, "no domain", "Open a website to look up its DNS records.");
    return;
  }
  const base = NetworkTools.baseDomain(hostname);
  const key = dnsCacheKey(hostname); // cache per exact hostname

  // Try cache first unless the user forced a refresh.
  if (!forceRefresh) {
    const cached = await cacheGet(key);
    if (cached) {
      logEvent("dns", `cache hit for ${hostname}`, { cached: true });
      renderDns(hostname, base, cached.hostResults, cached.baseResults);
      els.dnsBtn.textContent = "Refresh";
      return;
    }
  }

  els.dnsBtn.disabled = true;
  els.dnsBtn.textContent = "looking up…";
  renderState(els.dnsBody, "querying DNS…");

  const types = NetworkTools.RECORD_TYPES;
  let hostResults, baseResults;
  if (hostname === base) {
    hostResults = await dnsLookup(hostname, types);
  } else {
    [hostResults, baseResults] = await Promise.all([
      dnsLookup(hostname, types),
      dnsLookup(base, types),
    ]);
  }
  renderDns(hostname, base, hostResults, baseResults);
  await cacheSet(key, { hostResults, baseResults, savedAt: Date.now() });
  els.dnsBtn.disabled = false;
  els.dnsBtn.textContent = "Refresh";
}

async function runSubdomainLookup(forceRefresh = false) {
  const hostname = currentHostname();
  if (!hostname) {
    renderState(els.subBody, "no domain", "Open a website to discover its subdomains.");
    return;
  }
  const base = NetworkTools.baseDomain(hostname);
  const key = subCacheKey(base); // cache per registrable domain

  if (!forceRefresh) {
    const cached = await cacheGet(key);
    if (cached) {
      logEvent("subdomains", `cache hit for ${base}`, { cached: true });
      renderSubdomains(base, cached.data);
      els.subBtn.textContent = "Refresh";
      return;
    }
  }

  els.subBtn.disabled = true;
  els.subBtn.textContent = "searching…";
  renderState(els.subBody, `searching CT logs for ${base}…`,
    "This can take a few seconds.");
  const data = await subdomainLookup(base);
  renderSubdomains(base, data);
  // Only cache successful results (don't cache errors — let them retry).
  if (data && !data.error) {
    await cacheSet(key, { data, savedAt: Date.now() });
  }
  els.subBtn.disabled = false;
  els.subBtn.textContent = "Refresh";
}

els.dnsBtn.addEventListener("click", () => runDnsLookup(true));

els.dnsExportBtn.addEventListener("click", () => {
  if (!currentDnsExport) return;
  const { zone, byType } = currentDnsExport;
  const content = NetworkTools.buildZoneFile(zone, byType);
  const safeZone = zone.replace(/[^a-z0-9.-]/gi, "_");
  downloadFile(`${safeZone}.zone.txt`, content, "text/plain");
});
els.subBtn.addEventListener("click", () => runSubdomainLookup(true));

// --- WHOIS ---------------------------------------------------------------

// Format an ISO date string to a readable date, or return as-is on failure.
function fmtDate(v) {
  if (!v) return null;
  const d = new Date(v);
  if (isNaN(d.getTime())) return String(v);
  // Brazilian format DD/MM/YYYY. Use UTC parts to avoid timezone drift.
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const yyyy = d.getUTCFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

// Build a contact block from who-dat's contact shape:
// { name, organization, email, phone, address:{country,...}, redacted }
function contactRows(label, c) {
  if (!c) return "";
  const country = c.address && c.address.country;
  const parts = [];
  if (c.name) parts.push(["Name", c.name]);
  if (c.organization) parts.push(["Org", c.organization]);
  if (c.email) parts.push(["Email", c.email]);
  if (c.phone) parts.push(["Phone", c.phone]);
  if (country) parts.push(["Country", country]);

  if (!parts.length) {
    const why = c.redacted ? "redacted for privacy" : "not available";
    return `
      <div class="whois-group">
        <div class="whois-group-label">${escapeHtml(label)}</div>
        <div class="whois-redacted">${why}</div>
      </div>`;
  }
  return `
    <div class="whois-group">
      <div class="whois-group-label">${escapeHtml(label)}</div>
      ${parts
        .map(
          ([k, v]) =>
            `<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${escapeHtml(
              String(v)
            )}</span></div>`
        )
        .join("")}
    </div>`;
}

function renderWhois(data) {
  if (!data || data.error) {
    renderState(els.whoisBody, "lookup failed",
      (data && data.error) || "Could not reach the WHOIS service.");
    return;
  }

  if (data.isRegistered === false) {
    renderState(els.whoisBody, "not registered",
      "This domain appears to be unregistered or has no WHOIS record.");
    return;
  }

  const dates = data.dates || {};
  const registrar = data.registrar || {};
  const contacts = data.contacts || {};

  // Core registration facts. who-dat puts dates under data.dates, and the
  // registrar name is sometimes null — fall back to the whois/RDAP server.
  const created = fmtDate(dates.created);
  const updated = fmtDate(dates.updated);
  const expires = fmtDate(dates.expires);
  const registrarName =
    registrar.name || registrar.whoisServer ||
    (data.meta && data.meta.server) || null;

  const coreRows = [];
  if (data.domain) coreRows.push(["Domain", data.domain]);
  if (registrarName) coreRows.push(["Registrar", registrarName]);
  if (created) coreRows.push(["Created", created]);
  if (updated) coreRows.push(["Updated", updated]);
  if (expires) coreRows.push(["Expires", expires]);

  const coreHtml = coreRows.length
    ? coreRows
        .map(
          ([k, v]) =>
            `<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${escapeHtml(
              String(v)
            )}</span></div>`
        )
        .join("")
    : `<div class="whois-redacted">no registration data available</div>`;

  const status = data.status;
  const statusHtml = Array.isArray(status) && status.length
    ? `<div class="whois-group"><div class="whois-group-label">Status</div>${status
        .map((s) => `<div class="whois-status">${escapeHtml(String(s))}</div>`)
        .join("")}</div>`
    : "";

  // Source / freshness info (helps interpret the data).
  const src = data.meta && data.meta.source ? data.meta.source.toUpperCase() : null;
  const srcHtml = src
    ? `<div class="whois-note">Source: ${escapeHtml(src)}${
        registrar.whoisServer ? ` · ${escapeHtml(registrar.whoisServer)}` : ""
      }</div>`
    : "";

  els.whoisBody.innerHTML = `
    <div class="whois-group">
      <div class="whois-group-label">Registration</div>
      ${coreHtml}
    </div>
    ${statusHtml}
    ${contactRows("Registrant (owner)", contacts.registrant)}
    ${contactRows("Administrative contact", contacts.admin)}
    ${contactRows("Technical contact", contacts.tech)}
    ${contacts.billing ? contactRows("Billing contact", contacts.billing) : ""}
    ${srcHtml}
    <div class="whois-note">Some contact fields may be redacted by registrars under GDPR.</div>`;
}

async function runWhoisLookup(forceRefresh = false) {
  const hostname = currentHostname();
  if (!hostname) {
    renderState(els.whoisBody, "no domain", "Open a website to look up its WHOIS record.");
    return;
  }
  const base = NetworkTools.baseDomain(hostname);
  const key = whoisCacheKey(base);

  if (!forceRefresh) {
    const cached = await cacheGet(key);
    if (cached) {
      logEvent("whois", `cache hit for ${base}`, { cached: true });
      renderWhois(cached.data);
      els.whoisBtn.textContent = "Refresh";
      return;
    }
  }

  els.whoisBtn.disabled = true;
  els.whoisBtn.textContent = "looking up…";
  renderState(els.whoisBody, `querying WHOIS for ${base}…`, "This can take a few seconds.");
  const data = await whoisRequest(base);
  renderWhois(data);
  if (data && !data.error) {
    await cacheSet(key, { data, savedAt: Date.now() });
  }
  els.whoisBtn.disabled = false;
  els.whoisBtn.textContent = "Refresh";
}

els.whoisBtn.addEventListener("click", () => runWhoisLookup(true));

// Subdomain action: open in a new browser tab. (The name itself is copied
// via the generic click-to-copy handler below.)
els.subBody.addEventListener("click", (e) => {
  const openBtn = e.target.closest(".sub-open");
  if (openBtn) {
    const host = openBtn.dataset.host;
    if (host) chrome.tabs.create({ url: `https://${host}` });
  }
});

// Click-to-copy for value items across all tabs. We listen on the body and
// match known value containers.
const COPY_SELECTORS = [
  ".kv-val:not(.empty)", // Stack: IP, Server, Powered-By, Status; WHOIS contact values
  ".dns-value:not(.none)", // Network: DNS record values
  ".layer-name", // Stack: detected tech names
  ".wp-chip", // Stack: WordPress themes/plugins
  ".whois-status", // WHOIS: status codes
  ".sub-name", // Network: subdomain names
  ".header-value", // Headers: configured/misconfigured header values
];

document.body.addEventListener("click", (e) => {
  // Don't hijack clicks on interactive sub-elements.
  if (e.target.closest(".layer-help, .sub-actions, button, a, input")) return;

  for (const sel of COPY_SELECTORS) {
    const el = e.target.closest(sel);
    if (el && document.body.contains(el)) {
      const value = copyValueOf(el);
      if (value) copyToClipboard(value, el);
      return;
    }
  }
});

// --- Floating evidence tooltip (triggered by the ? icon) -----------------
// The tooltip is anchored to the help icon, not the whole row, so it only
// appears when the user hovers/focuses the ? button. position:fixed lets it
// escape the panels' overflow:hidden.

function positionTip(helpBtn) {
  // Works for both Stack rows (.layer) and Headers rows (.header-row).
  const layer = helpBtn.closest(".layer, .header-row");
  const tip = layer && layer.querySelector(".evidence-tip");
  if (!tip) return;

  // Hide any other open tooltip first (only one at a time, anywhere).
  document.querySelectorAll(".evidence-tip.show").forEach((t) => {
    if (t !== tip) t.classList.remove("show");
  });

  tip.style.visibility = "hidden";
  tip.classList.add("show");

  const anchor = helpBtn.getBoundingClientRect();
  const tipRect = tip.getBoundingClientRect();
  const margin = 8;
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  // Horizontal: right-align the tooltip to the icon, clamp into viewport.
  let left = anchor.right - tipRect.width;
  if (left + tipRect.width > vw - margin) left = vw - margin - tipRect.width;
  if (left < margin) left = margin;

  // Vertical: prefer ABOVE the icon; go below only if there's more room there.
  const spaceAbove = anchor.top - margin;
  const spaceBelow = vh - anchor.bottom - margin;
  let top;

  if (tipRect.height <= spaceAbove) {
    top = anchor.top - tipRect.height - 6;
  } else if (spaceBelow > spaceAbove) {
    top = anchor.bottom + 6;
  } else {
    top = Math.max(margin, anchor.top - tipRect.height - 6);
  }

  // Final safety clamp so it never leaves the viewport.
  if (top < margin) top = margin;
  if (top + tipRect.height > vh - margin) top = vh - margin - tipRect.height;

  tip.style.left = `${Math.round(left)}px`;
  tip.style.top = `${Math.round(top)}px`;
  tip.style.visibility = "";
}

function hideTipFor(helpBtn) {
  const layer = helpBtn.closest(".layer, .header-row");
  const tip = layer && layer.querySelector(".evidence-tip");
  if (tip) tip.classList.remove("show");
}

// Delegate tooltip triggers from a body; only the ? icon triggers it.
function wireTooltips(body) {
  body.addEventListener("mouseover", (e) => {
    const help = e.target.closest(".layer-help");
    if (help) positionTip(help);
  });
  body.addEventListener("mouseout", (e) => {
    const help = e.target.closest(".layer-help");
    if (help && e.relatedTarget !== help) hideTipFor(help);
  });
  body.addEventListener("focusin", (e) => {
    const help = e.target.closest(".layer-help");
    if (help) positionTip(help);
  });
  body.addEventListener("focusout", (e) => {
    const help = e.target.closest(".layer-help");
    if (help) hideTipFor(help);
  });
}

wireTooltips(els.techBody);
wireTooltips(els.headersBody);

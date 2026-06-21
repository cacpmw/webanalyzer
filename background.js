// background.js
// Captures HTTP response data (headers, IP, status) for the main document
// of each tab. In Manifest V3 the background is a service worker that can be
// terminated after ~30s idle, which would wipe in-memory state. So we persist
// captured data in chrome.storage.session (survives worker restarts, cleared
// when the browser closes). Also resolves IP via DNS-over-HTTPS as a fallback.

importScripts("logger.js");

const KEY = (tabId) => `tab_${tabId}`;

// True when the string looks like an IPv6 address (contains colons).
function isIpv6(ip) {
  return typeof ip === "string" && ip.includes(":");
}

async function getTab(tabId) {
  try {
    const r = await chrome.storage.session.get(KEY(tabId));
    return r[KEY(tabId)] || {};
  } catch (e) {
    return {};
  }
}

async function setTab(tabId, data) {
  try {
    await chrome.storage.session.set({ [KEY(tabId)]: data });
  } catch (e) {}
}

// onResponseStarted gives a more reliable `ip` than onHeadersReceived.
chrome.webRequest.onResponseStarted.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    const prev = await getTab(details.tabId);
    await setTab(details.tabId, {
      ...prev,
      url: details.url,
      ip: details.ip || prev.ip || null,
      fromCache: details.fromCache || false,
      statusCode: details.statusCode,
    });
  },
  { urls: ["<all_urls>"] }
);

// Headers come from onHeadersReceived.
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    const headers = {};
    (details.responseHeaders || []).forEach((h) => {
      const name = h.name.toLowerCase();
      if (headers[name]) headers[name] += "; " + h.value;
      else headers[name] = h.value;
    });
    const prev = await getTab(details.tabId);
    await setTab(details.tabId, {
      ...prev,
      url: details.url,
      ip: details.ip || prev.ip || null,
      statusCode: details.statusCode,
      headers,
      capturedAt: Date.now(),
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Clean up when a tab closes.
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(KEY(tabId)).catch(() => {});
});

// DNS-over-HTTPS lookup (Cloudflare, with Google as fallback).
// Always requests A records (IPv4).
async function resolveIp(hostname) {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
  ];
  for (const url of endpoints) {
    try {
      const resp = await fetch(url, { headers: { accept: "application/dns-json" } });
      if (!resp.ok) continue;
      const data = await resp.json();
      const answer = (data.Answer || []).find((a) => a.type === 1); // A record
      if (answer && answer.data) return answer.data;
    } catch (e) {}
  }
  return null;
}

// Fallback: fetch the page URL ourselves to read response headers, used when
// the worker missed the original request (e.g. page predated the extension,
// or the worker was asleep). Note: fetch() exposes a limited set of headers
// for cross-origin responses, but Server/Status are usually available.
async function fetchHeaders(url) {
  try {
    const resp = await fetch(url, { method: "GET", credentials: "omit", cache: "no-store" });
    const headers = {};
    resp.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    return {
      url,
      statusCode: resp.status,
      headers,
      ip: null,
      fromCache: false,
      viaFetch: true,
    };
  } catch (e) {
    return null;
  }
}

// Query a single DNS record type via DNS-over-HTTPS. Returns the raw Answer
// array (or empty). Tries Cloudflare then Google.
async function dnsQuery(hostname, type) {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`,
  ];
  for (const url of endpoints) {
    try {
      const resp = await fetch(url, { headers: { accept: "application/dns-json" } });
      if (!resp.ok) continue;
      const data = await resp.json();
      return data.Answer || [];
    } catch (e) {}
  }
  return [];
}

// Look up all requested record types in parallel.
// `types` is an array of { type, code }.
async function dnsLookupAll(hostname, types) {
  const results = {};
  await Promise.all(
    types.map(async ({ type }) => {
      results[type] = await dnsQuery(hostname, type);
    })
  );
  return results;
}

// Sleep helper for retry backoff.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// crt.sh source — with retries for its frequent 502/503 hiccups. Each attempt
// is logged with its HTTP status so a "0 subdomains" caused by repeated 503s is
// distinguishable from a domain that genuinely has none.
async function fromCrtSh(baseDomain, tabId, attempts = 3) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(baseDomain)}&output=json`;
  for (let i = 0; i < attempts; i++) {
    try {
      const resp = await fetch(url, { headers: { accept: "application/json" } });
      if (resp.ok) {
        const data = await resp.json();
        const names = [];
        (Array.isArray(data) ? data : []).forEach((entry) => {
          const field = entry.name_value || entry.common_name || "";
          String(field).split(/\n/).forEach((n) => names.push(n.trim()));
        });
        await Logger.append(tabId, "subdomains", `crt.sh attempt ${i + 1}/${attempts} → 200 (${names.length} names)`, null);
        return { names, source: "crt.sh" };
      }
      await Logger.append(tabId, "subdomains", `crt.sh attempt ${i + 1}/${attempts} → ${resp.status}`, null);
      // 502/503/504 → transient; wait and retry.
      if ([502, 503, 504].includes(resp.status) && i < attempts - 1) {
        await sleep(700 * (i + 1));
        continue;
      }
      return { error: `crt.sh returned ${resp.status}`, names: [] };
    } catch (e) {
      await Logger.append(tabId, "subdomains", `crt.sh attempt ${i + 1}/${attempts} → network error`, e.message);
      if (i < attempts - 1) {
        await sleep(700 * (i + 1));
        continue;
      }
      return { error: "Could not reach crt.sh", names: [] };
    }
  }
  return { error: "crt.sh unavailable", names: [] };
}

// Fallback source — Cert Spotter (also Certificate Transparency based).
async function fromCertSpotter(baseDomain, tabId) {
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(
    baseDomain
  )}&include_subdomains=true&expand=dns_names`;
  try {
    const resp = await fetch(url, { headers: { accept: "application/json" } });
    if (!resp.ok) {
      await Logger.append(tabId, "subdomains", `certspotter → ${resp.status}`, null);
      return { error: `certspotter returned ${resp.status}`, names: [] };
    }
    const data = await resp.json();
    const names = [];
    (Array.isArray(data) ? data : []).forEach((entry) => {
      (entry.dns_names || []).forEach((n) => names.push(String(n).trim()));
    });
    await Logger.append(tabId, "subdomains", `certspotter → 200 (${names.length} names)`, null);
    return { names, source: "certspotter" };
  } catch (e) {
    await Logger.append(tabId, "subdomains", `certspotter → network error`, e.message);
    return { error: "Could not reach certspotter", names: [] };
  }
}

// Passive subdomain discovery via Certificate Transparency.
// Tries crt.sh (with retries); if it yields nothing usable, falls back to
// Cert Spotter. Neither touches the target's own servers.
async function subdomainsViaCT(baseDomain, tabId) {
  const primary = await fromCrtSh(baseDomain, tabId);
  if (primary.names && primary.names.length) return primary;

  // crt.sh failed or returned empty — log the transition and try the fallback.
  await Logger.append(tabId, "subdomains", `crt.sh empty/failed (${primary.error || "0 names"}), trying certspotter`, null);
  const fallback = await fromCertSpotter(baseDomain, tabId);
  if (fallback.names && fallback.names.length) return fallback;

  // Both failed — surface the most informative error.
  return primary.error ? primary : fallback;
}

// WHOIS / RDAP lookup via who-dat (free, no-CORS, no-auth public instance).
// RDAP-first with WHOIS fallback, returns normalized JSON. Note: post-GDPR,
// most personal contact fields are redacted by the registrar.
async function whoisLookup(domain, tabId) {
  const url = `https://who-dat.as93.net/v1/whois/${encodeURIComponent(domain)}`;
  try {
    const r = await fetch(url, { headers: { accept: "application/json" } });
    const d = await r.json().catch(() => null);
    // Log the full normalized response so the parsing can be audited from the
    // downloaded log (field names vary between registries).
    await Logger.append(tabId, "whois", `who-dat ${domain} [${r.status}]`, d);
    if (!r.ok || !d) {
      const msg = (d && d.error && d.error.message) || `lookup failed (${r.status})`;
      await Logger.append(tabId, "whois", `who-dat ${domain} parsed [${r.status}] → error: ${msg}`, null);
      return { error: msg };
    }
    // Parsing outcome: count usable field groups so a "200 but nothing
    // extracted" is visible in the log, distinct from a transport error.
    const reg = d.registrar || {}, dt = d.dates || {}, ct = d.contacts || {};
    const usable =
      (d.domain ? 1 : 0) +
      (reg.name || reg.whoisServer ? 1 : 0) +
      (dt.created || dt.updated || dt.expires ? 1 : 0) +
      (ct.registrant || ct.admin || ct.tech || ct.billing ? 1 : 0);
    await Logger.append(tabId, "whois", `who-dat ${domain} parsed [${r.status}] → ${usable} usable field group(s)`, null);
    return d;
  } catch (e) {
    await Logger.append(tabId, "whois", `who-dat ${domain} error`, e.message);
    return { error: "Could not reach the WHOIS service." };
  }
}

// IP geolocation with permanent per-IP caching in storage.local. Public IP ->
// country allocation is stable, so caching forever is safe. Returns
// {cc, country} where cc is the ISO 3166-1 alpha-2 code (e.g. "BR").
// Tries multiple providers since free geo services vary in availability.
async function geoLookup(ip, tabId) {
  if (!ip) return null;
  const key = `geocache:${ip}`;
  try {
    const cached = await chrome.storage.local.get(key);
    if (cached[key]) {
      await Logger.append(tabId, "geo", `cache hit for ${ip}`, cached[key]);
      return cached[key];
    }
  } catch (e) {}

  const providers = [
    // freeipapi.com — free, HTTPS, CORS-enabled, no key, commercial use OK.
    // Returns countryName + countryCode (ISO alpha-2). 60 req/min.
    async () => {
      const r = await fetch(`https://free.freeipapi.com/api/json/${encodeURIComponent(ip)}`);
      const d = await r.json().catch(() => null);
      await Logger.append(tabId, "geo", `freeipapi ${ip} [${r.status}]`, d);
      if (d && d.countryCode) {
        return { cc: d.countryCode, country: d.countryName || d.countryCode };
      }
      return null;
    },
    // ipwho.is — fallback (note: free plan now blocks CORS, kept just in case).
    async () => {
      const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
      const d = await r.json().catch(() => null);
      await Logger.append(tabId, "geo", `ipwho.is ${ip} [${r.status}]`, d);
      if (d && d.success !== false && (d.country_code || d.country)) {
        return { cc: d.country_code || "", country: d.country || d.country_code };
      }
      return null;
    },
    // country.is — minimal fallback; returns just the country code.
    async () => {
      const r = await fetch(`https://api.country.is/${encodeURIComponent(ip)}`);
      const d = await r.json().catch(() => null);
      await Logger.append(tabId, "geo", `country.is ${ip} [${r.status}]`, d);
      if (d && d.country) {
        return { cc: d.country, country: d.country };
      }
      return null;
    },
  ];

  for (const provider of providers) {
    try {
      const result = await provider();
      if (result && result.cc) {
        try {
          await chrome.storage.local.set({ [key]: result });
        } catch (e) {}
        return result;
      }
    } catch (e) {
      await Logger.append(tabId, "geo", `provider error for ${ip}`, e.message);
    }
  }
  await Logger.append(tabId, "geo", `ALL PROVIDERS FAILED for ${ip}`, null);
  return null;
}

// Sends the analysis payload to the user's n8n webhook and returns its report.
// Kept self-contained (only Logger.append + fetch) so it can be unit-tested in
// isolation from the chrome.* surface around it.
async function sendToN8n(payload, webhookUrl, authToken, tabId) {
  if (!webhookUrl || typeof webhookUrl !== "string") {
    return { ok: false, error: "missing_webhook_url" };
  }

  const headers = { "Content-Type": "application/json" };
  if (authToken && typeof authToken === "string") {
    headers["X-Auth-Token"] = authToken;
  }

  try {
    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      credentials: "omit",
      cache: "no-store",
    });

    if (!resp.ok) {
      await Logger.append(tabId, "ai", `n8n → ${resp.status}`, null);
      return { ok: false, error: "http_error", status: resp.status };
    }

    // The workflow may return JSON or a bare formatted string; fall back to the
    // raw body so a non-JSON report still reaches the caller.
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      data = { report: await resp.text() };
    }

    await Logger.append(tabId, "ai", `n8n → 200`, null);
    return { ok: true, data };
  } catch (e) {
    await Logger.append(tabId, "ai", "n8n → network error", e.message);
    return { ok: false, error: "network_error", message: e.message };
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getHeaders") {
    getTab(request.tabId).then(async (data) => {
      if (data && data.headers) {
        await Logger.append(request.tabId, "headers", "captured from webRequest", {
          ip: data.ip, statusCode: data.statusCode, server: data.headers.server || null,
        });
        sendResponse(data);
      } else if (request.url) {
        const fetched = await fetchHeaders(request.url);
        await Logger.append(request.tabId, "headers", "fallback fetch", fetched ? {
          ip: fetched.ip, statusCode: fetched.statusCode,
        } : "fetch failed");
        sendResponse(fetched || (Object.keys(data).length ? data : null));
      } else {
        sendResponse(Object.keys(data).length ? data : null);
      }
    });
    return true;
  }
  if (request.action === "resolveIp") {
    resolveIp(request.hostname).then(async (ip) => {
      await Logger.append(request.tabId, "dns", `resolveIp ${request.hostname}`, ip);
      sendResponse({ ip });
    });
    return true;
  }
  if (request.action === "dnsLookup") {
    dnsLookupAll(request.hostname, request.types).then(async (r) => {
      const counts = {};
      Object.keys(r).forEach((t) => (counts[t] = (r[t] || []).length));
      await Logger.append(request.tabId, "dns", `lookup ${request.hostname}`, counts);
      sendResponse(r);
    });
    return true;
  }
  if (request.action === "subdomains") {
    subdomainsViaCT(request.baseDomain, request.tabId).then(async (r) => {
      await Logger.append(request.tabId, "subdomains", `discover ${request.baseDomain}`, {
        count: (r.names || []).length, source: r.source || null, error: r.error || null,
      });
      sendResponse(r);
    });
    return true;
  }
  if (request.action === "geoLookup") {
    geoLookup(request.ip, request.tabId).then((r) => sendResponse(r));
    return true;
  }
  if (request.action === "whois") {
    whoisLookup(request.domain, request.tabId).then((r) => sendResponse(r));
    return true;
  }
  if (request.action === "getLog") {
    Logger.get(request.tabId).then((entries) => sendResponse({ entries }));
    return true;
  }
  if (request.action === "clearLog") {
    Logger.clear(request.tabId).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.action === "logEvent") {
    // Lets the popup record its own events (e.g. cache hits) into the log.
    Logger.append(request.tabId, request.category, request.message, request.data)
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.action === "aiReport") {
    sendToN8n(request.payload, request.webhookUrl, request.authToken, request.tabId)
      .then((result) => sendResponse(result));
    return true;
  }
  return false;
});

// Exposed for unit tests; harmless in the service worker (module is undefined).
if (typeof module !== "undefined" && module.exports) {
  module.exports = { sendToN8n };
}

// content.js
// Reads page-level signals for tech detection. Passive by default: only
// reads what the page already delivered. The optional deep scan (triggered
// explicitly from the popup) makes a few extra requests to probe common
// WordPress paths — never automatically.

function collectPageSignals() {
  const signals = {
    url: location.href,
    hostname: location.hostname,
    html: "",
    scripts: [],
    stylesheets: [],
    meta: {},
    globals: [],
    cookies: [],
    generator: null,
    wordpress: { themes: [], plugins: [] },
  };

  let html = "";
  try {
    html = document.documentElement.outerHTML;
  } catch (e) {
    html = "";
  }
  signals.html = html.slice(0, 800000);

  document.querySelectorAll("script[src]").forEach((s) => {
    if (s.src) signals.scripts.push(s.src);
  });
  document.querySelectorAll('link[rel="stylesheet"][href]').forEach((l) => {
    if (l.href) signals.stylesheets.push(l.href);
  });
  // Also catch <link> for preconnect/dns hints and any href with wp-content.
  document.querySelectorAll("link[href]").forEach((l) => {
    if (l.href && /wp-content/i.test(l.href)) signals.stylesheets.push(l.href);
  });

  document.querySelectorAll("meta").forEach((m) => {
    const key = m.getAttribute("name") || m.getAttribute("property");
    const content = m.getAttribute("content");
    if (key && content) {
      signals.meta[key.toLowerCase()] = content;
      if (key.toLowerCase() === "generator") signals.generator = content;
    }
  });

  const knownGlobals = [
    "React", "ReactDOM", "Vue", "angular", "ng",
    "jQuery", "$", "__NEXT_DATA__", "__NUXT__", "__remixContext",
    "Shopify", "wp", "Drupal", "Joomla", "Stripe", "gtag", "dataLayer",
    "Alpine", "Svelte", "elementorFrontend", "wc", "woocommerce_params",
  ];
  knownGlobals.forEach((name) => {
    try {
      if (typeof window[name] !== "undefined") signals.globals.push(name);
    } catch (e) {}
  });

  try {
    signals.cookies = document.cookie
      .split(";")
      .map((c) => c.trim().split("=")[0])
      .filter(Boolean);
  } catch (e) {
    signals.cookies = [];
  }

  // --- WordPress theme & plugin extraction from the HTML (passive) ---
  // Themes live under /wp-content/themes/NAME/ and plugins under
  // /wp-content/plugins/NAME/. We scan all asset URLs in the markup.
  const allUrls = [...signals.scripts, ...signals.stylesheets];
  // Also sweep the raw HTML for any wp-content references we might have missed.
  const wpRefRegex = /wp-content\/(themes|plugins)\/([a-z0-9_-]+)/gi;
  let match;
  while ((match = wpRefRegex.exec(html)) !== null) {
    const kind = match[1].toLowerCase();
    const name = match[2];
    const bucket = kind === "themes" ? signals.wordpress.themes : signals.wordpress.plugins;
    if (!bucket.includes(name)) bucket.push(name);
  }
  allUrls.forEach((u) => {
    const m = /wp-content\/(themes|plugins)\/([a-z0-9_-]+)/i.exec(u);
    if (m) {
      const bucket = m[1].toLowerCase() === "themes"
        ? signals.wordpress.themes : signals.wordpress.plugins;
      if (!bucket.includes(m[2])) bucket.push(m[2]);
    }
  });

  return signals;
}

// Deep scan: probe a small, fixed set of common WordPress endpoints.
// Only runs when the popup explicitly requests it. Capped and fail-soft.
async function deepScan() {
  const origin = location.origin;
  const result = { restApi: false, restPlugins: [], probedThemes: [], readme: null };

  // 1. WP REST API — confirms WordPress and may list active plugins.
  try {
    const r = await fetch(`${origin}/wp-json/`, { method: "GET" });
    if (r.ok) {
      result.restApi = true;
      const data = await r.json();
      // Some sites expose plugin info via namespaces.
      if (data && data.namespaces) {
        result.restPlugins = data.namespaces.filter(
          (ns) => ns !== "wp/v2" && ns !== "oembed/1.0"
        );
      }
    }
  } catch (e) {}

  // 2. readme.html — often reveals the WordPress version.
  try {
    const r = await fetch(`${origin}/readme.html`, { method: "GET" });
    if (r.ok) {
      const text = await r.text();
      const vm = /Version\s+([\d.]+)/i.exec(text);
      if (vm) result.readme = vm[1];
    }
  } catch (e) {}

  return result;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getPageSignals") {
    sendResponse(collectPageSignals());
    return false;
  }
  if (request.action === "deepScan") {
    deepScan().then((res) => sendResponse(res));
    return true; // async
  }
  return false;
});

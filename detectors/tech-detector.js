// tech-detector.js
// Pure detection logic: given page signals (DOM) + response headers,
// returns detected technologies with category, confidence and version.
//
// No DOM access here — this module is given everything it needs as data,
// which keeps it testable and lets it run inside the popup context.

const TechDetector = (() => {
  // Signature database. Each tech can match on:
  //   headers  -> { 'header-name': /regex/ }   (lowercased header names)
  //   html     -> [ /regex/, ... ]             (tested against page HTML)
  //   scripts  -> [ /regex/, ... ]             (tested against each script src)
  //   meta     -> { metaKey: /regex/ }         (lowercased meta keys)
  //   globals  -> [ 'WindowName', ... ]        (window globals present)
  //   cookies  -> [ /regex/, ... ]             (cookie names)
  //   implies  -> [ 'OtherTech', ... ]         (added if this one matches)
  //   version  -> { from: 'meta'|'header'|'html'|'script', re: /(\d[\d.]*)/ }
  //              first capture group is taken as the version string
  const SIGNATURES = {
    // --- CMS ---
    WordPress: {
      category: "CMS",
      html: [/wp-content\//i, /wp-includes\//i, /<link[^>]+wp-json/i],
      meta: { generator: /wordpress/i },
      globals: ["wp"],
      implies: ["PHP", "MySQL"],
      version: { from: "meta", key: "generator", re: /wordpress\s+([\d.]+)/i },
    },
    Drupal: {
      category: "CMS",
      html: [/sites\/(default|all)\//i, /drupal-settings-json/i],
      meta: { generator: /drupal/i },
      globals: ["Drupal"],
      implies: ["PHP"],
      version: { from: "meta", key: "generator", re: /drupal\s+([\d.]+)/i },
    },
    Joomla: {
      category: "CMS",
      html: [/\/media\/jui\//i, /option=com_/i],
      meta: { generator: /joomla/i },
      globals: ["Joomla"],
      implies: ["PHP"],
      version: { from: "meta", key: "generator", re: /joomla!?\s+([\d.]+)/i },
    },
    Ghost: {
      category: "CMS",
      html: [/ghost-/i, /content\/images\//i],
      meta: { generator: /ghost/i },
      version: { from: "meta", key: "generator", re: /ghost\s+([\d.]+)/i },
    },
    Squarespace: {
      category: "CMS",
      html: [/static\.squarespace\.com/i, /squarespace-cdn/i],
    },
    Wix: {
      category: "CMS",
      html: [/static\.wixstatic\.com/i, /wix-warmup-data/i],
      headers: { "x-wix-request-id": /.*/ },
    },
    Webflow: {
      category: "CMS",
      html: [/assets\.website-files\.com/i, /data-wf-page/i],
      meta: { generator: /webflow/i },
    },

    // --- Ecommerce ---
    Shopify: {
      category: "Ecommerce",
      html: [/cdn\.shopify\.com/i, /shopify\.shop/i],
      headers: { "x-shopify-stage": /.*/, "x-shopid": /.*/ },
      globals: ["Shopify"],
    },
    Magento: {
      category: "Ecommerce",
      html: [/\/static\/version\d+/i, /mage\/cookies/i, /magento/i],
      implies: ["PHP"],
    },
    WooCommerce: {
      category: "Ecommerce",
      html: [/woocommerce/i, /wc-block/i],
      globals: ["wc", "woocommerce_params"],
      implies: ["WordPress"],
    },
    PrestaShop: {
      category: "Ecommerce",
      html: [/prestashop/i],
      meta: { generator: /prestashop/i },
      implies: ["PHP"],
    },
    BigCommerce: {
      category: "Ecommerce",
      html: [/cdn\d*\.bigcommerce\.com/i],
    },

    // --- JS Frameworks ---
    React: {
      category: "JS Framework",
      html: [/data-reactroot/i, /_reactlistening/i, /react-dom/i],
      scripts: [/react(\.production|\.development)?(\.min)?\.js/i],
      globals: ["React", "ReactDOM"],
    },
    "Next.js": {
      category: "JS Framework",
      html: [/id="__next"/i],
      scripts: [/\/_next\//i],
      globals: ["__NEXT_DATA__"],
      implies: ["React", "Node.js"],
    },
    "Vue.js": {
      category: "JS Framework",
      html: [/data-v-[0-9a-f]{8}/i, /id="app"[^>]+data-server-rendered/i],
      scripts: [/vue(\.runtime)?(\.min)?\.js/i],
      globals: ["Vue"],
    },
    "Nuxt.js": {
      category: "JS Framework",
      scripts: [/\/_nuxt\//i],
      globals: ["__NUXT__"],
      implies: ["Vue.js", "Node.js"],
    },
    Angular: {
      category: "JS Framework",
      html: [/ng-version="([\d.]+)"/i, /\sng-app/i],
      globals: ["angular", "ng"],
      version: { from: "html", re: /ng-version="([\d.]+)"/i },
    },
    Svelte: {
      category: "JS Framework",
      html: [/svelte-[0-9a-z]+/i],
      globals: ["Svelte"],
    },
    Gatsby: {
      category: "JS Framework",
      html: [/id="___gatsby"/i],
      scripts: [/\/page-data\//i],
      implies: ["React"],
    },
    Remix: {
      category: "JS Framework",
      globals: ["__remixContext"],
      implies: ["React"],
    },
    "Alpine.js": {
      category: "JS Framework",
      html: [/\sx-data[=\s>]/i],
      globals: ["Alpine"],
    },

    // --- JS Libraries ---
    jQuery: {
      category: "JS Library",
      scripts: [/jquery[-.]?[\d.]*(\.min)?\.js/i],
      globals: ["jQuery"],
      version: {
        from: "script",
        re: [
          /jquery[-.]?([\d.]+)(\.min)?\.js/i, // version in the filename
          /jquery(?:\.min)?\.js\?[^"']*\bver=([\d.]+)/i, // WordPress-style ?ver=
        ],
      },
    },
    "Lodash": {
      category: "JS Library",
      scripts: [/lodash(\.min)?\.js/i],
    },
    "Font Awesome": {
      category: "Font Script",
      html: [/font-?awesome/i, /fa-[a-z]+/i],
    },
    "Google Fonts": {
      category: "Font Script",
      html: [/fonts\.googleapis\.com/i, /fonts\.gstatic\.com/i],
    },

    // --- CSS Frameworks ---
    Bootstrap: {
      category: "CSS Framework",
      html: [/class="[^"]*\b(col-(xs|sm|md|lg|xl)-\d+|navbar-toggler)\b/i],
      scripts: [/bootstrap(\.bundle)?(\.min)?\.js/i],
    },
    "Tailwind CSS": {
      category: "CSS Framework",
      // Match only Tailwind-distinctive class tokens, and require each token to
      // START a class (negative lookbehind for word-char/hyphen) so themed
      // prefixes like "wpex-flex" or "wpex-py-30" don't false-positive. Bare
      // flex/grid and shared spacing scales (px-4, mt-5 — also Bootstrap) are
      // intentionally excluded; we key off variant prefixes (md:, hover:),
      // numbered color scales (bg-blue-500), text sizes and grid-cols-N.
      html: [/class="[^"]*(?<![-\w])(?:(?:sm|md|lg|xl|2xl|hover|focus|active|disabled|dark|group-hover):[a-z][\w-]+|(?:bg|text|border|ring|fill|stroke|from|via|to|divide|shadow|accent|decoration|outline)-(?:gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}|text-(?:xs|sm|base|lg|xl|[2-9]xl)(?![\w-])|grid-cols-\d{1,2})/i],
    },
    Elementor: {
      category: "Page Builder",
      html: [/elementor-(widget|section|element)/i, /\/uploads\/elementor\//i],
      globals: ["elementorFrontend"],
      implies: ["WordPress"],
      // WordPress stamps the plugin version onto its enqueued assets' ?ver=.
      // Require the core "elementor/assets" path so elementor-pro (own version)
      // isn't picked up.
      version: { from: "html", re: /plugins\/elementor\/assets\/[^"']*?[?&]ver=([\d.]+)/i },
    },

    // --- Web Servers (from headers) ---
    Nginx: {
      category: "Web Server",
      headers: { server: /nginx/i },
      version: { from: "header", key: "server", re: /nginx\/?([\d.]+)?/i },
    },
    Apache: {
      category: "Web Server",
      headers: { server: /apache/i },
      version: { from: "header", key: "server", re: /apache\/?([\d.]+)?/i },
    },
    "Microsoft IIS": {
      category: "Web Server",
      headers: { server: /microsoft-iis/i },
      implies: ["ASP.NET"],
      version: { from: "header", key: "server", re: /microsoft-iis\/?([\d.]+)?/i },
    },
    LiteSpeed: {
      category: "Web Server",
      headers: { server: /litespeed/i },
    },
    Caddy: { category: "Web Server", headers: { server: /caddy/i } },
    OpenResty: {
      category: "Web Server",
      headers: { server: /openresty/i },
    },

    // --- Languages / Backend (from headers + cookies) ---
    PHP: {
      category: "Language",
      headers: { "x-powered-by": /php/i },
      cookies: [/^phpsessid$/i],
      version: { from: "header", key: "x-powered-by", re: /php\/?([\d.]+)?/i },
    },
    "ASP.NET": {
      category: "Framework",
      headers: { "x-powered-by": /asp\.net/i, "x-aspnet-version": /.*/ },
      cookies: [/^asp\.net_sessionid$/i],
      version: { from: "header", key: "x-aspnet-version", re: /([\d.]+)/ },
    },
    "Node.js": {
      category: "Language",
      headers: { "x-powered-by": /express/i },
    },
    "Express.js": {
      category: "Framework",
      headers: { "x-powered-by": /express/i },
      implies: ["Node.js"],
    },
    "Ruby on Rails": {
      category: "Framework",
      headers: { "x-powered-by": /phusion passenger/i, server: /passenger/i },
      cookies: [/_session_id$/i],
    },
    Java: {
      category: "Language",
      cookies: [/^jsessionid$/i],
    },
    Laravel: {
      category: "Framework",
      cookies: [/^laravel_session$/i, /^xsrf-token$/i],
      implies: ["PHP"],
    },

    // --- Databases (matched only via implication today; listed so they
    //     inherit the right category instead of falling back to Unknown) ---
    MySQL: { category: "Database" },
    PostgreSQL: { category: "Database" },

    // --- CDN / Cloud / Proxy / Security (from headers) ---
    Cloudflare: {
      category: "CDN",
      headers: {
        server: /cloudflare/i,
        "cf-ray": /.*/,
        "cf-cache-status": /.*/,
      },
    },
    "Amazon CloudFront": {
      category: "CDN",
      headers: { "x-amz-cf-id": /.*/, via: /cloudfront/i },
    },
    Fastly: {
      category: "CDN",
      headers: { "x-served-by": /cache-/i, "x-fastly-request-id": /.*/ },
    },
    Akamai: {
      category: "CDN",
      headers: { "x-akamai-transformed": /.*/, server: /akamai/i },
    },
    Sucuri: {
      category: "Security",
      headers: { "x-sucuri-id": /.*/, server: /sucuri/i },
    },
    Vercel: {
      category: "Hosting",
      headers: { server: /vercel/i, "x-vercel-id": /.*/ },
    },
    Netlify: {
      category: "Hosting",
      headers: { server: /netlify/i, "x-nf-request-id": /.*/ },
    },
    "Amazon S3": {
      category: "Hosting",
      headers: { server: /amazons3/i, "x-amz-request-id": /.*/ },
    },
    "GitHub Pages": {
      category: "Hosting",
      headers: { server: /github\.com/i },
    },

    // --- Analytics / Tags ---
    "Google Tag Manager": {
      category: "Tag Manager",
      html: [/googletagmanager\.com\/gtm\.js/i],
      globals: ["dataLayer"],
    },
    "Google Analytics": {
      category: "Analytics",
      html: [/google-analytics\.com\/(analytics|ga)\.js/i, /gtag\/js\?id=G-/i],
      globals: ["gtag"],
    },
    "Facebook Pixel": {
      category: "Analytics",
      html: [/connect\.facebook\.net\/[^/]+\/fbevents\.js/i],
    },
    Hotjar: {
      category: "Analytics",
      html: [/static\.hotjar\.com/i, /hotjar-/i],
    },

    // --- Payments ---
    Stripe: {
      category: "Payments",
      scripts: [/js\.stripe\.com/i],
      globals: ["Stripe"],
    },
    PayPal: {
      category: "Payments",
      scripts: [/paypal\.com\/sdk/i, /paypalobjects\.com/i],
    },
  };

  const WEIGHTS = {
    headers: 100,
    cookies: 90,
    meta: 95,
    globals: 85,
    scripts: 80,
    html: 70,
  };

  function testRegexList(list, value) {
    if (!value) return false;
    return list.some((re) => re.test(value));
  }

  function extractVersion(sig, signals, headers) {
    if (!sig.version) return null;
    const v = sig.version;
    try {
      if (v.from === "meta" && signals.meta) {
        const val = signals.meta[(v.key || "generator").toLowerCase()];
        const m = val && v.re.exec(val);
        return m && m[1] ? m[1] : null;
      }
      if (v.from === "header") {
        const val = headers[(v.key || "").toLowerCase()];
        const m = val && v.re.exec(val);
        return m && m[1] ? m[1] : null;
      }
      if (v.from === "html" && signals.html) {
        const m = v.re.exec(signals.html);
        return m && m[1] ? m[1] : null;
      }
      if (v.from === "script" && signals.scripts) {
        // re may be one regex or several (e.g. version in the filename OR in a
        // ?ver= query string); first capture wins.
        const res = Array.isArray(v.re) ? v.re : [v.re];
        for (const s of signals.scripts) {
          for (const re of res) {
            const m = re.exec(s);
            if (m && m[1]) return m[1];
          }
        }
      }
    } catch (e) {}
    return null;
  }

  // Helper: pull a readable snippet around the first regex match in a string.
  function snippet(re, text, pad = 40) {
    try {
      const m = re.exec(text);
      if (!m) return null;
      const idx = m.index;
      const start = Math.max(0, idx - pad);
      const end = Math.min(text.length, idx + m[0].length + pad);
      let frag = text.slice(start, end).replace(/\s+/g, " ").trim();
      if (start > 0) frag = "…" + frag;
      if (end < text.length) frag = frag + "…";
      return frag;
    } catch (e) {
      return null;
    }
  }

  function detect(signals, headerData) {
    const headers = (headerData && headerData.headers) || {};
    const detected = {};

    Object.entries(SIGNATURES).forEach(([name, sig]) => {
      let confidence = 0;
      const matchedOn = [];
      const evidence = []; // { type, source, detail }

      if (sig.headers) {
        for (const [hName, re] of Object.entries(sig.headers)) {
          const hVal = headers[hName.toLowerCase()];
          if (hVal && re.test(hVal)) {
            confidence = Math.max(confidence, WEIGHTS.headers);
            matchedOn.push("headers");
            evidence.push({
              type: "header",
              source: hName,
              detail: `${hName}: ${hVal}`,
            });
            break;
          }
        }
      }
      if (sig.meta && signals.meta) {
        for (const [mKey, re] of Object.entries(sig.meta)) {
          const mVal = signals.meta[mKey.toLowerCase()];
          if (mVal && re.test(mVal)) {
            confidence = Math.max(confidence, WEIGHTS.meta);
            matchedOn.push("meta");
            evidence.push({
              type: "meta",
              source: mKey,
              detail: `<meta name="${mKey}" content="${mVal}">`,
            });
            break;
          }
        }
      }
      if (sig.globals && signals.globals) {
        const hit = sig.globals.find((g) => signals.globals.includes(g));
        if (hit) {
          confidence = Math.max(confidence, WEIGHTS.globals);
          matchedOn.push("globals");
          evidence.push({
            type: "global",
            source: hit,
            detail: `window.${hit} is defined on the page`,
          });
        }
      }
      if (sig.cookies && signals.cookies) {
        const hit = signals.cookies.find((c) => testRegexList(sig.cookies, c));
        if (hit) {
          confidence = Math.max(confidence, WEIGHTS.cookies);
          matchedOn.push("cookies");
          evidence.push({
            type: "cookie",
            source: hit,
            detail: `Cookie named "${hit}" is set`,
          });
        }
      }
      if (sig.scripts && signals.scripts) {
        const hit = signals.scripts.find((s) => testRegexList(sig.scripts, s));
        if (hit) {
          confidence = Math.max(confidence, WEIGHTS.scripts);
          matchedOn.push("scripts");
          evidence.push({
            type: "script",
            source: "script src",
            detail: hit,
          });
        }
      }
      if (sig.html && signals.html) {
        const re = sig.html.find((r) => r.test(signals.html));
        if (re) {
          confidence = Math.max(confidence, WEIGHTS.html);
          matchedOn.push("html");
          evidence.push({
            type: "html",
            source: "page HTML",
            detail: snippet(re, signals.html) || "pattern matched in page source",
          });
        }
      }

      if (confidence > 0) {
        detected[name] = {
          name,
          category: sig.category,
          confidence,
          matchedOn,
          evidence,
          implied: false,
          implies: sig.implies || [],
          version: extractVersion(sig, signals, headers),
        };
      }
    });

    Object.values({ ...detected }).forEach((tech) => {
      tech.implies.forEach((impliedName) => {
        if (!detected[impliedName]) {
          const sig = SIGNATURES[impliedName];
          detected[impliedName] = {
            name: impliedName,
            category: sig ? sig.category : "Unknown",
            confidence: 50,
            matchedOn: [`implied by ${tech.name}`],
            evidence: [{
              type: "inference",
              source: tech.name,
              detail: `${tech.name} was detected, and it uses ${impliedName} as part of its standard stack`,
            }],
            implied: true,
            implies: sig && sig.implies ? sig.implies : [],
            version: null,
          };
        }
      });
    });

    return Object.values(detected).sort((a, b) => {
      if (b.confidence !== a.confidence) return b.confidence - a.confidence;
      return a.category.localeCompare(b.category);
    });
  }

  function serverSummary(headerData) {
    const headers = (headerData && headerData.headers) || {};
    return {
      ip: (headerData && headerData.ip) || null,
      fromCache: (headerData && headerData.fromCache) || false,
      viaFetch: (headerData && headerData.viaFetch) || false,
      server: headers["server"] || null,
      poweredBy: headers["x-powered-by"] || null,
      via: headers["via"] || null,
      statusCode: (headerData && headerData.statusCode) || null,
    };
  }

  // --- Security headers --------------------------------------------------
  // Known HTTP security headers. Keys are the REAL lowercased header names as
  // captured by background.js (e.g. "strict-transport-security", not "hsts").
  //   importance     -> how much it matters when absent (drives the "missing" sort)
  //   descKey        -> i18n key for the explanation shown on a configured header
  //   recommendation -> the literal header line to add when missing (not translated)
  //   check(value)   -> inspects a present value and returns:
  //                       { status: "good" }                                       (well configured)
  //                       { status: "warning"|"bad", issueKey, issueArgs?, fixKey } (misconfigured)
  //
  // All human text is referenced by i18n key; analyzeHeaders() resolves the
  // keys through the translator passed in, so this module stays DOM- and
  // chrome-free (and still works standalone, returning keys, with no translator).
  const SECURITY_HEADERS = {
    "strict-transport-security": {
      name: "HSTS",
      importance: "high",
      descKey: "hdr_hsts_desc",
      recommendation: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
      check(value) {
        if (!/max-age=/i.test(value)) {
          return { status: "bad", issueKey: "hdr_hsts_nomaxage_issue", fixKey: "hdr_hsts_nomaxage_fix" };
        }
        const m = value.match(/max-age=(\d+)/i);
        const age = m ? parseInt(m[1], 10) : 0;
        if (age < 31536000) {
          return {
            status: "warning",
            issueKey: "hdr_hsts_short_issue",
            issueArgs: [String(age)],
            fixKey: "hdr_hsts_short_fix",
          };
        }
        return { status: "good" };
      },
    },
    "x-frame-options": {
      name: "X-Frame-Options",
      importance: "high",
      descKey: "hdr_xfo_desc",
      recommendation: "X-Frame-Options: SAMEORIGIN",
      check(value) {
        const v = value.trim().toUpperCase();
        if (v === "DENY" || v === "SAMEORIGIN") return { status: "good" };
        if (v.startsWith("ALLOW-FROM")) {
          return { status: "warning", issueKey: "hdr_xfo_allowfrom_issue", fixKey: "hdr_xfo_allowfrom_fix" };
        }
        return {
          status: "warning",
          issueKey: "hdr_xfo_invalid_issue",
          issueArgs: [value],
          fixKey: "hdr_xfo_invalid_fix",
        };
      },
    },
    "x-content-type-options": {
      name: "X-Content-Type-Options",
      importance: "high",
      descKey: "hdr_xcto_desc",
      recommendation: "X-Content-Type-Options: nosniff",
      check(value) {
        if (value.trim().toLowerCase() === "nosniff") return { status: "good" };
        return {
          status: "warning",
          issueKey: "hdr_xcto_invalid_issue",
          issueArgs: [value],
          fixKey: "hdr_xcto_invalid_fix",
        };
      },
    },
    "content-security-policy": {
      name: "CSP",
      importance: "high",
      descKey: "hdr_csp_desc",
      recommendation: "Content-Security-Policy: default-src 'self'",
      check(value) {
        const weak = [];
        if (/'unsafe-inline'/i.test(value)) weak.push("'unsafe-inline'");
        if (/'unsafe-eval'/i.test(value)) weak.push("'unsafe-eval'");
        if (weak.length) {
          return {
            status: "warning",
            issueKey: "hdr_csp_weak_issue",
            issueArgs: [weak.join(" & ")],
            fixKey: "hdr_csp_weak_fix",
          };
        }
        return { status: "good" };
      },
    },
    "referrer-policy": {
      name: "Referrer-Policy",
      importance: "medium",
      descKey: "hdr_referrer_desc",
      recommendation: "Referrer-Policy: strict-origin-when-cross-origin",
      check(value) {
        const v = value.trim().toLowerCase();
        if (v === "unsafe-url") {
          return { status: "bad", issueKey: "hdr_referrer_unsafe_issue", fixKey: "hdr_referrer_unsafe_fix" };
        }
        if (v === "no-referrer-when-downgrade") {
          return { status: "warning", issueKey: "hdr_referrer_downgrade_issue", fixKey: "hdr_referrer_downgrade_fix" };
        }
        return { status: "good" };
      },
    },
    "permissions-policy": {
      name: "Permissions-Policy",
      importance: "medium",
      descKey: "hdr_permissions_desc",
      recommendation: "Permissions-Policy: geolocation=(), camera=(), microphone=()",
      check() {
        // Presence is the win here; any explicit policy is a reasonable posture.
        return { status: "good" };
      },
    },
    // Deprecated. Unlike the others, this one is NEVER recommended when absent
    // (legacyOnlyIfPresent) — current best practice is to drop it and rely on
    // CSP. It only surfaces (in "misconfigured") if a site still sends it, since
    // check() never returns "good".
    "x-xss-protection": {
      name: "X-XSS-Protection",
      importance: "low",
      legacyOnlyIfPresent: true,
      descKey: "hdr_xss_desc",
      check() {
        // Any present value is flagged: the legacy reflected-XSS auditor is
        // unreliable and "1" has itself caused XSS in some browsers. Always a
        // warning, so a present header lands in misconfigured.
        return { status: "warning", issueKey: "hdr_xss_legacy_issue", fixKey: "hdr_xss_legacy_fix" };
      },
    },
  };

  // Analyze captured response headers against the known security headers.
  // `tr(key, args)` is the translator (from the popup); if omitted, keys are
  // returned verbatim so the module still works standalone/in tests.
  // Returns { configured, missing, misconfigured }. A present header lands in
  // exactly one of configured/misconfigured (never both); absent ones go to
  // missing. Returns null when no headers were captured at all.
  function analyzeHeaders(headers, tr) {
    if (!headers || typeof headers !== "object") return null;
    const t = typeof tr === "function" ? tr : (k) => k;

    const configured = [];
    const missing = [];
    const misconfigured = [];

    Object.entries(SECURITY_HEADERS).forEach(([key, spec]) => {
      const raw = headers[key];
      if (raw === undefined || raw === null || String(raw).trim() === "") {
        // Deprecated headers (legacyOnlyIfPresent) are only worth flagging when
        // present with a risky value — never recommend adding them, so skip
        // entirely instead of pushing to "missing".
        if (spec.legacyOnlyIfPresent) return;
        missing.push({
          name: spec.name,
          importance: spec.importance,
          why: t(spec.descKey),
          recommendation: `${t("hdr_add_prefix")} ${spec.recommendation}`,
        });
        return;
      }

      const value = String(raw);
      let result;
      try {
        result = spec.check ? spec.check(value) : { status: "good" };
      } catch (e) {
        result = { status: "good" };
      }

      if (result.status === "good") {
        configured.push({
          name: spec.name,
          value,
          status: "good",
          explanation: t(spec.descKey),
        });
      } else {
        misconfigured.push({
          name: spec.name,
          value,
          status: result.status, // "warning" | "bad"
          issue: t(result.issueKey, result.issueArgs),
          fix: t(result.fixKey),
        });
      }
    });

    return { configured, missing, misconfigured };
  }

  // Identify CDN / protection / security services from the detected list.
  function protection(headerData) {
    const headers = (headerData && headerData.headers) || {};
    const services = [];
    if (headers["cf-ray"] || /cloudflare/i.test(headers["server"] || "")) {
      services.push({ name: "Cloudflare", type: "CDN / WAF" });
    }
    if (headers["x-sucuri-id"] || /sucuri/i.test(headers["server"] || "")) {
      services.push({ name: "Sucuri", type: "WAF" });
    }
    if (headers["x-amz-cf-id"] || /cloudfront/i.test(headers["via"] || "")) {
      services.push({ name: "Amazon CloudFront", type: "CDN" });
    }
    if (headers["x-akamai-transformed"]) {
      services.push({ name: "Akamai", type: "CDN" });
    }
    if (headers["x-fastly-request-id"]) {
      services.push({ name: "Fastly", type: "CDN" });
    }
    return services;
  }

  return { detect, serverSummary, protection, analyzeHeaders, SECURITY_HEADERS, SIGNATURES };
})();

if (typeof window !== "undefined") window.TechDetector = TechDetector;
if (typeof module !== "undefined" && module.exports) module.exports = TechDetector;

// tech-detector.js
// Pure detection logic: given page signals (DOM) + response headers,
// returns detected technologies with category, confidence and version.
//
// No DOM access here — this module is given everything it needs as data,
// which keeps it testable and lets it run inside the popup context.

const TechDetector = (() => {
  // Signature schema documented in signatures.js
  const SIGNATURES =
    (typeof WA_SIGNATURES !== "undefined" && WA_SIGNATURES) ||
    (typeof require !== "undefined" ? require("./signatures.js") : {});

  const WEIGHTS = {
    headers: 100,
    cookies: 90,
    meta: 95,
    globals: 85,
    scripts: 80,
    html: 70,
  };

  // Techs whose signals are unambiguous — a vendor-specific global/cookie, or a
  // unique external resource (CDN host, service URL). A match means the tech is
  // certainly present, so it reports 100% confidence regardless of signal tier.
  // Deliberately EXCLUDES heuristic detections (CSS class-name guesses, generic
  // words like "magento"/"woocommerce", "fa-" icons) which keep their weight, so
  // the score still flags the genuinely-uncertain ones. WordPress is omitted on
  // purpose: it reaches 100% via its version / deep-scan confirmation.
  const CONFIDENT_TECHS = new Set([
    "Drupal", "Joomla", "Squarespace", "Wix", "Webflow",
    "Shopify", "BigCommerce",
    "VNDA", "Nuvemshop", "Tray", "Loja Integrada", "Yampi", "VTEX",
    "Salesforce Commerce Cloud",
    "React", "Next.js", "Vue.js", "Nuxt.js", "Angular", "Svelte",
    "Gatsby", "Remix", "Alpine.js", "jQuery", "Lodash",
    "Google Fonts", "Elementor",
    "PHP", "ASP.NET", "Node.js", "Express.js", "Ruby on Rails", "Java", "Laravel",
    "Google Tag Manager", "Google Analytics", "Facebook Pixel", "Hotjar",
    "Stripe", "PayPal",
  ]);

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
        // re may be one regex or several (e.g. a generator meta OR an asset
        // ?ver=); first capture wins.
        const res = Array.isArray(v.re) ? v.re : [v.re];
        for (const re of res) {
          const m = re.exec(signals.html);
          if (m && m[1]) return m[1];
        }
        return null;
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

  // signatureSet lets the caller pass a merged (embedded + remote) set; it
  // defaults to the embedded SIGNATURES so existing callers are unaffected.
  function detect(signals, headerData, signatureSet) {
    const headers = (headerData && headerData.headers) || {};
    const detected = {};
    const SIGS = signatureSet || SIGNATURES;

    Object.entries(SIGS).forEach(([name, sig]) => {
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
        const version = extractVersion(sig, signals, headers);
        // A captured version, or a match on an unambiguous signal (see
        // CONFIDENT_TECHS), means the tech is certainly present → full confidence.
        const certain = !!version || CONFIDENT_TECHS.has(name);
        detected[name] = {
          name,
          category: sig.category,
          confidence: certain ? 100 : confidence,
          matchedOn,
          evidence,
          implied: false,
          implies: sig.implies || [],
          version,
        };
      }
    });

    Object.values({ ...detected }).forEach((tech) => {
      tech.implies.forEach((impliedName) => {
        if (!detected[impliedName]) {
          const sig = SIGS[impliedName];
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

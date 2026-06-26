import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

// The detectors are browser IIFEs that also expose module.exports for Node.
// Load via CommonJS require so the module.exports guard fires.
const require = createRequire(import.meta.url);
const TechDetector = require("../detectors/tech-detector.js");

// Convenience: find a detected tech by name in the result array.
const find = (list, name) => list.find((t) => t.name === name);

describe("TechDetector — signature wiring", () => {
  it("loads signatures from the external signatures module", () => {
    expect(typeof TechDetector.SIGNATURES).toBe("object");
    expect(Object.keys(TechDetector.SIGNATURES).length).toBeGreaterThan(0);
    for (const key of ["WordPress", "Shopify", "VNDA"]) {
      expect(TechDetector.SIGNATURES[key]).toBeDefined();
    }
  });

  it("compiles regex sources from the signature data", () => {
    // The JSON stores regex as { $re, flags } strings; the loader must compile
    // them back into live RegExp with source AND flags preserved verbatim.
    const re = TechDetector.SIGNATURES.VNDA.html[0];
    expect(re).toBeInstanceOf(RegExp);
    expect(re.source).toBe("cdn\\.vnda\\.com\\.br");
    expect(re.flags).toBe("i");
  });

  it("signatures.json and the inline browser data are in sync", () => {
    // The popup/content-script path compiles from the inline RAW copy while
    // Node compiles from signatures.json — they must hold identical data.
    const signatures = require("../detectors/signatures.js");
    const json = require("../detectors/signatures.json");
    expect(signatures._raw).toEqual(json);
  });
});

describe("TechDetector.detect — detection by each signal type", () => {
  it("detects Nginx from the Server header and extracts the version", () => {
    const result = TechDetector.detect({}, { headers: { server: "nginx/1.2" } });
    const nginx = find(result, "Nginx");
    expect(nginx).toBeDefined();
    expect(nginx.version).toBe("1.2");
    expect(nginx.implied).toBe(false);
  });

  it("detects WordPress from the generator meta with meta-weight confidence (95)", () => {
    // Versionless generator so this exercises the meta weight, not the
    // version-override-to-100 rule (covered separately below).
    const result = TechDetector.detect({ meta: { generator: "WordPress" } }, null);
    const wp = find(result, "WordPress");
    expect(wp).toBeDefined();
    expect(wp.version).toBeNull();
    expect(wp.confidence).toBe(95);
  });

  it("reports 100% confidence when a version is identified (overrides signal weight)", () => {
    // WordPress via generator meta is weight 95, but a captured version is proof.
    const result = TechDetector.detect({ meta: { generator: "WordPress 6.4" } }, null);
    const wp = find(result, "WordPress");
    expect(wp.version).toBe("6.4");
    expect(wp.confidence).toBe(100);
  });

  it("detects React from a window global (unambiguous → 100%)", () => {
    const result = TechDetector.detect({ globals: ["React"] }, null);
    const react = find(result, "React");
    expect(react).toBeDefined();
    expect(react.implied).toBe(false);
    expect(react.confidence).toBe(100); // window.React is unambiguous
  });

  it("detects PHP from the PHPSESSID cookie (unambiguous → 100%)", () => {
    const result = TechDetector.detect({ cookies: ["PHPSESSID"] }, null);
    const php = find(result, "PHP");
    expect(php).toBeDefined();
    expect(php.confidence).toBe(100); // PHPSESSID is unambiguous
  });

  it("reports 100% for an unambiguous tech even without a version (Google Fonts)", () => {
    const result = TechDetector.detect(
      { html: '<link href="https://fonts.googleapis.com/css?family=Inter">' },
      null
    );
    const gf = find(result, "Google Fonts");
    expect(gf).toBeDefined();
    expect(gf.version).toBeNull();
    expect(gf.confidence).toBe(100);
  });

  it("keeps the html weight (70) for a heuristic class-name match (Tailwind)", () => {
    const result = TechDetector.detect({ html: '<div class="bg-blue-500"></div>' }, null);
    const tw = find(result, "Tailwind CSS");
    expect(tw).toBeDefined();
    expect(tw.confidence).toBe(70); // heuristic — stays weighted
  });

  it("detects jQuery from a script src and extracts the version", () => {
    const result = TechDetector.detect(
      { scripts: ["https://code.jquery.com/jquery-3.6.0.min.js"] },
      null
    );
    const jq = find(result, "jQuery");
    expect(jq).toBeDefined();
    expect(jq.version).toBe("3.6.0");
    expect(jq.confidence).toBe(100); // version identified → certain
  });

  it("extracts the jQuery version from a WordPress-style ?ver= query string", () => {
    const result = TechDetector.detect(
      {
        scripts: [
          "https://site.example/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1",
          "https://site.example/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
        ],
      },
      null
    );
    const jq = find(result, "jQuery");
    expect(jq).toBeDefined();
    // Must read jquery core's ?ver= (3.7.1), not jquery-migrate's (3.4.1).
    expect(jq.version).toBe("3.7.1");
  });

  it("extracts the WooCommerce version from its generator meta", () => {
    const html =
      '<body class="woocommerce-page"></body>' +
      '<meta name="generator" content="WordPress 7.0">' +
      '<meta name="generator" content="WooCommerce 8.5.1">';
    const result = TechDetector.detect({ html }, null);
    const wc = find(result, "WooCommerce");
    expect(wc).toBeDefined();
    expect(wc.version).toBe("8.5.1"); // found even amid other generator metas
    expect(wc.confidence).toBe(100); // version → certain
  });

  it("extracts the WooCommerce version from its asset ?ver= when no generator meta", () => {
    const html =
      '<div class="woocommerce"></div>' +
      '<link href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=9.2.3">';
    const wc = find(TechDetector.detect({ html }, null), "WooCommerce");
    expect(wc.version).toBe("9.2.3");
  });

  it("ignores a cache-busting timestamp in ?ver= (not a real version)", () => {
    const result = TechDetector.detect(
      { scripts: ["https://site.example/wp-includes/js/jquery/jquery.min.js?ver=1771584108"] },
      null
    );
    const jq = find(result, "jQuery");
    expect(jq).toBeDefined(); // still detected
    expect(jq.version).toBeNull(); // timestamp rejected, not shown as a version
  });

  it("extracts the Elementor version from its core asset ?ver= (not elementor-pro)", () => {
    const html =
      '<div class="elementor-widget"></div>' +
      '<link href="/wp-content/plugins/elementor-pro/assets/css/frontend.min.css?ver=3.99.0">' +
      '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.21.0"></script>';
    const result = TechDetector.detect({ html }, null);
    const el = find(result, "Elementor");
    expect(el).toBeDefined();
    expect(el.version).toBe("3.21.0"); // core, not the pro 3.99.0
  });

  describe("Tailwind CSS via HTML classes (lookbehind guard)", () => {
    it("matches a distinctive Tailwind class (bg-blue-500)", () => {
      const result = TechDetector.detect({ html: '<div class="bg-blue-500"></div>' }, null);
      expect(find(result, "Tailwind CSS")).toBeDefined();
    });

    it("does NOT match a themed-prefixed class (wpex-flex)", () => {
      const result = TechDetector.detect({ html: '<div class="wpex-flex"></div>' }, null);
      expect(find(result, "Tailwind CSS")).toBeUndefined();
    });

    it("does NOT match a themed-prefixed color class (wpex-bg-blue-500)", () => {
      const result = TechDetector.detect({ html: '<div class="wpex-bg-blue-500"></div>' }, null);
      expect(find(result, "Tailwind CSS")).toBeUndefined();
    });
  });
});

describe("TechDetector.detect — e-commerce platforms", () => {
  const ecom = (html) => TechDetector.detect({ html }, null);

  it("detects VNDA from a cdn.vnda.com.br asset URL", () => {
    const t = find(ecom('<img src="https://cdn.vnda.com.br/123/p.jpg">'), "VNDA");
    expect(t).toBeDefined();
    expect(t.category).toBe("Ecommerce");
  });

  it("detects Nuvemshop from its asset CDN host", () => {
    expect(find(ecom('<img src="https://dcdn.nuvemshop.com.br/x.png">'), "Nuvemshop")).toBeDefined();
  });

  it("detects Tray from its asset host", () => {
    expect(find(ecom('<img src="https://images.tcdn.com.br/x.jpg">'), "Tray")).toBeDefined();
  });

  it("detects Loja Integrada from its asset host", () => {
    expect(find(ecom('<img src="https://cdn.awsli.com.br/x.jpg">'), "Loja Integrada")).toBeDefined();
  });

  it("detects Yampi from its asset/checkout host", () => {
    expect(find(ecom('<script src="https://api.yampi.com.br/v1/x.js">'), "Yampi")).toBeDefined();
  });

  it("detects VTEX from vtexassets.com", () => {
    const t = find(ecom('<link href="https://store.vtexassets.com/a.css">'), "VTEX");
    expect(t).toBeDefined();
    expect(t.category).toBe("Ecommerce");
  });

  it("does NOT detect VNDA on an unrelated page", () => {
    expect(find(ecom("<div>just a regular page with no platform signals</div>"), "VNDA")).toBeUndefined();
  });

  it("does NOT match Tray on the generic words 'tray table' in body text", () => {
    expect(find(ecom("<p>buy a wooden tray table in our store</p>"), "Tray")).toBeUndefined();
  });

  // A page that only MENTIONS/links a platform (review, comparison, "developed by"
  // credit) must not be reported as running it — only its asset CDN proves usage.
  it("does NOT detect VNDA from a bare vnda.com.br link in page text", () => {
    expect(find(ecom('<a href="https://www.vnda.com.br">site by VNDA</a>'), "VNDA")).toBeUndefined();
  });

  it("does NOT detect Nuvemshop from a bare nuvemshop.com.br mention", () => {
    expect(find(ecom('<a href="https://www.nuvemshop.com.br">Nuvemshop review</a>'), "Nuvemshop")).toBeUndefined();
  });

  it("does NOT detect Tray from a bare tray.com.br mention", () => {
    expect(find(ecom('<a href="https://www.tray.com.br">Tray vs Nuvemshop</a>'), "Tray")).toBeUndefined();
  });

  it("does NOT detect Loja Integrada from a bare lojaintegrada.com.br mention", () => {
    expect(find(ecom('<a href="https://www.lojaintegrada.com.br">Loja Integrada</a>'), "Loja Integrada")).toBeUndefined();
  });
});

describe("TechDetector.detect — implications", () => {
  it("Next.js implies React and Node.js (implied: true, confidence 50)", () => {
    const result = TechDetector.detect({ globals: ["__NEXT_DATA__"] }, null);
    expect(find(result, "Next.js")).toBeDefined();

    const react = find(result, "React");
    const node = find(result, "Node.js");
    expect(react).toBeDefined();
    expect(react.implied).toBe(true);
    expect(react.confidence).toBe(50);
    expect(node).toBeDefined();
    expect(node.implied).toBe(true);
    expect(node.confidence).toBe(50);
  });

  it("WordPress implies PHP and MySQL", () => {
    const result = TechDetector.detect({ meta: { generator: "WordPress 6.4" } }, null);
    const php = find(result, "PHP");
    const mysql = find(result, "MySQL");
    expect(php).toBeDefined();
    expect(php.implied).toBe(true);
    expect(mysql).toBeDefined();
    expect(mysql.implied).toBe(true);
  });

  it("implication does NOT override a direct detection", () => {
    // React is detected directly (global) AND would be implied by Next.js.
    const result = TechDetector.detect({ globals: ["React", "__NEXT_DATA__"] }, null);
    const react = find(result, "React");
    expect(react).toBeDefined();
    expect(react.implied).toBe(false); // direct detection, not the implied one
    expect(react.confidence).toBe(100); // unambiguous global
  });
});

describe("TechDetector.detect — ordering and confidence", () => {
  it("returns results ordered by confidence descending", () => {
    const result = TechDetector.detect(
      { globals: ["React"], html: '<div class="bg-blue-500"></div>' },
      { headers: { server: "nginx/1.2" } }
    );
    const confs = result.map((t) => t.confidence);
    const sorted = [...confs].sort((a, b) => b - a);
    expect(confs).toEqual(sorted);
    // sanity: highest is the header-based Nginx (weight 100)
    expect(confs[0]).toBe(100);
  });

  it("uses the highest weight when a (non-confident) tech matches on multiple signals", () => {
    // Bootstrap is heuristic (not in CONFIDENT_TECHS): matches html col-* (70)
    // and a script (80) → max weight 80, not bumped to 100.
    const result = TechDetector.detect(
      { html: '<div class="col-md-6"></div>', scripts: ["/assets/bootstrap.min.js"] },
      null
    );
    const bs = find(result, "Bootstrap");
    expect(bs.confidence).toBe(80);
    expect(bs.matchedOn).toContain("scripts");
    expect(bs.matchedOn).toContain("html");
  });
});

describe("TechDetector.detect — robustness", () => {
  it("returns an empty array for empty signals and null headerData without throwing", () => {
    let result;
    expect(() => {
      result = TechDetector.detect({}, null);
    }).not.toThrow();
    expect(result).toEqual([]);
  });

  it("does not throw with empty signals and empty headerData", () => {
    expect(() => TechDetector.detect({}, {})).not.toThrow();
  });
});

describe("TechDetector.serverSummary", () => {
  it("extracts server, poweredBy, via, statusCode and ip from headerData", () => {
    const summary = TechDetector.serverSummary({
      headers: {
        server: "nginx/1.2",
        "x-powered-by": "PHP/8.1",
        via: "1.1 varnish",
      },
      ip: "203.0.113.4",
      statusCode: 200,
    });
    expect(summary.server).toBe("nginx/1.2");
    expect(summary.poweredBy).toBe("PHP/8.1");
    expect(summary.via).toBe("1.1 varnish");
    expect(summary.statusCode).toBe(200);
    expect(summary.ip).toBe("203.0.113.4");
  });

  it("propagates the fromCache and viaFetch flags", () => {
    const summary = TechDetector.serverSummary({
      headers: {},
      fromCache: true,
      viaFetch: true,
    });
    expect(summary.fromCache).toBe(true);
    expect(summary.viaFetch).toBe(true);
  });

  it("returns null fields (no throw) when headerData is null", () => {
    let summary;
    expect(() => {
      summary = TechDetector.serverSummary(null);
    }).not.toThrow();
    expect(summary.server).toBeNull();
    expect(summary.poweredBy).toBeNull();
    expect(summary.via).toBeNull();
    expect(summary.statusCode).toBeNull();
    expect(summary.ip).toBeNull();
    expect(summary.fromCache).toBe(false);
    expect(summary.viaFetch).toBe(false);
  });
});

describe("TechDetector.protection", () => {
  it("identifies Cloudflare from cf-ray", () => {
    const services = TechDetector.protection({ headers: { "cf-ray": "abc123" } });
    expect(services.some((s) => s.name === "Cloudflare")).toBe(true);
  });

  it("identifies Sucuri from x-sucuri-id", () => {
    const services = TechDetector.protection({ headers: { "x-sucuri-id": "12345" } });
    expect(services.some((s) => s.name === "Sucuri")).toBe(true);
  });

  it("identifies Amazon CloudFront from x-amz-cf-id", () => {
    const services = TechDetector.protection({ headers: { "x-amz-cf-id": "xyz" } });
    expect(services.some((s) => s.name === "Amazon CloudFront")).toBe(true);
  });

  it("identifies multiple protection services at once", () => {
    const services = TechDetector.protection({
      headers: { "cf-ray": "abc", "x-sucuri-id": "1", "x-amz-cf-id": "z" },
    });
    const names = services.map((s) => s.name);
    expect(names).toContain("Cloudflare");
    expect(names).toContain("Sucuri");
    expect(names).toContain("Amazon CloudFront");
  });

  it("returns an empty array when no protection headers are present", () => {
    expect(TechDetector.protection({ headers: { server: "nginx" } })).toEqual([]);
  });
});

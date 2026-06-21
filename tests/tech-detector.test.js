import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

// The detectors are browser IIFEs that also expose module.exports for Node.
// Load via CommonJS require so the module.exports guard fires.
const require = createRequire(import.meta.url);
const TechDetector = require("../detectors/tech-detector.js");

// Convenience: find a detected tech by name in the result array.
const find = (list, name) => list.find((t) => t.name === name);

describe("TechDetector.detect — detection by each signal type", () => {
  it("detects Nginx from the Server header and extracts the version", () => {
    const result = TechDetector.detect({}, { headers: { server: "nginx/1.2" } });
    const nginx = find(result, "Nginx");
    expect(nginx).toBeDefined();
    expect(nginx.version).toBe("1.2");
    expect(nginx.implied).toBe(false);
  });

  it("detects WordPress from the generator meta with meta-weight confidence (95)", () => {
    const result = TechDetector.detect({ meta: { generator: "WordPress 6.4" } }, null);
    const wp = find(result, "WordPress");
    expect(wp).toBeDefined();
    expect(wp.confidence).toBe(95);
  });

  it("detects React from a window global", () => {
    const result = TechDetector.detect({ globals: ["React"] }, null);
    const react = find(result, "React");
    expect(react).toBeDefined();
    expect(react.implied).toBe(false);
    expect(react.confidence).toBe(85); // globals weight
  });

  it("detects PHP from the PHPSESSID cookie", () => {
    const result = TechDetector.detect({ cookies: ["PHPSESSID"] }, null);
    const php = find(result, "PHP");
    expect(php).toBeDefined();
    expect(php.confidence).toBe(90); // cookies weight
  });

  it("detects jQuery from a script src and extracts the version", () => {
    const result = TechDetector.detect(
      { scripts: ["https://code.jquery.com/jquery-3.6.0.min.js"] },
      null
    );
    const jq = find(result, "jQuery");
    expect(jq).toBeDefined();
    expect(jq.version).toBe("3.6.0");
    expect(jq.confidence).toBe(80); // scripts weight
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
    expect(react.implied).toBe(false);
    expect(react.confidence).toBe(85); // stays the direct-detection confidence
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

  it("uses the highest weight when a tech matches on multiple signals", () => {
    // React matches both globals (85) and html data-reactroot (70).
    const result = TechDetector.detect(
      { globals: ["React"], html: "<div data-reactroot></div>" },
      null
    );
    const react = find(result, "React");
    expect(react.confidence).toBe(85);
    expect(react.matchedOn).toContain("globals");
    expect(react.matchedOn).toContain("html");
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

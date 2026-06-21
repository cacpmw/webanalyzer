import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const TechDetector = require("../detectors/tech-detector.js");
const { analyzeHeaders, SECURITY_HEADERS } = TechDetector;

// Single translation strategy for the whole file: an identity translator that
// also surfaces interpolation args, so a test can assert both the message and
// the value carried into it (e.g. the "3600" in an HSTS warning). Keeping it in
// one place makes every assertion independent of real translations.
const tr = (key, args) =>
  Array.isArray(args) && args.length ? `${key} :: ${args.join(" | ")}` : key;

const analyze = (headers) => analyzeHeaders(headers, tr);

// Display name as the module reports it (derived, not hardcoded).
const nameOf = (key) => SECURITY_HEADERS[key].name;
const find = (bucket, name) => bucket.find((h) => h.name === name);

const BUCKETS = ["configured", "misconfigured", "missing"];
const bucketsContaining = (result, name) =>
  BUCKETS.filter((b) => result[b].some((h) => h.name === name));

describe("analyzeHeaders — general classification", () => {
  it("a present, well-configured header lands in configured (good) and nowhere else", () => {
    const result = analyze({ "x-content-type-options": "nosniff" });
    const name = nameOf("x-content-type-options");
    const entry = find(result.configured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("good");
    expect(bucketsContaining(result, name)).toEqual(["configured"]);
  });

  it("a present, misconfigured header lands in misconfigured (status/issue/fix), never configured", () => {
    const result = analyze({ "x-content-type-options": "sniff-please" });
    const name = nameOf("x-content-type-options");
    const entry = find(result.misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBeTruthy();
    expect(entry.issue).toBeTruthy();
    expect(entry.fix).toBeTruthy();
    expect(find(result.configured, name)).toBeUndefined();
    expect(bucketsContaining(result, name)).toEqual(["misconfigured"]);
  });

  it("an absent header lands in missing with importance and recommendation", () => {
    const result = analyze({});
    const name = nameOf("strict-transport-security");
    const entry = find(result.missing, name);
    expect(entry).toBeDefined();
    expect(entry.importance).toBe("high");
    expect(entry.recommendation).toBeTruthy();
  });

  it("INVARIANT: every security header appears in exactly one bucket (mixed input)", () => {
    const result = analyze({
      "strict-transport-security": "max-age=31536000; includeSubDomains", // good
      "x-frame-options": "ALLOW-FROM https://x.com", // misconfigured
      "x-content-type-options": "nosniff", // good
      // content-security-policy absent → missing
      "referrer-policy": "unsafe-url", // misconfigured
      "permissions-policy": "geolocation=()", // good
      "x-xss-protection": "1; mode=block", // misconfigured (legacy, present)
    });
    // All seven headers are either present or absent-non-legacy here, so each
    // must show up in exactly one bucket.
    Object.values(SECURITY_HEADERS).forEach((spec) => {
      expect(bucketsContaining(result, spec.name)).toHaveLength(1);
    });
  });

  it("null / non-object headers → null (not an empty result object)", () => {
    expect(analyze(null)).toBeNull();
    expect(analyze(undefined)).toBeNull();
    expect(analyze("nope")).toBeNull();
    expect(analyze(123)).toBeNull();
  });

  it("an empty / whitespace-only value counts as absent → goes to missing", () => {
    const result = analyze({ "x-frame-options": "   " });
    const name = nameOf("x-frame-options");
    expect(find(result.missing, name)).toBeDefined();
    expect(find(result.configured, name)).toBeUndefined();
    expect(find(result.misconfigured, name)).toBeUndefined();
  });
});

describe("analyzeHeaders — HSTS (strict-transport-security)", () => {
  const name = nameOf("strict-transport-security");

  it("max-age=31536000; includeSubDomains → good", () => {
    const result = analyze({ "strict-transport-security": "max-age=31536000; includeSubDomains" });
    expect(find(result.configured, name)).toBeDefined();
  });

  it("no max-age → bad, 'nomaxage' issue", () => {
    const result = analyze({ "strict-transport-security": "includeSubDomains" });
    const entry = find(result.misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("bad");
    expect(entry.issue).toContain("nomaxage");
  });

  it("max-age below one year (3600) → warning, and the issue carries the value '3600'", () => {
    const result = analyze({ "strict-transport-security": "max-age=3600" });
    const entry = find(result.misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
    expect(entry.issue).toContain("3600");
  });

  it("exactly max-age=31536000 → good (boundary, must not become warning)", () => {
    const result = analyze({ "strict-transport-security": "max-age=31536000" });
    expect(find(result.configured, name)).toBeDefined();
    expect(find(result.misconfigured, name)).toBeUndefined();
  });
});

describe("analyzeHeaders — X-Frame-Options", () => {
  const name = nameOf("x-frame-options");

  it("DENY and SAMEORIGIN → good", () => {
    expect(find(analyze({ "x-frame-options": "DENY" }).configured, name)).toBeDefined();
    expect(find(analyze({ "x-frame-options": "SAMEORIGIN" }).configured, name)).toBeDefined();
  });

  it("ALLOW-FROM → warning, 'allowfrom' issue", () => {
    const entry = find(analyze({ "x-frame-options": "ALLOW-FROM https://x.com" }).misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
    expect(entry.issue).toContain("allowfrom");
  });

  it("invalid value → warning, 'invalid' issue carrying the offending value", () => {
    const entry = find(analyze({ "x-frame-options": "INVALID" }).misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
    expect(entry.issue).toContain("invalid");
    expect(entry.issue).toContain("INVALID");
  });

  it("is case-insensitive: lowercase 'sameorigin' → good", () => {
    expect(find(analyze({ "x-frame-options": "sameorigin" }).configured, name)).toBeDefined();
  });
});

describe("analyzeHeaders — X-Content-Type-Options", () => {
  const name = nameOf("x-content-type-options");

  it("nosniff → good; nosniff with spaces/caps → good", () => {
    expect(find(analyze({ "x-content-type-options": "nosniff" }).configured, name)).toBeDefined();
    expect(find(analyze({ "x-content-type-options": "  NoSniff  " }).configured, name)).toBeDefined();
  });

  it("any other value → warning", () => {
    const entry = find(analyze({ "x-content-type-options": "off" }).misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
  });
});

describe("analyzeHeaders — CSP (content-security-policy)", () => {
  const name = nameOf("content-security-policy");

  it("default-src 'self' → good", () => {
    expect(find(analyze({ "content-security-policy": "default-src 'self'" }).configured, name)).toBeDefined();
  });

  it("'unsafe-inline' present → warning, issue lists the token", () => {
    const entry = find(
      analyze({ "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'" }).misconfigured,
      name
    );
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
    expect(entry.issue).toContain("'unsafe-inline'");
  });

  it("both 'unsafe-inline' and 'unsafe-eval' → warning, issue lists both", () => {
    const entry = find(
      analyze({ "content-security-policy": "script-src 'unsafe-inline' 'unsafe-eval'" }).misconfigured,
      name
    );
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
    expect(entry.issue).toContain("'unsafe-inline'");
    expect(entry.issue).toContain("'unsafe-eval'");
  });
});

describe("analyzeHeaders — Referrer-Policy", () => {
  const name = nameOf("referrer-policy");

  it("strict-origin-when-cross-origin → good", () => {
    expect(find(analyze({ "referrer-policy": "strict-origin-when-cross-origin" }).configured, name)).toBeDefined();
  });

  it("unsafe-url → bad", () => {
    const entry = find(analyze({ "referrer-policy": "unsafe-url" }).misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("bad");
  });

  it("no-referrer-when-downgrade → warning", () => {
    const entry = find(analyze({ "referrer-policy": "no-referrer-when-downgrade" }).misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
  });
});

describe("analyzeHeaders — Permissions-Policy", () => {
  const name = nameOf("permissions-policy");

  it("any present value → good (presence is the criterion)", () => {
    expect(find(analyze({ "permissions-policy": "geolocation=()" }).configured, name)).toBeDefined();
    expect(find(analyze({ "permissions-policy": "camera=(), microphone=()" }).configured, name)).toBeDefined();
  });
});

describe("analyzeHeaders — X-XSS-Protection (legacyOnlyIfPresent)", () => {
  const name = nameOf("x-xss-protection");

  it("absent → appears in NO bucket (not even missing)", () => {
    const result = analyze({ "x-content-type-options": "nosniff" }); // anything but x-xss
    expect(bucketsContaining(result, name)).toEqual([]);
  });

  it("present with '1; mode=block' → misconfigured, warning", () => {
    const result = analyze({ "x-xss-protection": "1; mode=block" });
    const entry = find(result.misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
  });

  it("present with '0' → also misconfigured, warning (any present value is flagged)", () => {
    const result = analyze({ "x-xss-protection": "0" });
    const entry = find(result.misconfigured, name);
    expect(entry).toBeDefined();
    expect(entry.status).toBe("warning");
  });

  it("when present, never lands in configured or missing", () => {
    const result = analyze({ "x-xss-protection": "1" });
    expect(find(result.configured, name)).toBeUndefined();
    expect(find(result.missing, name)).toBeUndefined();
    expect(bucketsContaining(result, name)).toEqual(["misconfigured"]);
  });
});

describe("analyzeHeaders — check() robustness", () => {
  it("strange values don't bring down the analysis (no throw, well-formed, invariant holds)", () => {
    const weird = {
      "strict-transport-security": "🦄 max-age=not-a-number 💥",
      "x-frame-options": " ",
      "x-content-type-options": "x".repeat(4000),
      "content-security-policy": "'unsafe-inline'".repeat(50),
      "referrer-policy": "   ???   ",
      "permissions-policy": "()",
      "x-xss-protection": "??? garbage ???",
    };
    let result;
    expect(() => {
      result = analyze(weird);
    }).not.toThrow();
    expect(Array.isArray(result.configured)).toBe(true);
    expect(Array.isArray(result.misconfigured)).toBe(true);
    expect(Array.isArray(result.missing)).toBe(true);
    // Every header still classified into exactly one bucket.
    Object.values(SECURITY_HEADERS).forEach((spec) => {
      expect(bucketsContaining(result, spec.name)).toHaveLength(1);
    });
  });
});

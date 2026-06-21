import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

// Browser IIFE that also exposes module.exports for Node; require directly.
const require = createRequire(import.meta.url);
const NetworkTools = require("../detectors/network-detector.js");

describe("NetworkTools.cleanValue", () => {
  it("TXT: strips outer quotes and joins chunked strings", () => {
    expect(NetworkTools.cleanValue("TXT", '"a" "b"')).toBe("ab");
    expect(NetworkTools.cleanValue("TXT", '"hello world"')).toBe("hello world");
  });

  it("NS: removes the trailing dot", () => {
    expect(NetworkTools.cleanValue("NS", "ns1.example.com.")).toBe("ns1.example.com");
  });

  it("CNAME: removes the trailing dot", () => {
    expect(NetworkTools.cleanValue("CNAME", "target.example.com.")).toBe("target.example.com");
  });

  it("MX: removes the trailing dot, keeps the 'priority hostname' shape", () => {
    expect(NetworkTools.cleanValue("MX", "10 mail.example.com.")).toBe("10 mail.example.com");
  });

  it("null/undefined data → empty string, without throwing", () => {
    expect(() => NetworkTools.cleanValue("A", null)).not.toThrow();
    expect(NetworkTools.cleanValue("A", null)).toBe("");
    expect(NetworkTools.cleanValue("TXT", undefined)).toBe("");
  });
});

describe("NetworkTools.parseAnswers", () => {
  it("keeps only answers whose numeric code matches the expected type", () => {
    const answers = [
      { type: 1, data: "203.0.113.4", TTL: 300 },
      { type: 28, data: "2001:db8::1", TTL: 300 },
      { type: 5, data: "x.example.com.", TTL: 60 },
    ];
    const result = NetworkTools.parseAnswers(answers, "A");
    expect(result).toEqual([{ type: "A", value: "203.0.113.4", ttl: 300 }]);
  });

  it("maps to {type, value, ttl} applying cleanValue (CNAME trailing dot removed)", () => {
    const result = NetworkTools.parseAnswers(
      [{ type: 5, data: "alias.example.com.", TTL: 120 }],
      "CNAME"
    );
    expect(result).toEqual([{ type: "CNAME", value: "alias.example.com", ttl: 120 }]);
  });

  it("ignores answers of a different type than expected", () => {
    const result = NetworkTools.parseAnswers([{ type: 28, data: "::1", TTL: 60 }], "A");
    expect(result).toEqual([]);
  });

  it("falls back to ttl null when the answer has no TTL", () => {
    const result = NetworkTools.parseAnswers([{ type: 1, data: "203.0.113.4" }], "A");
    expect(result).toEqual([{ type: "A", value: "203.0.113.4", ttl: null }]);
  });

  it("non-array input → []", () => {
    expect(NetworkTools.parseAnswers(null, "A")).toEqual([]);
    expect(NetworkTools.parseAnswers(undefined, "A")).toEqual([]);
  });
});

describe("NetworkTools.baseDomain", () => {
  it("strips a subdomain: www.example.com → example.com", () => {
    expect(NetworkTools.baseDomain("www.example.com")).toBe("example.com");
  });

  it("returns ≤2-label hostnames unchanged: example.com → example.com", () => {
    expect(NetworkTools.baseDomain("example.com")).toBe("example.com");
  });

  it("handles multi-part TLDs: loja.exemplo.com.br → exemplo.com.br", () => {
    expect(NetworkTools.baseDomain("loja.exemplo.com.br")).toBe("exemplo.com.br");
  });

  it("handles 3+ labels over a multi-part TLD: sub.exemplo.com.br → exemplo.com.br", () => {
    expect(NetworkTools.baseDomain("sub.exemplo.com.br")).toBe("exemplo.com.br");
  });

  it("does NOT over-grab on a simple TLD: a.b.example.com → example.com", () => {
    expect(NetworkTools.baseDomain("a.b.example.com")).toBe("example.com");
  });
});

describe("NetworkTools.normalizeSubdomains", () => {
  it("dedupes, strips wildcards, drops apex/spaces/foreign names, sorts, requires .base suffix", () => {
    const base = "example.com";
    const names = [
      "www.example.com",
      "www.example.com", // duplicate
      "*.api.example.com", // wildcard prefix
      "example.com", // apex — should be dropped
      "bad name.example.com", // contains a space — dropped
      "other.com", // not under base — dropped
      "blog.example.com",
    ];
    expect(NetworkTools.normalizeSubdomains(names, base)).toEqual([
      "api.example.com",
      "blog.example.com",
      "www.example.com",
    ]);
  });
});

describe("NetworkTools.flagEmoji", () => {
  it("'BR' → 🇧🇷 (correct Regional Indicator code points)", () => {
    expect(NetworkTools.flagEmoji("BR")).toBe("🇧🇷");
    expect(NetworkTools.flagEmoji("BR")).toBe(String.fromCodePoint(0x1f1e7, 0x1f1f7));
  });

  it("lowercase 'br' → same result as 'BR'", () => {
    expect(NetworkTools.flagEmoji("br")).toBe(NetworkTools.flagEmoji("BR"));
  });

  it("invalid codes → empty string", () => {
    expect(NetworkTools.flagEmoji("")).toBe("");
    expect(NetworkTools.flagEmoji("B")).toBe("");
    expect(NetworkTools.flagEmoji("BRA")).toBe("");
    expect(NetworkTools.flagEmoji("B1")).toBe("");
  });
});

describe("NetworkTools.buildZoneFile", () => {
  it("includes a header with $ORIGIN and $TTL", () => {
    const out = NetworkTools.buildZoneFile("example.com", {});
    expect(out).toContain("$ORIGIN example.com.");
    expect(out).toContain("$TTL 3600");
  });

  it("A/AAAA: owner, ttl, type and value", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      A: [{ value: "203.0.113.5", ttl: 300 }],
      AAAA: [{ value: "2001:db8::1", ttl: 300 }],
    });
    expect(out).toContain("example.com.\t300\tA\t203.0.113.5");
    expect(out).toContain("example.com.\t300\tAAAA\t2001:db8::1");
  });

  it("CNAME: target becomes an FQDN with a trailing dot", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      CNAME: [{ value: "target.example.net", ttl: 120 }],
    });
    expect(out).toContain("example.com.\t120\tCNAME\ttarget.example.net.");
  });

  it("CNAME: does not double the trailing dot when already an FQDN", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      CNAME: [{ value: "target.example.net.", ttl: 120 }],
    });
    expect(out).toContain("example.com.\t120\tCNAME\ttarget.example.net.");
    expect(out).not.toContain("target.example.net..");
  });

  it("MX: 'priority hostname' with FQDN target", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      MX: [{ value: "20 mail.example.com", ttl: 3600 }],
    });
    expect(out).toContain("example.com.\t3600\tMX\t20 mail.example.com.");
  });

  it("MX: falls back to priority 10 when the value lacks a numeric priority", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      MX: [{ value: "mail2.example.com", ttl: 3600 }],
    });
    expect(out).toContain("example.com.\t3600\tMX\t10 mail2.example.com.");
  });

  it("TXT: value wrapped in quotes, with internal quotes escaped", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      TXT: [
        { value: "v=spf1 -all", ttl: 300 },
        { value: 'key="quoted"', ttl: 300 },
      ],
    });
    expect(out).toContain('example.com.\t300\tTXT\t"v=spf1 -all"');
    expect(out).toContain('example.com.\t300\tTXT\t"key=\\"quoted\\""');
  });

  it("excludes SOA and NS records even if present in byType", () => {
    const out = NetworkTools.buildZoneFile("example.com", {
      SOA: [{ value: "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600", ttl: 3600 }],
      NS: [{ value: "ns1.example.com", ttl: 3600 }],
      A: [{ value: "203.0.113.5", ttl: 300 }],
    });
    expect(out).not.toMatch(/\tSOA\t/);
    expect(out).not.toMatch(/\tNS\t/);
    expect(out).toContain("example.com.\t300\tA\t203.0.113.5");
  });

  it("empty byType → header only, without throwing", () => {
    let out;
    expect(() => {
      out = NetworkTools.buildZoneFile("example.com", {});
    }).not.toThrow();
    expect(out).toContain("$ORIGIN example.com.");
    // No record lines (only comments, directives and a blank line).
    expect(out).not.toMatch(/\t(A|AAAA|CNAME|MX|TXT|CAA)\t/);
  });
});

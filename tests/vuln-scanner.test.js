import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { buildOsvQueries, parseOsvBatchResponse, summarizeSeverity } = require("../detectors/vuln-scanner.js");

// Minimal tech object in the shape tech-detector emits.
const tech = (over) => ({ name: "?", version: null, implied: false, category: "x", ...over });

describe("buildOsvQueries", () => {
  it("includes a tech that has a version and a map entry (jQuery 1.8.3 → npm/jquery)", () => {
    const w = buildOsvQueries([tech({ name: "jQuery", version: "1.8.3" })]);
    expect(w).toEqual([
      {
        tech: "jQuery",
        version: "1.8.3",
        query: { version: "1.8.3", package: { name: "jquery", ecosystem: "npm" } },
      },
    ]);
  });

  it("skips a tech with no version (e.g. Cloudflare)", () => {
    expect(buildOsvQueries([tech({ name: "Cloudflare", version: null })])).toEqual([]);
    // Even a mapped tech is skipped when its version is missing/empty.
    expect(buildOsvQueries([tech({ name: "jQuery", version: null })])).toEqual([]);
    expect(buildOsvQueries([tech({ name: "jQuery", version: "  " })])).toEqual([]);
  });

  it("skips a tech marked implied:true even if it has a map entry", () => {
    expect(buildOsvQueries([tech({ name: "jQuery", version: "1.8.3", implied: true })])).toEqual([]);
  });

  it("skips a tech with no TECH_TO_OSV entry", () => {
    expect(buildOsvQueries([tech({ name: "Cloudflare", version: "2.0.0" })])).toEqual([]);
  });

  it("normalizes a leading 'v' (e.g. 'v3.2.1' → '3.2.1')", () => {
    const w = buildOsvQueries([tech({ name: "Angular", version: "v3.2.1" })]);
    expect(w[0].version).toBe("3.2.1");
    expect(w[0].query.version).toBe("3.2.1");
    expect(w[0].query.package).toEqual({ name: "@angular/core", ecosystem: "npm" });
  });

  it("normalizes by dropping a build/qualifier suffix", () => {
    const w = buildOsvQueries([tech({ name: "jQuery", version: "1.8.3-beta" })]);
    expect(w[0].version).toBe("1.8.3");
  });

  it("skips an item whose version isn't a valid dotted version after normalizing", () => {
    expect(buildOsvQueries([tech({ name: "jQuery", version: "5" })])).toEqual([]); // bare integer
    expect(buildOsvQueries([tech({ name: "jQuery", version: "latest" })])).toEqual([]);
  });

  it("returns wrappers carrying the original tech name and normalized version", () => {
    const w = buildOsvQueries([tech({ name: "Drupal", version: "v10.1.6" })]);
    expect(w[0].tech).toBe("Drupal");
    expect(w[0].version).toBe("10.1.6");
  });

  it("handles non-array input without throwing", () => {
    expect(buildOsvQueries(null)).toEqual([]);
    expect(buildOsvQueries(undefined)).toEqual([]);
  });
});

describe("parseOsvBatchResponse", () => {
  const wrappers = [
    { tech: "jQuery", version: "1.8.3", query: {} },
    { tech: "Angular", version: "3.2.1", query: {} },
  ];

  it("maps vulns back to the right tech by index", () => {
    const resp = {
      results: [
        { vulns: [{ id: "GHSA-aaa" }, { id: "CVE-2020-111" }] },
        { vulns: [{ id: "GHSA-bbb" }] },
      ],
    };
    expect(parseOsvBatchResponse(wrappers, resp)).toEqual([
      { tech: "jQuery", version: "1.8.3", vulnIds: ["GHSA-aaa", "CVE-2020-111"] },
      { tech: "Angular", version: "3.2.1", vulnIds: ["GHSA-bbb"] },
    ]);
  });

  it("omits techs whose result has no vulns", () => {
    const resp = { results: [{ vulns: [{ id: "GHSA-aaa" }] }, { vulns: [] }] };
    expect(parseOsvBatchResponse(wrappers, resp)).toEqual([
      { tech: "jQuery", version: "1.8.3", vulnIds: ["GHSA-aaa"] },
    ]);
  });

  it("omits techs whose result is missing/empty", () => {
    // Second result absent entirely, first has no vulns key.
    const resp = { results: [{}] };
    expect(parseOsvBatchResponse(wrappers, resp)).toEqual([]);
  });

  it("does not throw on a malformed results array (returns [])", () => {
    expect(parseOsvBatchResponse(wrappers, null)).toEqual([]);
    expect(parseOsvBatchResponse(wrappers, {})).toEqual([]);
    expect(parseOsvBatchResponse(wrappers, { results: "nope" })).toEqual([]);
    expect(parseOsvBatchResponse(null, { results: [] })).toEqual([]);
  });
});

describe("summarizeSeverity", () => {
  it("maps CVSS base scores to labels", () => {
    expect(summarizeSeverity(9.5)).toBe("critical");
    expect(summarizeSeverity(7.2)).toBe("high");
    expect(summarizeSeverity(5.0)).toBe("medium");
    expect(summarizeSeverity(1.1)).toBe("low");
    expect(summarizeSeverity(0)).toBe("unknown");
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// background.js is a service worker: it importScripts() detectors + logger and
// registers chrome.* listeners at load. Stub those so it can be required in Node.
// We use the REAL VulnScanner (set as a global, since importScripts is stubbed)
// so the correlation logic is exercised end-to-end; only fetch is mocked.
global.importScripts = () => {};
const noopListener = { addListener: () => {} };
global.chrome = {
  webRequest: { onResponseStarted: noopListener, onHeadersReceived: noopListener },
  tabs: { onRemoved: noopListener },
  runtime: { onMessage: noopListener },
};
global.Logger = { append: vi.fn() };
global.fetch = vi.fn();
global.VulnScanner = require("../detectors/vuln-scanner.js");

const { runVulnScan } = require("../background.js");

const jsonResp = (body, { ok = true, status = 200 } = {}) => ({ ok, status, json: async () => body });
const tech = (over) => ({ name: "?", version: null, implied: false, ...over });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("runVulnScan", () => {
  it("returns { ok: true, findings: [] } and makes NO fetch when no verifiable versions", async () => {
    const r = await runVulnScan([tech({ name: "Cloudflare", version: null })], 1);
    expect(r).toEqual({ ok: true, findings: [] });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("sends a querybatch POST with the correct body shape for a versioned tech", async () => {
    global.fetch.mockImplementation((url) =>
      Promise.resolve(
        String(url).includes("querybatch") ? jsonResp({ results: [{}] }) : jsonResp({})
      )
    );
    await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);

    const batchCall = global.fetch.mock.calls.find(([u]) => String(u).includes("querybatch"));
    expect(batchCall).toBeTruthy();
    const [url, opts] = batchCall;
    expect(url).toBe("https://api.osv.dev/v1/querybatch");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(opts.body)).toEqual({
      queries: [{ version: "1.8.3", package: { name: "jquery", ecosystem: "npm" } }],
    });
  });

  it("returns osv_error on a non-ok batch status", async () => {
    global.fetch.mockResolvedValue(jsonResp({}, { ok: false, status: 503 }));
    const r = await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);
    expect(r).toEqual({ ok: false, error: "osv_error", status: 503 });
  });

  it("returns network_error when the batch fetch throws", async () => {
    global.fetch.mockRejectedValue(new Error("connection reset"));
    const r = await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);
    expect(r).toEqual({ ok: false, error: "network_error", message: "connection reset" });
  });

  it("returns findings: [] when OSV reports no vulns", async () => {
    global.fetch.mockResolvedValue(jsonResp({ results: [{ vulns: [] }] }));
    const r = await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);
    expect(r).toEqual({ ok: true, findings: [] });
  });

  it("hydrates vuln detail and returns a finding with severity label + fixedVersion", async () => {
    const detail = {
      id: "GHSA-jq",
      summary: "XSS in jQuery",
      severity: [{ type: "CVSS_V3", score: "9.8" }],
      affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "1.9.0" }] }] }],
    };
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (u.includes("querybatch")) return Promise.resolve(jsonResp({ results: [{ vulns: [{ id: "GHSA-jq" }] }] }));
      if (u.includes("/vulns/GHSA-jq")) return Promise.resolve(jsonResp(detail));
      return Promise.resolve(jsonResp({}));
    });

    const r = await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);
    expect(r.ok).toBe(true);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ tech: "jQuery", version: "1.8.3", count: 1 });
    expect(r.findings[0].vulns[0]).toEqual({
      id: "GHSA-jq",
      summary: "XSS in jQuery",
      severity: "critical",
      score: 9.8,
      fixedVersion: "1.9.0",
    });
  });

  it("a single failed /vulns/{id} hydration does not fail the whole scan", async () => {
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (u.includes("querybatch")) return Promise.resolve(jsonResp({ results: [{ vulns: [{ id: "GHSA-x" }] }] }));
      if (u.includes("/vulns/")) return Promise.resolve(jsonResp({}, { ok: false, status: 500 }));
      return Promise.resolve(jsonResp({}));
    });

    const r = await runVulnScan([tech({ name: "jQuery", version: "1.8.3" })], 1);
    expect(r.ok).toBe(true);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].vulns[0]).toEqual({
      id: "GHSA-x",
      summary: "",
      severity: "unknown",
      score: null,
      fixedVersion: null,
    });
  });

  it("sorts findings highest-severity first", async () => {
    const batch = { results: [{ vulns: [{ id: "GHSA-ng" }] }, { vulns: [{ id: "GHSA-jq" }] }] };
    const details = {
      "GHSA-ng": { id: "GHSA-ng", summary: "minor", severity: [{ type: "CVSS_V3", score: "3.1" }] },
      "GHSA-jq": { id: "GHSA-jq", summary: "bad", severity: [{ type: "CVSS_V3", score: "9.8" }] },
    };
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (u.includes("querybatch")) return Promise.resolve(jsonResp(batch));
      const id = u.split("/vulns/")[1];
      return Promise.resolve(jsonResp(details[id]));
    });

    // Input order is Angular (low) then jQuery (critical); the result must flip.
    const r = await runVulnScan(
      [tech({ name: "Angular", version: "3.2.1" }), tech({ name: "jQuery", version: "1.8.3" })],
      1
    );
    expect(r.findings.map((f) => f.tech)).toEqual(["jQuery", "Angular"]);
    expect(r.findings[0].vulns[0].severity).toBe("critical");
    expect(r.findings[1].vulns[0].severity).toBe("low");
  });
});

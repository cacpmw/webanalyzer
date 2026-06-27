import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// background.js is a service worker: it importScripts() detectors + logger and
// registers chrome.* listeners at load. Stub those so it can be required in
// Node. storage.local is Map-backed so cache hits/writes can be asserted; only
// fetch is mocked.
global.importScripts = () => {};
const noopListener = { addListener: () => {} };
const localStore = new Map();
global.chrome = {
  webRequest: { onResponseStarted: noopListener, onHeadersReceived: noopListener },
  tabs: { onRemoved: noopListener },
  runtime: { onMessage: noopListener },
  storage: {
    local: {
      get: vi.fn(async (key) => (localStore.has(key) ? { [key]: localStore.get(key) } : {})),
      set: vi.fn(async (obj) => { for (const k of Object.keys(obj)) localStore.set(k, obj[k]); }),
    },
  },
};
global.Logger = { append: vi.fn() };
global.fetch = vi.fn();
global.VulnScanner = require("../detectors/vuln-scanner.js");

const { asnLookup, parseAsString } = require("../background.js");

const jsonResp = (body, { ok = true, status = 200 } = {}) => ({ ok, status, json: async () => body });

beforeEach(() => {
  vi.clearAllMocks();
  localStore.clear();
});

describe("parseAsString", () => {
  it("splits an AS-prefixed string into asn + org", () => {
    expect(parseAsString("AS13335 Cloudflare, Inc.")).toEqual({ asn: 13335, org: "Cloudflare, Inc." });
    expect(parseAsString("AS8075 Microsoft Corporation")).toEqual({ asn: 8075, org: "Microsoft Corporation" });
  });

  it("returns the original string as org when there is no AS prefix", () => {
    expect(parseAsString("Hetzner Online GmbH")).toEqual({ asn: null, org: "Hetzner Online GmbH" });
  });

  it("returns nulls for empty / garbage input", () => {
    expect(parseAsString("")).toEqual({ asn: null, org: null });
    expect(parseAsString("   ")).toEqual({ asn: null, org: null });
    expect(parseAsString(null)).toEqual({ asn: null, org: null });
    expect(parseAsString(undefined)).toEqual({ asn: null, org: null });
  });
});

describe("asnLookup", () => {
  it("returns the cached result without fetching when asncache:{ip} exists", async () => {
    localStore.set("asncache:1.2.3.4", { asn: 13335, org: "Cloudflare, Inc." });
    const r = await asnLookup("1.2.3.4", 1);
    expect(r).toEqual({ asn: 13335, org: "Cloudflare, Inc." });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("reads asn/org from ipwho.is connection fields", async () => {
    global.fetch.mockImplementation((url) =>
      Promise.resolve(
        String(url).includes("ipwho.is")
          ? jsonResp({ success: true, connection: { asn: 24940, org: "Hetzner Online GmbH", isp: "Hetzner" } })
          : jsonResp({})
      )
    );
    const r = await asnLookup("147.79.81.58", 1);
    expect(r).toEqual({ asn: 24940, org: "Hetzner Online GmbH" });
    expect(localStore.get("asncache:147.79.81.58")).toEqual({ asn: 24940, org: "Hetzner Online GmbH" });
  });

  it("falls back to ip-api when ipwho.is lacks org", async () => {
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (u.includes("ipwho.is")) return Promise.resolve(jsonResp({ success: true, connection: {} }));
      if (u.includes("ip-api.com"))
        return Promise.resolve(jsonResp({ status: "success", as: "AS8075 Microsoft Corporation", org: "Microsoft Azure" }));
      return Promise.resolve(jsonResp({}));
    });
    const r = await asnLookup("20.1.2.3", 1);
    // org prefers the clean `org` field; asn comes from the AS string.
    expect(r).toEqual({ asn: 8075, org: "Microsoft Azure" });
  });

  it("returns { asn:null, org:null } and does not throw when no provider yields data", async () => {
    global.fetch.mockResolvedValue(jsonResp({}, { ok: false, status: 503 }));
    const r = await asnLookup("9.9.9.9", 1);
    expect(r).toEqual({ asn: null, org: null });
    expect(global.chrome.storage.local.set).not.toHaveBeenCalled(); // never cache a miss
  });

  it("does not throw when a provider fetch rejects", async () => {
    global.fetch.mockRejectedValue(new Error("offline"));
    const r = await asnLookup("9.9.9.9", 1);
    expect(r).toEqual({ asn: null, org: null });
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// background.js is a service worker: it importScripts() detectors + logger and
// registers chrome.* listeners at load. Stub those so it can be required in
// Node. storage.local is backed by a plain object so "doesn't overwrite" cases
// can be asserted by inspecting it; only fetch + storage are mocked.
global.importScripts = () => {};
const noopListener = { addListener: () => {} };
let storageData = {};
global.chrome = {
  webRequest: { onResponseStarted: noopListener, onHeadersReceived: noopListener },
  tabs: { onRemoved: noopListener },
  runtime: { onMessage: noopListener },
  storage: {
    local: {
      get: vi.fn(async (key) => ({ [key]: storageData[key] })),
      set: vi.fn(async (obj) => { Object.assign(storageData, obj); }),
    },
  },
};
global.Logger = { append: vi.fn() };
global.fetch = vi.fn();
global.VulnScanner = require("../detectors/vuln-scanner.js");

const { validateSignatures, refreshSignatures } = require("../background.js");

const CACHE_KEY = "sigcache:v1";
const TTL_MS = 24 * 60 * 60 * 1000;

// A response whose body text is the JSON of `body` (refreshSignatures reads
// .text() then JSON.parses). `rawText` overrides the body with literal text.
const resp = (body, { ok = true, status = 200, rawText } = {}) => ({
  ok,
  status,
  text: async () => (rawText !== undefined ? rawText : JSON.stringify(body)),
});

const validRaw = {
  VNDA: { category: "Ecommerce", html: [{ $re: "cdn\\.vnda\\.com\\.br", flags: "i" }] },
};

beforeEach(() => {
  vi.clearAllMocks();
  storageData = {};
});

describe("validateSignatures", () => {
  it("accepts a real signature object (VNDA with html)", () => {
    expect(validateSignatures(validRaw)).toBe(true);
    // The actual shipped database must also validate.
    expect(validateSignatures(require("../detectors/signatures.json"))).toBe(true);
  });

  it("rejects an empty object", () => {
    expect(validateSignatures({})).toBe(false);
  });

  it("rejects an array", () => {
    expect(validateSignatures([{ category: "x" }])).toBe(false);
  });

  it("rejects a string / a parsed-404-HTML-ish value", () => {
    expect(validateSignatures("404: Not Found")).toBe(false);
    expect(validateSignatures(null)).toBe(false);
    expect(validateSignatures(undefined)).toBe(false);
  });

  it("rejects an object whose entries lack any known signature field", () => {
    expect(validateSignatures({ Foo: { bar: 1, baz: 2 } })).toBe(false);
    // One bad entry among good ones still fails (strict).
    expect(validateSignatures({ VNDA: { html: [] }, Foo: { bar: 1 } })).toBe(false);
  });
});

describe("refreshSignatures", () => {
  it("returns cached data without fetching when the cache is fresh", async () => {
    storageData[CACHE_KEY] = { fetchedAt: Date.now(), data: validRaw };
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("fetches and stores when the cache is absent", async () => {
    global.fetch.mockResolvedValue(resp(validRaw));
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(storageData[CACHE_KEY].data).toEqual(validRaw);
  });

  it("fetches when the cache is stale (older than the TTL)", async () => {
    storageData[CACHE_KEY] = { fetchedAt: Date.now() - 2 * TTL_MS, data: { Old: { html: [] } } };
    global.fetch.mockResolvedValue(resp(validRaw));
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it("on HTTP non-ok, returns existing cache and does NOT overwrite it", async () => {
    const existing = { fetchedAt: Date.now() - 2 * TTL_MS, data: validRaw };
    storageData[CACHE_KEY] = existing;
    global.fetch.mockResolvedValue(resp(null, { ok: false, status: 500 }));
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.chrome.storage.local.set).not.toHaveBeenCalled();
    expect(storageData[CACHE_KEY]).toBe(existing);
  });

  it("on invalid shape, returns existing cache and does NOT store the bad data", async () => {
    const existing = { fetchedAt: Date.now() - 2 * TTL_MS, data: validRaw };
    storageData[CACHE_KEY] = existing;
    global.fetch.mockResolvedValue(resp({})); // empty object → invalid
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.chrome.storage.local.set).not.toHaveBeenCalled();
    expect(storageData[CACHE_KEY]).toBe(existing);
  });

  it("on a parse error (e.g. 404 HTML body), returns existing cache and stores nothing", async () => {
    const existing = { fetchedAt: Date.now() - 2 * TTL_MS, data: validRaw };
    storageData[CACHE_KEY] = existing;
    global.fetch.mockResolvedValue(resp(null, { rawText: "<html>404</html>" }));
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
    expect(global.chrome.storage.local.set).not.toHaveBeenCalled();
  });

  it("on fetch throw, returns existing cache and does not throw", async () => {
    storageData[CACHE_KEY] = { fetchedAt: Date.now() - 2 * TTL_MS, data: validRaw };
    global.fetch.mockRejectedValue(new Error("connection reset"));
    const out = await refreshSignatures(false);
    expect(out).toEqual(validRaw);
  });

  it("on fetch throw with no cache, returns null and does not throw", async () => {
    global.fetch.mockRejectedValue(new Error("offline"));
    const out = await refreshSignatures(false);
    expect(out).toBeNull();
  });
});

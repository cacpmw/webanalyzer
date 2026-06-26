import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// In-memory fake of chrome.storage.session: get(key)->{[key]:val}, set(obj), remove(key).
// Logger reads global `chrome` at call time, so a fresh store per test is enough.
function makeSession() {
  const store = new Map();
  return {
    get: async (key) => (store.has(key) ? { [key]: store.get(key) } : {}),
    set: async (obj) => { for (const k of Object.keys(obj)) store.set(k, obj[k]); },
    remove: async (key) => { store.delete(key); },
    _store: store,
  };
}

global.chrome = { storage: { session: makeSession() } };
const Logger = require("../logger.js");

const messages = (entries) => entries.map((e) => e.message);

beforeEach(() => {
  global.chrome.storage.session = makeSession();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("Logger.append — routing", () => {
  it("writes a tab event under log_<tabId>", async () => {
    await Logger.append(123, "headers", "captured");
    expect(global.chrome.storage.session._store.get("log_123").entries).toHaveLength(1);
    expect(global.chrome.storage.session._store.has("log_global")).toBe(false);
  });

  it("writes a tab-less event under log_global instead of dropping it", async () => {
    await Logger.append(null, "sig", "remote → updated");
    expect(global.chrome.storage.session._store.has("log_123")).toBe(false);
    const g = global.chrome.storage.session._store.get("log_global").entries;
    expect(messages(g)).toEqual(["remote → updated"]);
  });
});

describe("Logger.get — merging", () => {
  it("returns entries from BOTH the tab bucket and the global bucket", async () => {
    await Logger.append(123, "headers", "tab-event");
    await Logger.append(null, "sig", "global-event");
    const out = await Logger.get(123);
    expect(messages(out)).toContain("tab-event");
    expect(messages(out)).toContain("global-event");
  });

  it("merges tab + global entries sorted ascending by timestamp", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2020-01-01T00:00:01.000Z"));
    await Logger.append(123, "headers", "first-tab");
    vi.setSystemTime(new Date("2020-01-01T00:00:02.000Z"));
    await Logger.append(null, "sig", "mid-global");
    vi.setSystemTime(new Date("2020-01-01T00:00:03.000Z"));
    await Logger.append(123, "headers", "last-tab");

    const out = await Logger.get(123);
    expect(messages(out)).toEqual(["first-tab", "mid-global", "last-tab"]);
  });

  it("get(null) returns only the global bucket", async () => {
    await Logger.append(123, "headers", "tab-event");
    await Logger.append(null, "sig", "global-event");
    const out = await Logger.get(null);
    expect(messages(out)).toEqual(["global-event"]);
  });
});

describe("Logger.clear — isolation", () => {
  it("clears the per-tab bucket but leaves the global bucket intact", async () => {
    await Logger.append(123, "headers", "tab-event");
    await Logger.append(null, "sig", "global-event");
    await Logger.clear(123);
    expect(global.chrome.storage.session._store.has("log_123")).toBe(false);
    const out = await Logger.get(123);
    expect(messages(out)).toEqual(["global-event"]);
  });
});

describe("Logger — robustness", () => {
  it("returns [] for a tab with no entries and an empty global bucket", async () => {
    expect(await Logger.get(999)).toEqual([]);
  });

  it("never throws into the caller when storage fails", async () => {
    global.chrome.storage.session = {
      get: async () => { throw new Error("boom"); },
      set: async () => { throw new Error("boom"); },
      remove: async () => { throw new Error("boom"); },
    };
    await expect(Logger.append(1, "x", "y")).resolves.toBeUndefined();
    await expect(Logger.get(1)).resolves.toEqual([]);
    await expect(Logger.clear(1)).resolves.toBeUndefined();
  });

  it("applies MAX_ENTRIES trimming to the global bucket (keeps the last 500)", async () => {
    for (let i = 0; i < 600; i++) await Logger.append(null, "sig", `m${i}`);
    const out = await Logger.get(null);
    expect(out).toHaveLength(500);
    expect(out[0].message).toBe("m100");
    expect(out[499].message).toBe("m599");
  });
});

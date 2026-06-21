import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// background.js is a service worker: at load it calls importScripts(), registers
// chrome.* listeners, and logs through a global `Logger` (provided by
// importScripts in the browser). Stub those so the module can be required in
// Node — we only exercise the exported sendToN8n. (vi.mock on logger.js can't
// intercept an importScripts-injected global, so Logger is stubbed directly.)
global.importScripts = () => {};
const noopListener = { addListener: () => {} };
global.chrome = {
  webRequest: { onResponseStarted: noopListener, onHeadersReceived: noopListener },
  tabs: { onRemoved: noopListener },
  runtime: { onMessage: noopListener },
};
global.Logger = { append: vi.fn() };
global.fetch = vi.fn();

const { sendToN8n } = require("../background.js");

const WEBHOOK = "https://n8n.example.com/webhook/abc123";

// Minimal fake Response with controllable ok/status/json/text.
const mockResponse = ({ ok = true, status = 200, json, text } = {}) => ({
  ok,
  status,
  json: json || (async () => ({})),
  text: text || (async () => ""),
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("sendToN8n", () => {
  it("returns missing_webhook_url error when webhookUrl is empty", async () => {
    const r = await sendToN8n({ a: 1 }, "", "tok", 1);
    expect(r).toEqual({ ok: false, error: "missing_webhook_url" });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("returns missing_webhook_url error when webhookUrl is not a string", async () => {
    const r = await sendToN8n({ a: 1 }, null, "tok", 1);
    expect(r).toEqual({ ok: false, error: "missing_webhook_url" });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("sends a POST request to the correct webhookUrl", async () => {
    global.fetch.mockResolvedValue(mockResponse({ json: async () => ({ report: "ok" }) }));
    await sendToN8n({ a: 1 }, WEBHOOK, "tok", 1);
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe(WEBHOOK);
    expect(opts.method).toBe("POST");
    expect(opts.body).toBe(JSON.stringify({ a: 1 }));
  });

  it("includes X-Auth-Token header when authToken is provided", async () => {
    global.fetch.mockResolvedValue(mockResponse({ json: async () => ({}) }));
    await sendToN8n({ a: 1 }, WEBHOOK, "secret-token", 1);
    const [, opts] = global.fetch.mock.calls[0];
    expect(opts.headers["X-Auth-Token"]).toBe("secret-token");
    expect(opts.headers["Content-Type"]).toBe("application/json");
  });

  it("omits X-Auth-Token header when authToken is empty", async () => {
    global.fetch.mockResolvedValue(mockResponse({ json: async () => ({}) }));
    await sendToN8n({ a: 1 }, WEBHOOK, "", 1);
    const [, opts] = global.fetch.mock.calls[0];
    expect("X-Auth-Token" in opts.headers).toBe(false);
  });

  it("returns ok: true and parsed data on a successful JSON response", async () => {
    const payload = { report: "# Report", score: 9 };
    global.fetch.mockResolvedValue(mockResponse({ json: async () => payload }));
    const r = await sendToN8n({ a: 1 }, WEBHOOK, "tok", 1);
    expect(r).toEqual({ ok: true, data: payload });
  });

  it("returns ok: true and raw text as report when response is not valid JSON", async () => {
    global.fetch.mockResolvedValue(
      mockResponse({
        json: async () => {
          throw new Error("Unexpected token");
        },
        text: async () => "plain text report",
      })
    );
    const r = await sendToN8n({ a: 1 }, WEBHOOK, "tok", 1);
    expect(r).toEqual({ ok: true, data: { report: "plain text report" } });
  });

  it("returns http_error when response status is outside 200-299", async () => {
    global.fetch.mockResolvedValue(mockResponse({ ok: false, status: 500 }));
    const r = await sendToN8n({ a: 1 }, WEBHOOK, "tok", 1);
    expect(r).toEqual({ ok: false, error: "http_error", status: 500 });
  });

  it("returns network_error when fetch throws", async () => {
    global.fetch.mockRejectedValue(new Error("connection refused"));
    const r = await sendToN8n({ a: 1 }, WEBHOOK, "tok", 1);
    expect(r).toEqual({ ok: false, error: "network_error", message: "connection refused" });
  });
});

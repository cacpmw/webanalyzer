import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// popup.js is a classic browser script: at load it builds an `els` map via
// document.getElementById and registers listeners. Stub the globals it touches
// at load so it can be required in Node — we only exercise the two exported pure
// functions. Any element method returns [] so chained `.forEach` is harmless.
const makeEl = () =>
  new Proxy(
    { style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} } },
    { get: (t, p) => (p in t ? t[p] : () => []) }
  );

global.document = new Proxy(
  { body: makeEl(), title: "" },
  {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (prop === "getElementById") return () => makeEl();
      return () => [];
    },
  }
);
global.chrome = {
  storage: { local: { get() {}, set() {} } },
  runtime: { sendMessage() {}, openOptionsPage() {} },
  tabs: { query() {}, create() {} },
};

const { aiStateMap, aiErrorMessage } = require("../popup.js");

const STATES = ["actions", "loading", "result", "error", "unconfigured", "mode-select"];

describe("aiStateMap", () => {
  STATES.forEach((target) => {
    it(`shows only '${target}' when which is '${target}'`, () => {
      const map = aiStateMap(target);
      expect(map[target]).toBe(false); // visible
      STATES.filter((s) => s !== target).forEach((other) => {
        expect(map[other]).toBe(true); // hidden
      });
    });
  });

  it("hides all states for an unknown value", () => {
    const map = aiStateMap("nope");
    STATES.forEach((s) => expect(map[s]).toBe(true));
  });
});

describe("aiErrorMessage", () => {
  const t = {
    missing_webhook_url: "no webhook",
    http_error: "http error",
    network_error: "network error",
    unknown: "unknown error",
  };

  it("returns the matching translation for 'missing_webhook_url'", () => {
    expect(aiErrorMessage("missing_webhook_url", t)).toBe("no webhook");
  });

  it("returns the matching translation for 'http_error'", () => {
    expect(aiErrorMessage("http_error", t)).toBe("http error");
  });

  it("returns the matching translation for 'network_error'", () => {
    expect(aiErrorMessage("network_error", t)).toBe("network error");
  });

  it("returns the 'unknown' fallback for an unrecognized error code", () => {
    expect(aiErrorMessage("weird_code", t)).toBe("unknown error");
  });

  it("returns the error code itself when translations object has no 'unknown' key", () => {
    expect(aiErrorMessage("weird_code", { http_error: "http error" })).toBe("weird_code");
  });
});

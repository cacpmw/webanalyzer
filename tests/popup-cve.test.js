import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// popup.js is a classic browser script that touches document at load. Stub the
// globals it reads so it can be required in Node; we only use the pure exports.
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

const { cveStateMap, cveSeverityClass } = require("../popup.js");

const STATES = ["loading", "result", "clean", "none", "error"];

describe("cveStateMap", () => {
  STATES.forEach((target) => {
    it(`shows only '${target}' when which is '${target}'`, () => {
      const map = cveStateMap(target);
      expect(map[target]).toBe(false); // visible
      STATES.filter((s) => s !== target).forEach((other) => {
        expect(map[other]).toBe(true); // hidden
      });
    });
  });

  it("hides everything for an unknown value", () => {
    const map = cveStateMap("nope");
    STATES.forEach((s) => expect(map[s]).toBe(true));
  });
});

describe("cveSeverityClass", () => {
  it("maps known severities to their class", () => {
    expect(cveSeverityClass("critical")).toBe("sev-critical");
    expect(cveSeverityClass("high")).toBe("sev-high");
    expect(cveSeverityClass("medium")).toBe("sev-medium");
    expect(cveSeverityClass("low")).toBe("sev-low");
  });

  it("falls back to sev-unknown for 'unknown' or any unrecognized value", () => {
    expect(cveSeverityClass("unknown")).toBe("sev-unknown");
    expect(cveSeverityClass("weird")).toBe("sev-unknown");
    expect(cveSeverityClass("")).toBe("sev-unknown");
    expect(cveSeverityClass(undefined)).toBe("sev-unknown");
  });
});

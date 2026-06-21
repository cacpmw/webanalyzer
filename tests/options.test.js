import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// Import ONLY the exported pure function. options.js guards its DOM/chrome
// bootstrap behind a `typeof document` check, so requiring it in Node is safe.
const { updateCustomUrlVisibility } = require("../options.js");

// No real DOM — a plain object with a style bag is all the function touches.
const makeGroup = () => ({ style: { display: "none" } });

describe("updateCustomUrlVisibility", () => {
  it("shows the group when provider is 'custom'", () => {
    const group = makeGroup();
    updateCustomUrlVisibility("custom", group);
    expect(group.style.display).toBe("");
  });

  it("hides the group when provider is 'openai'", () => {
    const group = makeGroup();
    updateCustomUrlVisibility("openai", group);
    expect(group.style.display).toBe("none");
  });

  it("hides the group when provider is 'anthropic'", () => {
    const group = makeGroup();
    updateCustomUrlVisibility("anthropic", group);
    expect(group.style.display).toBe("none");
  });

  it("hides the group when provider is 'gemini'", () => {
    const group = makeGroup();
    updateCustomUrlVisibility("gemini", group);
    expect(group.style.display).toBe("none");
  });

  it("hides the group for any unknown provider value", () => {
    const group = makeGroup();
    updateCustomUrlVisibility("something-else", group);
    expect(group.style.display).toBe("none");
  });
});

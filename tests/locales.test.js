import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const localesDir = resolve(here, "..", "_locales");

const load = (locale) =>
  JSON.parse(readFileSync(resolve(localesDir, locale, "messages.json"), "utf8"));

// en is the default_locale (the source of truth Chrome falls back to).
const DEFAULT_LOCALE = "en";
const en = load(DEFAULT_LOCALE);
const enKeys = Object.keys(en).sort();

// Validate every other locale folder against en, so new locales are covered
// automatically and any future key can't silently break a translation.
const otherLocales = readdirSync(localesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory() && d.name !== DEFAULT_LOCALE)
  .map((d) => d.name);

// Map each key that has placeholders to its (sorted) placeholder names.
const placeholdersOf = (msgs) => {
  const out = {};
  for (const [k, v] of Object.entries(msgs)) {
    if (v.placeholders) out[k] = Object.keys(v.placeholders).sort();
  }
  return out;
};
const enPlaceholders = placeholdersOf(en);

describe("locale completeness", () => {
  it("ships the German (de) locale", () => {
    expect(otherLocales).toContain("de");
  });

  describe.each(otherLocales)("locale '%s'", (locale) => {
    const msgs = load(locale);

    it("has exactly the same keys as the default locale (100% coverage)", () => {
      expect(Object.keys(msgs).sort()).toEqual(enKeys);
    });

    it("has no empty messages", () => {
      const empty = Object.entries(msgs)
        .filter(([, v]) => !v.message || !String(v.message).trim())
        .map(([k]) => k);
      expect(empty).toEqual([]);
    });

    it("preserves the same placeholder names as the default locale", () => {
      expect(placeholdersOf(msgs)).toEqual(enPlaceholders);
    });
  });
});

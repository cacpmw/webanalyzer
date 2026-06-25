// vuln-scanner.js
// Passive vulnerability correlation: maps technologies detected WITH a
// trustworthy version to OSV.dev package identifiers, builds the /v1/querybatch
// payload, and interprets the response. Pure logic only — no network, no DOM,
// no chrome.* — so it runs anywhere and stays unit-testable.
//
// Principle: only items with a confident, real version are ever queried. Items
// without a version (or only inferred) are skipped — never guessed — because
// false positives are the worst outcome for a security signal.

const VulnScanner = (() => {
  // The single extension point for new coverage: a detected tech name (as
  // tech-detector emits it) → how OSV.dev identifies its package.
  // WordPress plugins/themes are intentionally absent — content.js captures
  // their slug but not a version, and we never query without a confident version.
  const TECH_TO_OSV = {
    "jQuery":    { ecosystem: "npm", package: "jquery" },
    "WordPress": { ecosystem: "Packagist", package: "wordpress/wordpress" },
    "Angular":   { ecosystem: "npm", package: "@angular/core" },
    "Drupal":    { ecosystem: "Packagist", package: "drupal/core" },
  };

  // Keep only the dotted numeric core (strip a leading "v" and any build/qualifier
  // suffix). Requires at least major.minor, so a bare integer — a common
  // mis-detection — can't trigger a query. Returns null when there's no valid core.
  function normalizeVersion(raw) {
    if (raw == null) return null;
    const m = String(raw).trim().match(/^v?(\d+\.\d+(?:\.\d+)*)/);
    return m ? m[1] : null;
  }

  function buildOsvQueries(technologies) {
    const list = Array.isArray(technologies) ? technologies : [];
    const wrappers = [];
    list.forEach((tech) => {
      if (!tech || tech.implied) return; // implied = inferred, not version-trusted
      const map = TECH_TO_OSV[tech.name];
      if (!map) return;
      if (tech.version == null || String(tech.version).trim() === "") return;
      const version = normalizeVersion(tech.version);
      if (!version) return;
      wrappers.push({
        tech: tech.name,
        version,
        query: {
          version,
          package: { name: map.package, ecosystem: map.ecosystem },
        },
      });
    });
    return wrappers;
  }

  function parseOsvBatchResponse(wrappers, osvResponse) {
    const results =
      osvResponse && Array.isArray(osvResponse.results) ? osvResponse.results : [];
    const list = Array.isArray(wrappers) ? wrappers : [];
    const findings = [];
    list.forEach((w, i) => {
      const r = results[i];
      const vulns = r && Array.isArray(r.vulns) ? r.vulns : [];
      if (!vulns.length) return; // omit clean items
      findings.push({
        tech: w.tech,
        version: w.version,
        vulnIds: vulns.map((v) => v && v.id).filter(Boolean),
      });
    });
    return findings;
  }

  function summarizeSeverity(cvssScore) {
    const s = Number(cvssScore);
    if (!(s > 0)) return "unknown";
    if (s >= 9.0) return "critical";
    if (s >= 7.0) return "high";
    if (s >= 4.0) return "medium";
    return "low";
  }

  return {
    TECH_TO_OSV,
    buildOsvQueries,
    parseOsvBatchResponse,
    summarizeSeverity,
  };
})();

if (typeof window !== "undefined") window.VulnScanner = VulnScanner;
if (typeof module !== "undefined" && module.exports) module.exports = VulnScanner;

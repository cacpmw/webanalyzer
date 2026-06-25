#!/usr/bin/env node
// scripts/package.cjs
// Builds the Chrome Web Store ZIP from an explicit runtime allowlist, preserving
// the directory tree: manifest.json sits at the ZIP root with detectors/,
// _locales/en/, _locales/pt_BR/ and images/ below it (no flattening, no extra
// wrapper folder), which is exactly what Chrome expects.
//
// Excluded — as a consequence of the allowlist (these are not runtime files):
//   tests/, node_modules/, package.json, package-lock.json, .gitignore,
//   README.md, PRIVACY.md, LICENSE, images/nofile.txt, any vitest.config.*,
//   and .DS_Store.
//
// Integrity gate: before zipping, every icon referenced by manifest.json must
// exist on disk. A missing icon makes the extension fail to load and the store
// reject the upload, so this aborts with a clear message rather than producing a
// silently-broken ZIP.

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
process.chdir(root);

const manifest = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
const version = manifest.version;

// Exact runtime allowlist. Paths are relative to the project root so `zip`
// stores them with the same structure inside the archive.
const ALLOWLIST = [
  "manifest.json",
  "background.js",
  "content.js",
  "logger.js",
  "popup.js",
  "popup.html",
  "popup.css",
  "options.js",
  "options.html",
  "design-system.css",
  "detectors/tech-detector.js",
  "detectors/network-detector.js",
  "detectors/vuln-scanner.js",
  "_locales/en/messages.json",
  "_locales/pt_BR/messages.json",
  "_locales/de/messages.json",
  "images/icon-16.png",
  "images/icon-48.png",
  "images/icon-128.png",
];

// --- Manifest integrity: every referenced icon must exist on disk. ---
const iconPaths = Object.values(manifest.icons || {});
const missingIcons = iconPaths.filter((p) => !fs.existsSync(p));
if (missingIcons.length) {
  console.error("✖ manifest.json references icon files missing on disk:");
  missingIcons.forEach((p) => console.error(`    - ${p}`));
  console.error("\nThe extension would fail to load and the Web Store would reject the upload.");
  console.error("Add the missing icon(s), then run `npm run package` again.");
  process.exit(1);
}

// --- Every allowlisted runtime file must exist too. ---
const missing = ALLOWLIST.filter((p) => !fs.existsSync(p));
if (missing.length) {
  console.error("✖ Allowlisted runtime files are missing on disk:");
  missing.forEach((p) => console.error(`    - ${p}`));
  process.exit(1);
}

// --- Build the ZIP. Native `zip` with an explicit file list preserves the tree;
//     -X drops macOS extra attributes and we still exclude any stray .DS_Store. ---
const zipName = `webanalyzer-v${version}.zip`;
fs.rmSync(zipName, { force: true }); // zip appends by default — start fresh

execFileSync("zip", ["-q", "-X", zipName, ...ALLOWLIST, "-x", "*.DS_Store"], {
  stdio: "inherit",
});

const sizeKb = (fs.statSync(zipName).size / 1024).toFixed(1);
console.log(`✔ Built ${zipName} (${sizeKb} KB) with ${ALLOWLIST.length} files.`);

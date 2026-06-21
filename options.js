// options.js
// Persists the integration settings (n8n webhook + direct LLM API) in
// chrome.storage.local. Read by the AI report client in Phase 2; stored locally
// per browser, so no secret ships in the package.

// Pure visibility rule for the custom-URL field — DOM-free so it can be
// unit-tested in isolation (the rest of this file touches document/chrome).
function updateCustomUrlVisibility(provider, groupElement) {
  groupElement.style.display = provider === "custom" ? "" : "none";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { updateCustomUrlVisibility };
}

// i18n: Chrome serves the locale matching the browser UI language, falling
// back to default_locale (en) for unsupported languages.
function tr(key) {
  return chrome.i18n.getMessage(key) || key;
}

function localizeHtml() {
  document.title = `WebAnalyzer · ${tr("opt_settings_word")}`;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const m = tr(el.dataset.i18n);
    if (m) el.textContent = m;
  });
}

let fields;
let customUrlGroup;
let saveBtn;
let saved;

function load() {
  chrome.storage.local.get(
    ["webhookUrl", "authToken", "llmProvider", "llmApiKey", "llmCustomUrl"],
    (cfg) => {
      if (cfg.webhookUrl) fields.webhookUrl.value = cfg.webhookUrl;
      if (cfg.authToken) fields.authToken.value = cfg.authToken;
      if (cfg.llmProvider) fields.llmProvider.value = cfg.llmProvider;
      if (cfg.llmApiKey) fields.llmApiKey.value = cfg.llmApiKey;
      if (cfg.llmCustomUrl) fields.llmCustomUrl.value = cfg.llmCustomUrl;
      updateCustomUrlVisibility(fields.llmProvider.value, customUrlGroup);
    }
  );
}

function save() {
  const cfg = {
    webhookUrl: fields.webhookUrl.value.trim(),
    authToken: fields.authToken.value.trim(),
    llmProvider: fields.llmProvider.value,
    llmApiKey: fields.llmApiKey.value.trim(),
    llmCustomUrl: fields.llmCustomUrl.value.trim(),
  };
  chrome.storage.local.set(cfg, () => {
    saved.classList.add("show");
    setTimeout(() => saved.classList.remove("show"), 1600);
  });
}

// Browser-only wiring. Guarded so this file can be required in Node (tests)
// without touching document/chrome at import time.
if (typeof document !== "undefined" && typeof chrome !== "undefined") {
  fields = {
    webhookUrl: document.getElementById("webhookUrl"),
    authToken: document.getElementById("authToken"),
    llmProvider: document.getElementById("llmProvider"),
    llmApiKey: document.getElementById("llmApiKey"),
    llmCustomUrl: document.getElementById("llmCustomUrl"),
  };
  customUrlGroup = document.getElementById("customUrlGroup");
  saveBtn = document.getElementById("saveBtn");
  saved = document.getElementById("saved");

  saveBtn.addEventListener("click", save);
  fields.llmProvider.addEventListener("change", () => {
    updateCustomUrlVisibility(fields.llmProvider.value, customUrlGroup);
  });
  document.addEventListener("DOMContentLoaded", () => {
    localizeHtml();
    load();
  });
}

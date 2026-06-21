// options.js
// Persists the n8n integration settings in chrome.storage.local.
// These are read by the n8n client in Phase 2. Stored locally per browser;
// each team member configures their own, so no secret ships in the package.

const fields = {
  webhookUrl: document.getElementById("webhookUrl"),
  authToken: document.getElementById("authToken"),
};
const saveBtn = document.getElementById("saveBtn");
const saved = document.getElementById("saved");

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

function load() {
  chrome.storage.local.get(["webhookUrl", "authToken"], (cfg) => {
    if (cfg.webhookUrl) fields.webhookUrl.value = cfg.webhookUrl;
    if (cfg.authToken) fields.authToken.value = cfg.authToken;
  });
}

function save() {
  const cfg = {
    webhookUrl: fields.webhookUrl.value.trim(),
    authToken: fields.authToken.value.trim(),
  };
  chrome.storage.local.set(cfg, () => {
    saved.classList.add("show");
    setTimeout(() => saved.classList.remove("show"), 1600);
  });
}

saveBtn.addEventListener("click", save);
document.addEventListener("DOMContentLoaded", () => {
  localizeHtml();
  load();
});

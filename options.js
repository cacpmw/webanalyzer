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
document.addEventListener("DOMContentLoaded", load);

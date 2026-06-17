// logger.js
// Lightweight diagnostic logger shared between the background worker and the
// popup. Entries are kept per-tab in chrome.storage.session, so they survive
// the worker sleeping but are cleared when the browser closes (no unbounded
// growth). The popup reads them to build a downloadable log file on demand.

const Logger = (() => {
  const KEY = (tabId) => `log_${tabId}`;
  const MAX_ENTRIES = 500; // hard cap so a session can never bloat memory

  async function append(tabId, category, message, data) {
    if (tabId == null) return;
    const entry = {
      t: new Date().toISOString(),
      category,
      message,
      data: data === undefined ? null : data,
    };
    try {
      const k = KEY(tabId);
      const cur = await chrome.storage.session.get(k);
      const list = (cur[k] && cur[k].entries) || [];
      list.push(entry);
      // Keep only the most recent MAX_ENTRIES.
      const trimmed = list.slice(-MAX_ENTRIES);
      await chrome.storage.session.set({ [k]: { entries: trimmed } });
    } catch (e) {
      // Logging must never throw into the caller.
    }
  }

  async function get(tabId) {
    try {
      const k = KEY(tabId);
      const cur = await chrome.storage.session.get(k);
      return (cur[k] && cur[k].entries) || [];
    } catch (e) {
      return [];
    }
  }

  async function clear(tabId) {
    try {
      await chrome.storage.session.remove(KEY(tabId));
    } catch (e) {}
  }

  return { append, get, clear };
})();

if (typeof window !== "undefined") window.Logger = Logger;
if (typeof self !== "undefined") self.Logger = Logger;
if (typeof module !== "undefined" && module.exports) module.exports = Logger;

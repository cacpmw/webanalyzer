// logger.js
// Lightweight diagnostic logger shared between the background worker and the
// popup. Entries are kept per-tab in chrome.storage.session, so they survive
// the worker sleeping but are cleared when the browser closes (no unbounded
// growth). The popup reads them to build a downloadable log file on demand.

const Logger = (() => {
  const KEY = (tabId) => `log_${tabId}`;
  const GLOBAL_KEY = "log_global"; // tab-less events (e.g. remote signature fetch)
  const MAX_ENTRIES = 500; // hard cap so a session can never bloat memory

  async function readEntries(k) {
    const cur = await chrome.storage.session.get(k);
    return (cur[k] && cur[k].entries) || [];
  }

  async function append(tabId, category, message, data) {
    // Tab-less events (tabId == null) go to a shared global bucket instead of
    // being dropped, so background diagnostics like remote signature fetches
    // still reach the exported log.
    const k = tabId == null ? GLOBAL_KEY : KEY(tabId);
    const entry = {
      t: new Date().toISOString(),
      category,
      message,
      data: data === undefined ? null : data,
    };
    try {
      const list = await readEntries(k);
      list.push(entry);
      // Keep only the most recent MAX_ENTRIES (applies to the global bucket too).
      const trimmed = list.slice(-MAX_ENTRIES);
      await chrome.storage.session.set({ [k]: { entries: trimmed } });
    } catch (e) {
      // Logging must never throw into the caller.
    }
  }

  async function get(tabId) {
    try {
      const global = await readEntries(GLOBAL_KEY);
      const perTab = tabId == null ? [] : await readEntries(KEY(tabId));
      // Merge tab + global events into one chronological stream. ISO timestamps
      // sort lexicographically, which is chronological.
      return perTab.concat(global).sort((a, b) => (a.t < b.t ? -1 : a.t > b.t ? 1 : 0));
    } catch (e) {
      return [];
    }
  }

  async function clear(tabId) {
    try {
      // Only the per-tab bucket is cleared; the global bucket is intentionally
      // left intact, since its events may relate to other tabs/sessions.
      await chrome.storage.session.remove(KEY(tabId));
    } catch (e) {}
  }

  return { append, get, clear };
})();

if (typeof window !== "undefined") window.Logger = Logger;
if (typeof self !== "undefined") self.Logger = Logger;
if (typeof module !== "undefined" && module.exports) module.exports = Logger;

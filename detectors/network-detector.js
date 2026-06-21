// network-detector.js
// Network reconnaissance helpers: DNS record lookup (all types) and passive
// subdomain discovery via Certificate Transparency logs. The actual network
// calls happen in the background worker (CORS-friendly); this module holds the
// record-type metadata and the parsing/formatting helpers.

const NetworkTools = (() => {
  // DNS record types we query, with their numeric codes (for DoH JSON `type`)
  // and a short human label. Order here is the display order.
  const RECORD_TYPES = [
    { type: "A", code: 1, label: "IPv4 address" },
    { type: "AAAA", code: 28, label: "IPv6 address" },
    { type: "CNAME", code: 5, label: "Canonical name" },
    { type: "MX", code: 15, label: "Mail server" },
    { type: "NS", code: 2, label: "Nameserver" },
    { type: "TXT", code: 16, label: "Text record" },
    { type: "SOA", code: 6, label: "Start of authority" },
    { type: "CAA", code: 257, label: "Cert authority" },
  ];

  // Map numeric DoH answer type back to a name, for safety when displaying.
  const CODE_TO_TYPE = RECORD_TYPES.reduce((acc, r) => {
    acc[r.code] = r.type;
    return acc;
  }, {});

  // Normalize a DoH JSON answer array into clean {type, value, ttl} entries.
  function parseAnswers(answers, expectedType) {
    if (!Array.isArray(answers)) return [];
    return answers
      .filter((a) => CODE_TO_TYPE[a.type] === expectedType)
      .map((a) => ({
        type: expectedType,
        value: cleanValue(expectedType, a.data),
        ttl: a.TTL || null,
      }));
  }

  // DoH returns some records with quirks (trailing dots, quoted TXT, etc.)
  function cleanValue(type, data) {
    if (data == null) return "";
    let v = String(data).trim();
    if (type === "TXT") {
      // TXT values come wrapped in quotes, sometimes split into chunks.
      v = v.replace(/^"|"$/g, "").replace(/"\s+"/g, "");
    }
    if ((type === "NS" || type === "CNAME" || type === "MX") && v.endsWith(".")) {
      v = v.slice(0, -1);
    }
    if (type === "MX") {
      // MX data is "priority hostname" — keep as-is but tidy trailing dot.
      v = v.replace(/\.$/, "");
    }
    return v;
  }

  // Extract registrable domain (naive: last two labels, or three for known
  // multi-part TLDs like .com.br). Good enough for CT lookups.
  function baseDomain(hostname) {
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length <= 2) return hostname;
    const multiPartTlds = [
      // Brazil (registro.br) — registrations live at the 3rd level under one of
      // many second-level categories, so all of these are effective TLDs.
      "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br",
      "blog.br", "dev.br", "app.br", "eco.br", "ind.br", "inf.br", "rec.br",
      "srv.br", "tur.br", "tv.br", "wiki.br",
      // Other common multi-part TLDs.
      "com.au", "co.uk", "co.jp", "com.mx", "co.nz", "com.ar",
    ];
    const lastTwo = parts.slice(-2).join(".");
    const lastThree = parts.slice(-3).join(".");
    if (multiPartTlds.some((t) => lastThree.endsWith(t))) return lastThree;
    return lastTwo;
  }

  // Deduplicate + sort a list of subdomains, dropping wildcards.
  function normalizeSubdomains(names, base) {
    const set = new Set();
    names.forEach((n) => {
      let name = String(n).trim().toLowerCase();
      name = name.replace(/^\*\./, ""); // drop wildcard prefix
      if (!name || name.includes(" ")) return;
      if (name === base) return; // skip the apex itself
      if (name.endsWith("." + base) || name === base) set.add(name);
    });
    return Array.from(set).sort();
  }

  // Convert an ISO 3166-1 alpha-2 country code (e.g. "BR") into its flag emoji
  // (🇧🇷) by mapping each letter to its Regional Indicator Symbol.
  function flagEmoji(cc) {
    if (!cc || cc.length !== 2) return "";
    const code = cc.toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return "";
    const A = 0x1f1e6; // Regional Indicator Symbol Letter A
    const base = "A".charCodeAt(0);
    return String.fromCodePoint(
      A + (code.charCodeAt(0) - base),
      A + (code.charCodeAt(1) - base)
    );
  }

  // Build a BIND zone file from looked-up DNS records, in the format
  // Cloudflare's "Import DNS records" accepts. SOA and NS are excluded
  // (Cloudflare manages those; importing them conflicts). CNAME/MX/CAA targets
  // are made FQDN with a trailing dot as Cloudflare requires.
  //
  // `byType` is a map: { A: [{value,ttl}], MX: [{value,ttl}], ... }
  // `zoneName` is the registrable domain (e.g. example.com).
  function buildZoneFile(zoneName, byType) {
    const lines = [];
    lines.push(`; BIND zone file for ${zoneName}`);
    lines.push(`; Exported by WebAnalyzer - ready for Cloudflare import`);
    lines.push(`; SOA and NS records intentionally omitted (Cloudflare manages them).`);
    lines.push(`$ORIGIN ${zoneName}.`);
    lines.push(`$TTL 3600`);
    lines.push("");

    const exportTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "CAA"];
    const fqdn = (s) => (String(s).endsWith(".") ? String(s) : String(s) + ".");

    exportTypes.forEach((type) => {
      const entries = byType[type] || [];
      entries.forEach((e) => {
        const ttl = e.ttl || 3600;
        const owner = `${zoneName}.`;
        let line = null;
        if (type === "A" || type === "AAAA") {
          line = `${owner}\t${ttl}\t${type}\t${e.value}`;
        } else if (type === "CNAME") {
          line = `${owner}\t${ttl}\tCNAME\t${fqdn(e.value)}`;
        } else if (type === "MX") {
          const m = String(e.value).trim().match(/^(\d+)\s+(.+)$/);
          line = m
            ? `${owner}\t${ttl}\tMX\t${m[1]} ${fqdn(m[2])}`
            : `${owner}\t${ttl}\tMX\t10 ${fqdn(e.value)}`;
        } else if (type === "TXT") {
          const escaped = String(e.value).replace(/"/g, '\\"');
          line = `${owner}\t${ttl}\tTXT\t"${escaped}"`;
        } else if (type === "CAA") {
          line = `${owner}\t${ttl}\tCAA\t${e.value}`;
        }
        if (line) lines.push(line);
      });
    });

    return lines.join("\n") + "\n";
  }

  return { RECORD_TYPES, parseAnswers, baseDomain, normalizeSubdomains, cleanValue, flagEmoji, buildZoneFile };
})();

if (typeof window !== "undefined") window.NetworkTools = NetworkTools;
if (typeof module !== "undefined" && module.exports) module.exports = NetworkTools;

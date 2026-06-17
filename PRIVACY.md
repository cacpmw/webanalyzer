# Privacy Policy — WebAnalyzer

_Last updated: 2026-06-17_

WebAnalyzer is a browser extension that detects the technologies, hosting, and
server stack behind websites. This policy explains what data the extension
handles.

## What WebAnalyzer does NOT do

- It does **not** collect, store, or transmit any data to the developer.
- It has **no analytics, no tracking, and no telemetry**.
- It does **not** read or transmit the content of your cookies, form fields,
  passwords, or any personal data on the pages you visit.
- It does **not** sell or share data with anyone for advertising.

## Data processed locally on your device

To detect technologies, the extension reads, **only on your device**:

- HTTP response headers of the page you are viewing.
- The page's public HTML markup and script URLs.
- The **names** of cookies (never their values) — used to fingerprint the
  backend (e.g. a `PHPSESSID` cookie suggests PHP).

This information is processed in memory to show you the analysis and is not sent
anywhere except as described below. Settings and lookup caches are stored
locally via the browser's `storage` API and never leave your browser.

## Data sent to third-party services (only when you use certain tabs)

Some features require looking up public records about a domain. When you open
the **Network** or **WHOIS** tabs, the extension sends the **domain or IP being
analyzed** (not your identity, not page content) to these public services:

| Feature | Service | What is sent |
|---|---|---|
| DNS records | `cloudflare-dns.com`, `dns.google` | the domain name |
| Subdomain discovery | `crt.sh`, `api.certspotter.com` | the domain name |
| WHOIS / registration | `who-dat.as93.net` | the domain name |
| IP geolocation | `free.freeipapi.com`, `ipwho.is`, `api.country.is` | the IP address |

These lookups are made directly from your browser to those services; the
developer never sees them. Each service has its own privacy policy. No lookup is
performed until you open the relevant tab.

## Optional integration (AI analysis)

If you choose to configure an integration in the extension's Settings (for
example, your own n8n webhook), the URL and token you enter are stored locally
in your browser and used only to contact the endpoint **you** specified. No such
credentials are bundled with the extension.

## Diagnostic log

The extension can generate a diagnostic log that you may download. It is created
only on your request, stays on your device, and is never transmitted. Because it
can include public-record data (such as a domain's WHOIS contact details), avoid
sharing a log publicly if it contains information you don't want disclosed.

## Contact

This is an open-source project. Questions and issues can be raised on the public
repository.

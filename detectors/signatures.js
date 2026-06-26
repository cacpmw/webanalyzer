// signatures.js
// Tech-detection signature database. Pure data, no logic.
// Decoupled from tech-detector.js so signatures can evolve independently
// (and, later, be fetched remotely). Loaded as a browser global (WA_SIGNATURES)
// and as a CommonJS export.
//
// Signature schema: each entry is keyed by display name and may contain:
//   category (string), html (regex[]), headers (obj of regex), meta (obj of regex),
//   scripts (regex[]), globals (string[]), cookies (regex[]), implies (string[]),
//   version (extraction rule). Match = any listed signal hits.
(function (root) {
  const SIGNATURES = {
    // --- CMS ---
    WordPress: {
      category: "CMS",
      html: [/wp-content\//i, /wp-includes\//i, /<link[^>]+wp-json/i],
      meta: { generator: /wordpress/i },
      globals: ["wp"],
      implies: ["PHP", "MySQL"],
      version: { from: "meta", key: "generator", re: /wordpress\s+([\d.]+)/i },
    },
    Drupal: {
      category: "CMS",
      html: [/sites\/(default|all)\//i, /drupal-settings-json/i],
      meta: { generator: /drupal/i },
      globals: ["Drupal"],
      implies: ["PHP"],
      version: { from: "meta", key: "generator", re: /drupal\s+([\d.]+)/i },
    },
    Joomla: {
      category: "CMS",
      html: [/\/media\/jui\//i, /option=com_/i],
      meta: { generator: /joomla/i },
      globals: ["Joomla"],
      implies: ["PHP"],
      version: { from: "meta", key: "generator", re: /joomla!?\s+([\d.]+)/i },
    },
    Ghost: {
      category: "CMS",
      html: [/ghost-/i, /content\/images\//i],
      meta: { generator: /ghost/i },
      version: { from: "meta", key: "generator", re: /ghost\s+([\d.]+)/i },
    },
    Squarespace: {
      category: "CMS",
      html: [/static\.squarespace\.com/i, /squarespace-cdn/i],
    },
    Wix: {
      category: "CMS",
      html: [/static\.wixstatic\.com/i, /wix-warmup-data/i],
      headers: { "x-wix-request-id": /.*/ },
    },
    Webflow: {
      category: "CMS",
      html: [/assets\.website-files\.com/i, /data-wf-page/i],
      meta: { generator: /webflow/i },
    },

    // --- Ecommerce ---
    Shopify: {
      category: "Ecommerce",
      html: [/cdn\.shopify\.com/i, /shopify\.shop/i],
      headers: { "x-shopify-stage": /.*/, "x-shopid": /.*/ },
      globals: ["Shopify"],
    },
    Magento: {
      category: "Ecommerce",
      html: [/\/static\/version\d+/i, /mage\/cookies/i, /magento/i],
      implies: ["PHP"],
    },
    WooCommerce: {
      category: "Ecommerce",
      html: [/woocommerce/i, /wc-block/i],
      globals: ["wc", "woocommerce_params"],
      implies: ["WordPress"],
      // Version from the generator meta (read from raw HTML, since a page can
      // carry several <meta generator> that clobber each other in the parsed
      // map) or, failing that, the WooCommerce assets' ?ver= (dotted only).
      version: {
        from: "html",
        re: [
          /content=["']WooCommerce\s+([\d.]+)/i,
          /plugins\/woocommerce\/[^"']*?[?&]ver=(\d+\.\d[\d.]*)/i,
        ],
      },
    },
    PrestaShop: {
      category: "Ecommerce",
      html: [/prestashop/i],
      meta: { generator: /prestashop/i },
      implies: ["PHP"],
    },
    BigCommerce: {
      category: "Ecommerce",
      html: [/cdn\d*\.bigcommerce\.com/i],
    },
    // Brazilian hosted store platform. The asset CDN host is the reliable tell
    // (verified live: every product image is served from cdn.vnda.com.br); the
    // footer "developed by" link is a weaker backup.
    // Match only the asset-CDN host (proves the platform serves the page); a bare
    // vnda.com.br link would also appear on a page that merely mentions/credits it.
    VNDA: {
      category: "Ecommerce",
      html: [/cdn\.vnda\.com\.br/i],
    },
    // Nuvemshop / Tiendanube (same platform). Asset CDN hosts only, not the bare
    // institutional domain (which any review/comparison page could carry).
    Nuvemshop: {
      category: "Ecommerce",
      html: [/[ad]cdn\.nuvemshop\.com\.br/i, /\.tiendanube\.com\//i],
    },
    Tray: {
      category: "Ecommerce",
      html: [/images\.tcdn\.com\.br/i],
    },
    "Loja Integrada": {
      category: "Ecommerce",
      html: [/awsli\.com\.br/i],
    },
    Yampi: {
      category: "Ecommerce",
      html: [/\byampi\.com\.br/i, /\byampi\.io/i],
    },
    VTEX: {
      category: "Ecommerce",
      html: [/vtexassets\.com/i, /vtexcommercestable/i],
      meta: { generator: /vtex/i },
    },
    // Bagy runs on the Dooca Commerce platform; its asset host is the stable tell.
    Bagy: {
      category: "Ecommerce",
      html: [/dooca\.store/i], // TODO: verify a dedicated bagy.com.br asset host
    },
    "Salesforce Commerce Cloud": {
      category: "Ecommerce",
      html: [/demandware\.(net|static)/i, /dwstatic/i],
    },
    Shopware: {
      category: "Ecommerce",
      meta: { generator: /shopware/i },
      html: [/\/bundles\/storefront\//i], // TODO: verify across Shopware 5 vs 6 themes
    },
    OpenCart: {
      category: "Ecommerce",
      html: [/catalog\/view\/(theme|javascript)\//i],
      implies: ["PHP"],
    },

    // --- JS Frameworks ---
    React: {
      category: "JS Framework",
      html: [/data-reactroot/i, /_reactlistening/i, /react-dom/i],
      scripts: [/react(\.production|\.development)?(\.min)?\.js/i],
      globals: ["React", "ReactDOM"],
    },
    "Next.js": {
      category: "JS Framework",
      html: [/id="__next"/i],
      scripts: [/\/_next\//i],
      globals: ["__NEXT_DATA__"],
      implies: ["React", "Node.js"],
    },
    "Vue.js": {
      category: "JS Framework",
      html: [/data-v-[0-9a-f]{8}/i, /id="app"[^>]+data-server-rendered/i],
      scripts: [/vue(\.runtime)?(\.min)?\.js/i],
      globals: ["Vue"],
    },
    "Nuxt.js": {
      category: "JS Framework",
      scripts: [/\/_nuxt\//i],
      globals: ["__NUXT__"],
      implies: ["Vue.js", "Node.js"],
    },
    Angular: {
      category: "JS Framework",
      html: [/ng-version="([\d.]+)"/i, /\sng-app/i],
      globals: ["angular", "ng"],
      version: { from: "html", re: /ng-version="([\d.]+)"/i },
    },
    Svelte: {
      category: "JS Framework",
      html: [/svelte-[0-9a-z]+/i],
      globals: ["Svelte"],
    },
    Gatsby: {
      category: "JS Framework",
      html: [/id="___gatsby"/i],
      scripts: [/\/page-data\//i],
      implies: ["React"],
    },
    Remix: {
      category: "JS Framework",
      globals: ["__remixContext"],
      implies: ["React"],
    },
    "Alpine.js": {
      category: "JS Framework",
      html: [/\sx-data[=\s>]/i],
      globals: ["Alpine"],
    },

    // --- JS Libraries ---
    jQuery: {
      category: "JS Library",
      scripts: [/jquery[-.]?[\d.]*(\.min)?\.js/i],
      globals: ["jQuery"],
      version: {
        from: "script",
        re: [
          /jquery[-.]?([\d.]+)(\.min)?\.js/i, // version in the filename
          /jquery(?:\.min)?\.js\?[^"']*\bver=(\d+\.\d[\d.]*)/i, // WordPress-style ?ver= (dotted only)
        ],
      },
    },
    "Lodash": {
      category: "JS Library",
      scripts: [/lodash(\.min)?\.js/i],
    },
    "Font Awesome": {
      category: "Font Script",
      html: [/font-?awesome/i, /fa-[a-z]+/i],
    },
    "Google Fonts": {
      category: "Font Script",
      html: [/fonts\.googleapis\.com/i, /fonts\.gstatic\.com/i],
    },

    // --- CSS Frameworks ---
    Bootstrap: {
      category: "CSS Framework",
      html: [/class="[^"]*\b(col-(xs|sm|md|lg|xl)-\d+|navbar-toggler)\b/i],
      scripts: [/bootstrap(\.bundle)?(\.min)?\.js/i],
    },
    "Tailwind CSS": {
      category: "CSS Framework",
      // Match only Tailwind-distinctive class tokens, and require each token to
      // START a class (negative lookbehind for word-char/hyphen) so themed
      // prefixes like "wpex-flex" or "wpex-py-30" don't false-positive. Bare
      // flex/grid and shared spacing scales (px-4, mt-5 — also Bootstrap) are
      // intentionally excluded; we key off variant prefixes (md:, hover:),
      // numbered color scales (bg-blue-500), text sizes and grid-cols-N.
      html: [/class="[^"]*(?<![-\w])(?:(?:sm|md|lg|xl|2xl|hover|focus|active|disabled|dark|group-hover):[a-z][\w-]+|(?:bg|text|border|ring|fill|stroke|from|via|to|divide|shadow|accent|decoration|outline)-(?:gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}|text-(?:xs|sm|base|lg|xl|[2-9]xl)(?![\w-])|grid-cols-\d{1,2})/i],
    },
    Elementor: {
      category: "Page Builder",
      html: [/elementor-(widget|section|element)/i, /\/uploads\/elementor\//i],
      globals: ["elementorFrontend"],
      implies: ["WordPress"],
      // WordPress stamps the plugin version onto its enqueued assets' ?ver=.
      // Require the core "elementor/assets" path so elementor-pro (own version)
      // isn't picked up.
      version: { from: "html", re: /plugins\/elementor\/assets\/[^"']*?[?&]ver=(\d+\.\d[\d.]*)/i },
    },

    // --- Web Servers (from headers) ---
    Nginx: {
      category: "Web Server",
      headers: { server: /nginx/i },
      version: { from: "header", key: "server", re: /nginx\/?([\d.]+)?/i },
    },
    Apache: {
      category: "Web Server",
      headers: { server: /apache/i },
      version: { from: "header", key: "server", re: /apache\/?([\d.]+)?/i },
    },
    "Microsoft IIS": {
      category: "Web Server",
      headers: { server: /microsoft-iis/i },
      implies: ["ASP.NET"],
      version: { from: "header", key: "server", re: /microsoft-iis\/?([\d.]+)?/i },
    },
    LiteSpeed: {
      category: "Web Server",
      headers: { server: /litespeed/i },
    },
    Caddy: { category: "Web Server", headers: { server: /caddy/i } },
    OpenResty: {
      category: "Web Server",
      headers: { server: /openresty/i },
    },

    // --- Languages / Backend (from headers + cookies) ---
    PHP: {
      category: "Language",
      headers: { "x-powered-by": /php/i },
      cookies: [/^phpsessid$/i],
      version: { from: "header", key: "x-powered-by", re: /php\/?([\d.]+)?/i },
    },
    "ASP.NET": {
      category: "Framework",
      headers: { "x-powered-by": /asp\.net/i, "x-aspnet-version": /.*/ },
      cookies: [/^asp\.net_sessionid$/i],
      version: { from: "header", key: "x-aspnet-version", re: /([\d.]+)/ },
    },
    "Node.js": {
      category: "Language",
      headers: { "x-powered-by": /express/i },
    },
    "Express.js": {
      category: "Framework",
      headers: { "x-powered-by": /express/i },
      implies: ["Node.js"],
    },
    "Ruby on Rails": {
      category: "Framework",
      headers: { "x-powered-by": /phusion passenger/i, server: /passenger/i },
      cookies: [/_session_id$/i],
    },
    Java: {
      category: "Language",
      cookies: [/^jsessionid$/i],
    },
    Laravel: {
      category: "Framework",
      cookies: [/^laravel_session$/i, /^xsrf-token$/i],
      implies: ["PHP"],
    },

    // --- Databases (matched only via implication today; listed so they
    //     inherit the right category instead of falling back to Unknown) ---
    MySQL: { category: "Database" },
    PostgreSQL: { category: "Database" },

    // --- CDN / Cloud / Proxy / Security (from headers) ---
    Cloudflare: {
      category: "CDN",
      headers: {
        server: /cloudflare/i,
        "cf-ray": /.*/,
        "cf-cache-status": /.*/,
      },
    },
    "Amazon CloudFront": {
      category: "CDN",
      headers: { "x-amz-cf-id": /.*/, via: /cloudfront/i },
    },
    Fastly: {
      category: "CDN",
      headers: { "x-served-by": /cache-/i, "x-fastly-request-id": /.*/ },
    },
    Akamai: {
      category: "CDN",
      headers: { "x-akamai-transformed": /.*/, server: /akamai/i },
    },
    Sucuri: {
      category: "Security",
      headers: { "x-sucuri-id": /.*/, server: /sucuri/i },
    },
    Vercel: {
      category: "Hosting",
      headers: { server: /vercel/i, "x-vercel-id": /.*/ },
    },
    Netlify: {
      category: "Hosting",
      headers: { server: /netlify/i, "x-nf-request-id": /.*/ },
    },
    "Amazon S3": {
      category: "Hosting",
      headers: { server: /amazons3/i, "x-amz-request-id": /.*/ },
    },
    "GitHub Pages": {
      category: "Hosting",
      headers: { server: /github\.com/i },
    },

    // --- Analytics / Tags ---
    "Google Tag Manager": {
      category: "Tag Manager",
      html: [/googletagmanager\.com\/gtm\.js/i],
      globals: ["dataLayer"],
    },
    "Google Analytics": {
      category: "Analytics",
      html: [/google-analytics\.com\/(analytics|ga)\.js/i, /gtag\/js\?id=G-/i],
      globals: ["gtag"],
    },
    "Facebook Pixel": {
      category: "Analytics",
      html: [/connect\.facebook\.net\/[^/]+\/fbevents\.js/i],
    },
    Hotjar: {
      category: "Analytics",
      html: [/static\.hotjar\.com/i, /hotjar-/i],
    },

    // --- Payments ---
    Stripe: {
      category: "Payments",
      scripts: [/js\.stripe\.com/i],
      globals: ["Stripe"],
    },
    PayPal: {
      category: "Payments",
      scripts: [/paypal\.com\/sdk/i, /paypalobjects\.com/i],
    },
  };
  root.WA_SIGNATURES = SIGNATURES;
  if (typeof module !== "undefined" && module.exports) module.exports = SIGNATURES;
})(typeof globalThis !== "undefined" ? globalThis : this);

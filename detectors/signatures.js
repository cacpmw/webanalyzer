// signatures.js
// Tech-detection signature loader + compiler.
//
// The signature DATABASE is pure data (regex stored as { "$re": source,
// "flags": flags } strings) so it is JSON-serializable — the prerequisite for
// fetching it remotely later, and safe for Chrome Web Store review (we ship
// DATA, never executable code). This module compiles those string markers back
// into live RegExp at load time and exposes the result exactly as before:
// a browser global (WA_SIGNATURES) and a CommonJS export.
//
// Source of truth: detectors/signatures.json. The browser cannot synchronously
// require JSON (and detect() is sync, no async/eval/build step allowed), so the
// identical data is also embedded inline below as RAW_INLINE for the popup/
// content-script path. Node/tests compile from the JSON file; the browser
// compiles from RAW_INLINE. A deep-equal test guards the two against drift.
//
// Signature schema: each entry is keyed by display name and may contain:
//   category (string), html (regex[]), headers (obj of regex), meta (obj of regex),
//   scripts (regex[]), globals (string[]), cookies (regex[]), implies (string[]),
//   version (extraction rule, regex under `re`). Match = any listed signal hits.
(function (root) {
  // Recursively turn { $re, flags } markers into RegExp; leave everything else
  // (strings, arrays of strings, plain fields) untouched. Field-name agnostic,
  // so it handles html/scripts/cookies arrays, headers/meta objects and the
  // version rule's `re` (single marker or array of markers) alike.
  function compile(node) {
    if (Array.isArray(node)) return node.map(compile);
    if (node && typeof node === "object") {
      if (typeof node.$re === "string") return new RegExp(node.$re, node.flags || "");
      const out = {};
      for (const k of Object.keys(node)) out[k] = compile(node[k]);
      return out;
    }
    return node;
  }

  // Inline copy of signatures.json for the synchronous browser load path.
  const RAW_INLINE = {
    "WordPress": {
      "category": "CMS",
      "html": [
        {
          "$re": "wp-content\\/",
          "flags": "i"
        },
        {
          "$re": "wp-includes\\/",
          "flags": "i"
        },
        {
          "$re": "<link[^>]+wp-json",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "wordpress",
          "flags": "i"
        }
      },
      "globals": [
        "wp"
      ],
      "implies": [
        "PHP",
        "MySQL"
      ],
      "version": {
        "from": "meta",
        "key": "generator",
        "re": {
          "$re": "wordpress\\s+([\\d.]+)",
          "flags": "i"
        }
      }
    },
    "Drupal": {
      "category": "CMS",
      "html": [
        {
          "$re": "sites\\/(default|all)\\/",
          "flags": "i"
        },
        {
          "$re": "drupal-settings-json",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "drupal",
          "flags": "i"
        }
      },
      "globals": [
        "Drupal"
      ],
      "implies": [
        "PHP"
      ],
      "version": {
        "from": "meta",
        "key": "generator",
        "re": {
          "$re": "drupal\\s+([\\d.]+)",
          "flags": "i"
        }
      }
    },
    "Joomla": {
      "category": "CMS",
      "html": [
        {
          "$re": "\\/media\\/jui\\/",
          "flags": "i"
        },
        {
          "$re": "option=com_",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "joomla",
          "flags": "i"
        }
      },
      "globals": [
        "Joomla"
      ],
      "implies": [
        "PHP"
      ],
      "version": {
        "from": "meta",
        "key": "generator",
        "re": {
          "$re": "joomla!?\\s+([\\d.]+)",
          "flags": "i"
        }
      }
    },
    "Ghost": {
      "category": "CMS",
      "html": [
        {
          "$re": "ghost-",
          "flags": "i"
        },
        {
          "$re": "content\\/images\\/",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "ghost",
          "flags": "i"
        }
      },
      "version": {
        "from": "meta",
        "key": "generator",
        "re": {
          "$re": "ghost\\s+([\\d.]+)",
          "flags": "i"
        }
      }
    },
    "Squarespace": {
      "category": "CMS",
      "html": [
        {
          "$re": "static\\.squarespace\\.com",
          "flags": "i"
        },
        {
          "$re": "squarespace-cdn",
          "flags": "i"
        }
      ]
    },
    "Wix": {
      "category": "CMS",
      "html": [
        {
          "$re": "static\\.wixstatic\\.com",
          "flags": "i"
        },
        {
          "$re": "wix-warmup-data",
          "flags": "i"
        }
      ],
      "headers": {
        "x-wix-request-id": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "Webflow": {
      "category": "CMS",
      "html": [
        {
          "$re": "assets\\.website-files\\.com",
          "flags": "i"
        },
        {
          "$re": "data-wf-page",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "webflow",
          "flags": "i"
        }
      }
    },
    "Shopify": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "cdn\\.shopify\\.com",
          "flags": "i"
        },
        {
          "$re": "shopify\\.shop",
          "flags": "i"
        }
      ],
      "headers": {
        "x-shopify-stage": {
          "$re": ".*",
          "flags": ""
        },
        "x-shopid": {
          "$re": ".*",
          "flags": ""
        }
      },
      "globals": [
        "Shopify"
      ]
    },
    "Magento": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "\\/static\\/version\\d+",
          "flags": "i"
        },
        {
          "$re": "mage\\/cookies",
          "flags": "i"
        },
        {
          "$re": "magento",
          "flags": "i"
        }
      ],
      "implies": [
        "PHP"
      ]
    },
    "WooCommerce": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "woocommerce",
          "flags": "i"
        },
        {
          "$re": "wc-block",
          "flags": "i"
        }
      ],
      "globals": [
        "wc",
        "woocommerce_params"
      ],
      "implies": [
        "WordPress"
      ],
      "version": {
        "from": "html",
        "re": [
          {
            "$re": "content=[\"']WooCommerce\\s+([\\d.]+)",
            "flags": "i"
          },
          {
            "$re": "plugins\\/woocommerce\\/[^\"']*?[?&]ver=(\\d+\\.\\d[\\d.]*)",
            "flags": "i"
          }
        ]
      }
    },
    "PrestaShop": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "prestashop",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "prestashop",
          "flags": "i"
        }
      },
      "implies": [
        "PHP"
      ]
    },
    "BigCommerce": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "cdn\\d*\\.bigcommerce\\.com",
          "flags": "i"
        }
      ]
    },
    "VNDA": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "cdn\\.vnda\\.com\\.br",
          "flags": "i"
        }
      ]
    },
    "Nuvemshop": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "[ad]cdn\\.nuvemshop\\.com\\.br",
          "flags": "i"
        },
        {
          "$re": "\\.tiendanube\\.com\\/",
          "flags": "i"
        }
      ]
    },
    "Tray": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "images\\.tcdn\\.com\\.br",
          "flags": "i"
        }
      ]
    },
    "Loja Integrada": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "awsli\\.com\\.br",
          "flags": "i"
        }
      ]
    },
    "Yampi": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "\\byampi\\.com\\.br",
          "flags": "i"
        },
        {
          "$re": "\\byampi\\.io",
          "flags": "i"
        }
      ]
    },
    "VTEX": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "vtexassets\\.com",
          "flags": "i"
        },
        {
          "$re": "vtexcommercestable",
          "flags": "i"
        }
      ],
      "meta": {
        "generator": {
          "$re": "vtex",
          "flags": "i"
        }
      }
    },
    "Bagy": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "dooca\\.store",
          "flags": "i"
        }
      ]
    },
    "Salesforce Commerce Cloud": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "demandware\\.(net|static)",
          "flags": "i"
        },
        {
          "$re": "dwstatic",
          "flags": "i"
        }
      ]
    },
    "Shopware": {
      "category": "Ecommerce",
      "meta": {
        "generator": {
          "$re": "shopware",
          "flags": "i"
        }
      },
      "html": [
        {
          "$re": "\\/bundles\\/storefront\\/",
          "flags": "i"
        }
      ]
    },
    "OpenCart": {
      "category": "Ecommerce",
      "html": [
        {
          "$re": "catalog\\/view\\/(theme|javascript)\\/",
          "flags": "i"
        }
      ],
      "implies": [
        "PHP"
      ]
    },
    "React": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "data-reactroot",
          "flags": "i"
        },
        {
          "$re": "_reactlistening",
          "flags": "i"
        },
        {
          "$re": "react-dom",
          "flags": "i"
        }
      ],
      "scripts": [
        {
          "$re": "react(\\.production|\\.development)?(\\.min)?\\.js",
          "flags": "i"
        }
      ],
      "globals": [
        "React",
        "ReactDOM"
      ]
    },
    "Next.js": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "id=\"__next\"",
          "flags": "i"
        }
      ],
      "scripts": [
        {
          "$re": "\\/_next\\/",
          "flags": "i"
        }
      ],
      "globals": [
        "__NEXT_DATA__"
      ],
      "implies": [
        "React",
        "Node.js"
      ]
    },
    "Vue.js": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "data-v-[0-9a-f]{8}",
          "flags": "i"
        },
        {
          "$re": "id=\"app\"[^>]+data-server-rendered",
          "flags": "i"
        }
      ],
      "scripts": [
        {
          "$re": "vue(\\.runtime)?(\\.min)?\\.js",
          "flags": "i"
        }
      ],
      "globals": [
        "Vue"
      ]
    },
    "Nuxt.js": {
      "category": "JS Framework",
      "scripts": [
        {
          "$re": "\\/_nuxt\\/",
          "flags": "i"
        }
      ],
      "globals": [
        "__NUXT__"
      ],
      "implies": [
        "Vue.js",
        "Node.js"
      ]
    },
    "Angular": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "ng-version=\"([\\d.]+)\"",
          "flags": "i"
        },
        {
          "$re": "\\sng-app",
          "flags": "i"
        }
      ],
      "globals": [
        "angular",
        "ng"
      ],
      "version": {
        "from": "html",
        "re": {
          "$re": "ng-version=\"([\\d.]+)\"",
          "flags": "i"
        }
      }
    },
    "Svelte": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "svelte-[0-9a-z]+",
          "flags": "i"
        }
      ],
      "globals": [
        "Svelte"
      ]
    },
    "Gatsby": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "id=\"___gatsby\"",
          "flags": "i"
        }
      ],
      "scripts": [
        {
          "$re": "\\/page-data\\/",
          "flags": "i"
        }
      ],
      "implies": [
        "React"
      ]
    },
    "Remix": {
      "category": "JS Framework",
      "globals": [
        "__remixContext"
      ],
      "implies": [
        "React"
      ]
    },
    "Alpine.js": {
      "category": "JS Framework",
      "html": [
        {
          "$re": "\\sx-data[=\\s>]",
          "flags": "i"
        }
      ],
      "globals": [
        "Alpine"
      ]
    },
    "jQuery": {
      "category": "JS Library",
      "scripts": [
        {
          "$re": "jquery[-.]?[\\d.]*(\\.min)?\\.js",
          "flags": "i"
        }
      ],
      "globals": [
        "jQuery"
      ],
      "version": {
        "from": "script",
        "re": [
          {
            "$re": "jquery[-.]?([\\d.]+)(\\.min)?\\.js",
            "flags": "i"
          },
          {
            "$re": "jquery(?:\\.min)?\\.js\\?[^\"']*\\bver=(\\d+\\.\\d[\\d.]*)",
            "flags": "i"
          }
        ]
      }
    },
    "Lodash": {
      "category": "JS Library",
      "scripts": [
        {
          "$re": "lodash(\\.min)?\\.js",
          "flags": "i"
        }
      ]
    },
    "Font Awesome": {
      "category": "Font Script",
      "html": [
        {
          "$re": "font-?awesome",
          "flags": "i"
        },
        {
          "$re": "fa-[a-z]+",
          "flags": "i"
        }
      ]
    },
    "Google Fonts": {
      "category": "Font Script",
      "html": [
        {
          "$re": "fonts\\.googleapis\\.com",
          "flags": "i"
        },
        {
          "$re": "fonts\\.gstatic\\.com",
          "flags": "i"
        }
      ]
    },
    "Bootstrap": {
      "category": "CSS Framework",
      "html": [
        {
          "$re": "class=\"[^\"]*\\b(col-(xs|sm|md|lg|xl)-\\d+|navbar-toggler)\\b",
          "flags": "i"
        }
      ],
      "scripts": [
        {
          "$re": "bootstrap(\\.bundle)?(\\.min)?\\.js",
          "flags": "i"
        }
      ]
    },
    "Tailwind CSS": {
      "category": "CSS Framework",
      "html": [
        {
          "$re": "class=\"[^\"]*(?<![-\\w])(?:(?:sm|md|lg|xl|2xl|hover|focus|active|disabled|dark|group-hover):[a-z][\\w-]+|(?:bg|text|border|ring|fill|stroke|from|via|to|divide|shadow|accent|decoration|outline)-(?:gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\\d{2,3}|text-(?:xs|sm|base|lg|xl|[2-9]xl)(?![\\w-])|grid-cols-\\d{1,2})",
          "flags": "i"
        }
      ]
    },
    "Elementor": {
      "category": "Page Builder",
      "html": [
        {
          "$re": "elementor-(widget|section|element)",
          "flags": "i"
        },
        {
          "$re": "\\/uploads\\/elementor\\/",
          "flags": "i"
        }
      ],
      "globals": [
        "elementorFrontend"
      ],
      "implies": [
        "WordPress"
      ],
      "version": {
        "from": "html",
        "re": {
          "$re": "plugins\\/elementor\\/assets\\/[^\"']*?[?&]ver=(\\d+\\.\\d[\\d.]*)",
          "flags": "i"
        }
      }
    },
    "Nginx": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "nginx",
          "flags": "i"
        }
      },
      "version": {
        "from": "header",
        "key": "server",
        "re": {
          "$re": "nginx\\/?([\\d.]+)?",
          "flags": "i"
        }
      }
    },
    "Apache": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "apache",
          "flags": "i"
        }
      },
      "version": {
        "from": "header",
        "key": "server",
        "re": {
          "$re": "apache\\/?([\\d.]+)?",
          "flags": "i"
        }
      }
    },
    "Microsoft IIS": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "microsoft-iis",
          "flags": "i"
        }
      },
      "implies": [
        "ASP.NET"
      ],
      "version": {
        "from": "header",
        "key": "server",
        "re": {
          "$re": "microsoft-iis\\/?([\\d.]+)?",
          "flags": "i"
        }
      }
    },
    "LiteSpeed": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "litespeed",
          "flags": "i"
        }
      }
    },
    "Caddy": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "caddy",
          "flags": "i"
        }
      }
    },
    "OpenResty": {
      "category": "Web Server",
      "headers": {
        "server": {
          "$re": "openresty",
          "flags": "i"
        }
      }
    },
    "PHP": {
      "category": "Language",
      "headers": {
        "x-powered-by": {
          "$re": "php",
          "flags": "i"
        }
      },
      "cookies": [
        {
          "$re": "^phpsessid$",
          "flags": "i"
        }
      ],
      "version": {
        "from": "header",
        "key": "x-powered-by",
        "re": {
          "$re": "php\\/?([\\d.]+)?",
          "flags": "i"
        }
      }
    },
    "ASP.NET": {
      "category": "Framework",
      "headers": {
        "x-powered-by": {
          "$re": "asp\\.net",
          "flags": "i"
        },
        "x-aspnet-version": {
          "$re": ".*",
          "flags": ""
        }
      },
      "cookies": [
        {
          "$re": "^asp\\.net_sessionid$",
          "flags": "i"
        }
      ],
      "version": {
        "from": "header",
        "key": "x-aspnet-version",
        "re": {
          "$re": "([\\d.]+)",
          "flags": ""
        }
      }
    },
    "Node.js": {
      "category": "Language",
      "headers": {
        "x-powered-by": {
          "$re": "express",
          "flags": "i"
        }
      }
    },
    "Express.js": {
      "category": "Framework",
      "headers": {
        "x-powered-by": {
          "$re": "express",
          "flags": "i"
        }
      },
      "implies": [
        "Node.js"
      ]
    },
    "Ruby on Rails": {
      "category": "Framework",
      "headers": {
        "x-powered-by": {
          "$re": "phusion passenger",
          "flags": "i"
        },
        "server": {
          "$re": "passenger",
          "flags": "i"
        }
      },
      "cookies": [
        {
          "$re": "_session_id$",
          "flags": "i"
        }
      ]
    },
    "Java": {
      "category": "Language",
      "cookies": [
        {
          "$re": "^jsessionid$",
          "flags": "i"
        }
      ]
    },
    "Laravel": {
      "category": "Framework",
      "cookies": [
        {
          "$re": "^laravel_session$",
          "flags": "i"
        },
        {
          "$re": "^xsrf-token$",
          "flags": "i"
        }
      ],
      "implies": [
        "PHP"
      ]
    },
    "MySQL": {
      "category": "Database"
    },
    "PostgreSQL": {
      "category": "Database"
    },
    "Cloudflare": {
      "category": "CDN",
      "headers": {
        "server": {
          "$re": "cloudflare",
          "flags": "i"
        },
        "cf-ray": {
          "$re": ".*",
          "flags": ""
        },
        "cf-cache-status": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "Amazon CloudFront": {
      "category": "CDN",
      "headers": {
        "x-amz-cf-id": {
          "$re": ".*",
          "flags": ""
        },
        "via": {
          "$re": "cloudfront",
          "flags": "i"
        }
      }
    },
    "Fastly": {
      "category": "CDN",
      "headers": {
        "x-served-by": {
          "$re": "cache-",
          "flags": "i"
        },
        "x-fastly-request-id": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "Akamai": {
      "category": "CDN",
      "headers": {
        "x-akamai-transformed": {
          "$re": ".*",
          "flags": ""
        },
        "server": {
          "$re": "akamai",
          "flags": "i"
        }
      }
    },
    "Sucuri": {
      "category": "Security",
      "headers": {
        "x-sucuri-id": {
          "$re": ".*",
          "flags": ""
        },
        "server": {
          "$re": "sucuri",
          "flags": "i"
        }
      }
    },
    "Vercel": {
      "category": "Hosting",
      "headers": {
        "server": {
          "$re": "vercel",
          "flags": "i"
        },
        "x-vercel-id": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "Netlify": {
      "category": "Hosting",
      "headers": {
        "server": {
          "$re": "netlify",
          "flags": "i"
        },
        "x-nf-request-id": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "Amazon S3": {
      "category": "Hosting",
      "headers": {
        "server": {
          "$re": "amazons3",
          "flags": "i"
        },
        "x-amz-request-id": {
          "$re": ".*",
          "flags": ""
        }
      }
    },
    "GitHub Pages": {
      "category": "Hosting",
      "headers": {
        "server": {
          "$re": "github\\.com",
          "flags": "i"
        }
      }
    },
    "Google Tag Manager": {
      "category": "Tag Manager",
      "html": [
        {
          "$re": "googletagmanager\\.com\\/gtm\\.js",
          "flags": "i"
        }
      ],
      "globals": [
        "dataLayer"
      ]
    },
    "Google Analytics": {
      "category": "Analytics",
      "html": [
        {
          "$re": "google-analytics\\.com\\/(analytics|ga)\\.js",
          "flags": "i"
        },
        {
          "$re": "gtag\\/js\\?id=G-",
          "flags": "i"
        }
      ],
      "globals": [
        "gtag"
      ]
    },
    "Facebook Pixel": {
      "category": "Analytics",
      "html": [
        {
          "$re": "connect\\.facebook\\.net\\/[^/]+\\/fbevents\\.js",
          "flags": "i"
        }
      ]
    },
    "Hotjar": {
      "category": "Analytics",
      "html": [
        {
          "$re": "static\\.hotjar\\.com",
          "flags": "i"
        },
        {
          "$re": "hotjar-",
          "flags": "i"
        }
      ]
    },
    "Stripe": {
      "category": "Payments",
      "scripts": [
        {
          "$re": "js\\.stripe\\.com",
          "flags": "i"
        }
      ],
      "globals": [
        "Stripe"
      ]
    },
    "PayPal": {
      "category": "Payments",
      "scripts": [
        {
          "$re": "paypal\\.com\\/sdk",
          "flags": "i"
        },
        {
          "$re": "paypalobjects\\.com",
          "flags": "i"
        }
      ]
    }
  };

  const RAW =
    typeof module !== "undefined" && module.exports
      ? require("./signatures.json")
      : RAW_INLINE;

  const SIGNATURES = compile(RAW);

  // Expose the raw (uncompiled) inline data non-enumerably so consumers that
  // iterate SIGNATURES as the tech list (Object.entries) never see it, but the
  // drift test can still reach it.
  Object.defineProperty(SIGNATURES, "_raw", { value: RAW_INLINE, enumerable: false });

  root.WA_SIGNATURES = SIGNATURES;
  if (typeof module !== "undefined" && module.exports) module.exports = SIGNATURES;
})(typeof globalThis !== "undefined" ? globalThis : this);

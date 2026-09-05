# Velvet product site

The public Velvet and ShadowPath product site, built with Astro and deployed as a
Cloudflare Worker with static assets.

- Production: <https://shadowpath.coriolislabs.ca>
- UI: statically generated Astro pages with a small TypeScript replay controller
- API: `POST /api/events`, a Cloudflare Worker endpoint that accepts only five
  allowlisted event names and stores no visitor identifiers or arbitrary payloads
- Hosting: Cloudflare Workers Static Assets with a managed custom domain, TLS,
  immutable fingerprinted assets, security headers, and a custom 404 page

## Local development

Use Node.js 22.19 or newer.

```bash
npm install
npm run dev
```

Run the production build and all site checks:

```bash
npm test
npm run deploy:dry-run
```

Deploy with the Cloudflare account authenticated by Wrangler:

```bash
npm run deploy
```

The site is intentionally independent of the ChatGPT Sites wrapper. Deployment
configuration lives in [`wrangler.jsonc`](wrangler.jsonc), and the canonical
origin is set in [`astro.config.mjs`](astro.config.mjs).

The proof replay uses the exact eight route classes from the committed ShadowPath
fixture. The portfolio panel is explicitly labelled as an illustrative UI for the
implemented portfolio schema. Before changing product claims, review
[`../docs/public/CLAIMS.md`](../docs/public/CLAIMS.md) and
[`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).

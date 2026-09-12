# Velvet product site

The public Velvet and ShadowPath product site, built with Astro and deployed as a
Cloudflare Worker with static assets.

- Production: <https://shadowpath.coriolislabs.ca>
- UI: statically generated Astro pages with a small TypeScript replay controller
- API: `POST /api/events`, a Cloudflare Worker endpoint that accepts only eight
  allowlisted event names and stores no visitor identifiers or arbitrary payloads
- Hosting: Cloudflare Workers Static Assets with a managed custom domain, TLS,
  immutable fingerprinted assets, security headers, and a custom 404 page

## Customer pilot inquiries

`/pilot/` gives prospective customers a scoped entry point from the homepage and
refund evidence page. The contact is `paul@coriolislabs.ca`, configured in
`src/lib/pilot.ts`. Optional workflow details stay in the browser until the
visitor opens their email app or copies the inquiry; the visitor sends the email.
There is no submission endpoint, CRM write, or delivery confirmation. The direct
email link also works without JavaScript, and the copy action has a manual
selection fallback when clipboard access fails.

The Worker logs three additional aggregate events: `pilot_viewed`,
`pilot_email_opened`, and `pilot_inquiry_copied`. Email opens and copies measure
intent only. Use actual inbound emails to count inquiries; track qualified
conversations and agreed pilots separately. Do not report these browser events
as leads or customers. The events carry no inquiry text or visitor identifiers.
No additional service, secret, or database is needed when deploying this page.

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

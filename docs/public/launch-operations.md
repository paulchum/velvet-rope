# Launch operations

This runbook distinguishes a source change, a validated build, and a verified public deployment.
The existing host is the Cloudflare Worker `shadowpath-replay` on
`shadowpath.coriolislabs.ca`; `site/wrangler.jsonc` remains the deployment configuration.

## Verify before merging

Review the PR diff, current implementation claims, and CI checks. The customer-facing readiness
workflow installs the locked site, audits dependencies, builds and checks Astro and the Worker,
tests internal links and commercial boundaries, and validates the Cloudflare bundle without
publishing. A dry run does not update the public domain.

The full repository CI and protected-refund checks are separate. Do not waive a failed security
or correctness check solely because the changed pages are marketing material.

## Deploy from GitHub Actions

The `Deploy customer website` workflow is restricted to `main` in this repository. It runs
when site or deployment-workflow changes reach `main`, or when manually selected in Actions.

Configure these **repository secrets** in GitHub Settings > Secrets and variables > Actions:

- `CLOUDFLARE_API_TOKEN`: a token scoped to the existing Cloudflare account and required Worker/zone.
- `CLOUDFLARE_ACCOUNT_ID`: the account that owns the existing Worker and domain.

Do not paste token values into chat, an issue, source code, a public document, or a terminal
command that will be retained in shell history. Follow the
[official Cloudflare authentication instructions](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/)
for account/zone scoping. No broad account token is required by this runbook.

The workflow stops before deployment when either secret is absent. It does not interpret missing
authorization as a successful release. Install and test steps run without deployment secrets in
their environment; only the authorization preflight and Wrangler step receive them.

After building, the workflow stamps `dist/deployment.json` with the source commit and build time,
deploys the existing Worker, then checks the public revision and all eight customer-facing routes.
A successful source build alone must not be reported as a live deployment.

## Local deployment alternative

Use Node satisfying `site/package.json`, a clean checkout of the reviewed commit, and the
account owner's interactive Cloudflare login. Do not publish from an unreviewed working tree.

```bash
cd site
npm ci
npm audit --audit-level=high
npm test
npx --no-install wrangler login
npm run deploy
```

This existing local command does not add the CI revision stamp. Record the deployed source commit,
Wrangler result, and public-page checks separately. Confirm the selected account before approving
Wrangler's authentication flow.

## Public smoke checks

Open `/`, `/pilot/`, `/evidence/`, `/investors/`, `/trust/`, `/contact/`, `/replay/`, and
`/protected-refunds/` on the configured HTTPS domain. Check desktop and mobile navigation,
page titles, links, and that the contact helper prepares a draft without claiming it was sent.
Test `?intent=pilot` and `?intent=investor`. Send a real inquiry only from an authorized mailbox
when deliberately verifying delivery; the helper does not test email delivery automatically.

The recorded replay must stay labeled synthetic and recorded. Neither it nor the website's
reference ledger represents a new production assessment or customer deployment.

## Rollback and commercial operation

For a bad source change, revert the reviewed PR and rerun the same validation and deployment
process. Do not disable checks or force-push `main` to hide a failed rollout. A failed public smoke
check needs investigation even when Wrangler reported upload success.

Before accepting the first engagement, agree the written scope, price, schedule, payment terms,
testing authorization, data handling, and acceptance criteria with the buyer. Use the
[pilot scope](pilot.md) and [onboarding checklist](customer-onboarding.md). No subscription,
customer commitment, financing commitment, or service-level agreement is created by publishing
these pages.

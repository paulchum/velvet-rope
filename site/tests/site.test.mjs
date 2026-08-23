import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("builds a canonical Astro product site without ChatGPT Sites branding", async () => {
  const html = await read("../dist/index.html");

  assert.match(html, /<meta name="generator" content="Astro v7\./);
  assert.match(html, /<title>Velvet — Outcome assurance for autonomous agents<\/title>/);
  assert.match(html, /rel="canonical" href="https:\/\/shadowpath\.coriolislabs\.ca\/"/);
  assert.match(html, /Your agent passed policy/);
  assert.match(html, /CONTROL_FALSE_SUCCESS/);
  assert.doesNotMatch(html, /chatgpt\.site|vinext|next\/static/i);
});

test("keeps the replay route inventory aligned with the committed proof", async () => {
  const replay = await read("../src/scripts/replay.ts");
  const routes = replay.match(/\{ id: "[a-z0-9_]+", ingress:/g) ?? [];

  assert.equal(routes.length, 8);
  assert.match(replay, /matchMedia\("\(prefers-reduced-motion: reduce\)"\)/);
  assert.match(replay, /trackEvent\("replay_completed"\)/);
});

test("limits telemetry to an explicit privacy-safe event vocabulary", async () => {
  const worker = await read("../worker/index.ts");

  for (const event of [
    "replay_started",
    "replay_completed",
    "install_copied",
    "github_opened",
    "custom_effect_opened",
  ]) {
    assert.match(worker, new RegExp(`"${event}"`));
  }
  assert.match(worker, /url\.pathname !== "\/api\/events"/);
  assert.match(worker, /request\.method !== "POST"/);
  assert.doesNotMatch(worker, /request\.headers\.get/i);
});

test("ships custom-domain routing, hardening headers, and crawl metadata", async () => {
  const [wrangler, headers, robots, sitemap] = await Promise.all([
    read("../wrangler.jsonc"),
    read("../dist/_headers"),
    read("../dist/robots.txt"),
    read("../dist/sitemap.xml"),
  ]);

  assert.match(wrangler, /"pattern": "shadowpath\.coriolislabs\.ca"/);
  assert.match(wrangler, /"custom_domain": true/);
  assert.match(wrangler, /"run_worker_first": \["\/api\/\*"\]/);
  assert.match(headers, /Content-Security-Policy:/);
  assert.match(headers, /X-Frame-Options: DENY/);
  assert.match(robots, /Sitemap: https:\/\/shadowpath\.coriolislabs\.ca\/sitemap\.xml/);
  assert.match(sitemap, /<loc>https:\/\/shadowpath\.coriolislabs\.ca\/<\/loc>/);
});

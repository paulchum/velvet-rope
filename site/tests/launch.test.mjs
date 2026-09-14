import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";
const root = fileURLToPath(new URL("../dist/", import.meta.url));
const routes = ["/", "/pilot/", "/evidence/", "/investors/", "/trust/", "/contact/", "/replay/", "/protected-refunds/"];
const htmlFor = (route) => readFile(path.join(root, route, "index.html"), "utf8");
const source = (name) => readFile(new URL(name, import.meta.url), "utf8");

test("customer and investor entry points render with descriptive metadata", async () => {
  for (const route of routes) {
    const html = await htmlFor(route);
    assert.match(html, /<html[^>]*lang="en"/);
    assert.equal((html.match(/<h1(?:\s|>)/g) ?? []).length, 1, `${route}: one main heading`);
    assert.match(html, /name="description" content="[^"]{30,}"/);
    assert.ok(html.includes(`rel="canonical" href="https://shadowpath.coriolislabs.ca${route}"`), route);
    assert.doesNotMatch(html, /pipelock|GHSA-[a-z0-9-]+|CVE-\d{4}-\d+/i, "Private finding material must not enter launch pages");
  }
});

test("all internal rendered links and fragments resolve", async () => {
  for (const route of routes) {
    const html = await htmlFor(route);
    for (const [, raw] of html.matchAll(/\bhref="([^"]+)"/g)) {
      const url = new URL(raw.replaceAll("&amp;", "&"), `https://shadowpath.coriolislabs.ca${route}`);
      if (url.origin !== "https://shadowpath.coriolislabs.ca") continue;
      let target = path.join(root, decodeURIComponent(url.pathname));
      if ((await stat(target)).isDirectory()) target = path.join(target, "index.html");
      assert.ok((await stat(target)).isFile(), `${route} -> ${raw}`);
      if (url.hash && target.endsWith(".html")) {
        const targetHtml = await readFile(target, "utf8");
        const fragment = decodeURIComponent(url.hash.slice(1));
        assert.ok(targetHtml.includes(`id="${fragment}"`), `${route} -> missing ${raw}`);
      }
    }
  }
});

test("the commercial offer is bounded and consistently priced", async () => {
  for (const route of ["/", "/pilot/", "/investors/"]) {
    const html = await htmlFor(route);
    assert.ok(html.includes("C$7,500"), route);
  }
  const pilot = await htmlFor("/pilot/");
  assert.match(pilot, /one staging workflow/i);
  assert.match(pilot, /no automatic subscription or renewal/i);
  assert.match(pilot, /Indicative starting price/);
});

test("contact is an explicit client-only draft with a direct-email fallback", async () => {
  const html = await htmlFor("/contact/");
  const client = await source("../src/scripts/contact.ts");
  assert.match(html, /mailto:paulchum1@gmail\.com/);
  assert.match(html, /id="context"[^>]*required/);
  assert.match(html, /<noscript>/);
  assert.match(html, /id="draft-output"[^>]*hidden/);
  assert.match(client, /encodeURIComponent\(subject\)/);
  assert.match(client, /encodeURIComponent\(body\)/);
  assert.match(client, /reportValidity\(\)/);
  assert.match(client, /Nothing has been sent/);
  assert.doesNotMatch(client, /\bfetch\s*\(|XMLHttpRequest|sendBeacon|localStorage|sessionStorage|innerHTML/);
});

test("replay remains clearly recorded and exposes its existing control selectors", async () => {
  const html = await htmlFor("/replay/");
  assert.match(html, /does not execute new tests/);
  for (const selector of ["data-route-list", "data-run-proof", "data-reset-proof", "data-tested-count", "data-breach-count", "data-protected-status", "data-verdict", "data-console-state", "data-nav-toggle", "data-nav", "data-header", "data-copy-command", "data-command"]) {
    assert.ok(html.includes(selector), selector);
  }
});

test("sitemap includes every customer-facing route", async () => {
  const sitemap = await readFile(path.join(root, "sitemap.xml"), "utf8");
  for (const route of routes) assert.ok(sitemap.includes(`<loc>https://shadowpath.coriolislabs.ca${route}</loc>`), route);
});

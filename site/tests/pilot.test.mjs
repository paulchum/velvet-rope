import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildPilotInquiry, trackPilotEvent } from "../src/lib/pilot.ts";
import worker from "../worker/index.ts";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");
const emailAddress = "paul@coriolislabs.ca";
const pilotEvents = ["pilot_viewed", "pilot_email_opened", "pilot_inquiry_copied"];
const decodeAttribute = (value) => value.replaceAll("&amp;", "&");

test("a blank inquiry produces a usable draft addressed to Paul", () => {
  const inquiry = buildPilotInquiry();
  const mailto = new URL(inquiry.mailto);

  assert.equal(mailto.protocol, "mailto:");
  assert.equal(mailto.pathname, emailAddress);
  assert.equal(mailto.searchParams.get("subject"), "Velvet pilot — scope our agent workflow");
  assert.match(inquiry.body, /Team \/ company: Not specified yet\n/);
  assert.match(inquiry.body, /Workflow: Agent refunds\n/);
  assert.match(inquiry.body, /I'd like to discuss the workflow and the limits we need to test\./);
  assert.equal(mailto.searchParams.get("body"), inquiry.body);
  assert.equal(inquiry.copyText, `To: ${emailAddress}\nSubject: ${mailto.searchParams.get("subject")}\n\n${inquiry.body}`);
  assert.deepEqual(buildPilotInquiry({ company: "  ", details: "\n " }), inquiry);
});

test("reserved characters, Unicode, and header-looking lines remain email body text", () => {
  const company = "Équipe & Co. #1";
  const details = "Refund ¥500 & keep #audit intact.\r\nBcc: someone@example.com\nsubject=Replacement&to=elsewhere@example.com";
  const inquiry = buildPilotInquiry({ company, details });
  const mailto = new URL(inquiry.mailto);

  assert.equal(mailto.pathname, emailAddress);
  assert.equal(mailto.hash, "");
  assert.deepEqual([...mailto.searchParams.keys()], ["subject", "body"]);
  assert.equal(mailto.searchParams.get("subject"), "Velvet pilot — scope our agent workflow");
  assert.equal(mailto.searchParams.get("body"), inquiry.body);
  assert.ok(inquiry.body.includes(company));
  assert.ok(inquiry.body.includes(details));
});

test("drafts bound free text and accept only supported workflows", () => {
  const inquiry = buildPilotInquiry({
    company: `  ${"C".repeat(101)}  `,
    details: `  ${"D".repeat(601)}  `,
    workflow: "Agent refunds\nBcc: someone@example.com",
  });

  assert.match(inquiry.body, new RegExp(`Team / company: C{100}\\n`));
  assert.match(inquiry.body, new RegExp(`\\nD{600}\\n`));
  assert.doesNotMatch(inquiry.body, /C{101}|D{601}|Bcc:/);
  assert.match(inquiry.body, /Workflow: Agent refunds\n/);

  for (const workflow of ["Agent refunds", "Agent spending or payments", "Another consequential action"]) {
    assert.ok(buildPilotInquiry({ workflow }).body.includes(`Workflow: ${workflow}\n`));
  }
});

test("truncating text at an emoji boundary still yields a valid email draft", () => {
  for (const input of [
    { company: `${"A".repeat(99)}🚀` },
    { details: `${"B".repeat(599)}💸` },
  ]) {
    const inquiry = buildPilotInquiry(input);
    assert.equal(new URL(inquiry.mailto).searchParams.get("body"), inquiry.body);
    assert.equal(inquiry.body.isWellFormed(), true);
  }
});

test("browser telemetry sends only the event name without credentials", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response(null, { status: 204 }));

  for (const event of pilotEvents) trackPilotEvent(event);

  assert.equal(fetchMock.mock.callCount(), pilotEvents.length);
  for (const [index, call] of fetchMock.mock.calls.entries()) {
    const [url, options] = call.arguments;
    assert.equal(url, "/api/events");
    assert.equal(options.method, "POST");
    assert.equal(options.credentials, "omit");
    assert.deepEqual(JSON.parse(options.body), { event: pilotEvents[index] });
    assert.deepEqual(options.headers, { "content-type": "application/json" });
  }
});

test("the worker accepts pilot events while discarding inquiry text and identifiers", async (t) => {
  const infoMock = t.mock.method(console, "info", () => {});
  const privateText = "Private customer note: paul+prospect@example.com";

  for (const event of pilotEvents) {
    const response = await worker.fetch(new Request("https://shadowpath.coriolislabs.ca/api/events?company=private", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: "visitor=private", referer: "https://example.com/private" },
      body: JSON.stringify({ event, company: privateText, details: privateText, email: privateText, visitorId: "private", properties: { privateText } }),
    }), {});

    assert.equal(response.status, 204);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(await response.text(), "");
  }

  assert.deepEqual(infoMock.mock.calls.map(({ arguments: args }) => args), pilotEvents.map((event) => [JSON.stringify({ kind: "velvet_site_event", event })]));
});

test("the worker rejects arbitrary event content without logging it", async (t) => {
  const infoMock = t.mock.method(console, "info", () => {});
  for (const body of [
    JSON.stringify({ event: "pilot_submitted", details: "private inquiry" }),
    JSON.stringify({ event: "paul+prospect@example.com" }),
    JSON.stringify({ event: { message: "private inquiry" } }),
    "null",
    "{malformed",
  ]) {
    const response = await worker.fetch(new Request("https://shadowpath.coriolislabs.ca/api/events", { method: "POST", body }), {});
    assert.equal(response.status, 400);
  }
  assert.equal(infoMock.mock.callCount(), 0);
});

test("built pages expose a discoverable pilot path with a working no-JavaScript contact", async () => {
  const [home, proof, pilot, sitemap] = await Promise.all([
    read("../dist/index.html"),
    read("../dist/protected-refunds/index.html"),
    read("../dist/pilot/index.html"),
    read("../dist/sitemap.xml"),
  ]);

  for (const html of [home, proof]) assert.match(html, /<a\b[^>]*href="\/pilot\/(?:#[^"]*)?"/);
  assert.match(pilot, /rel="canonical" href="https:\/\/shadowpath\.coriolislabs\.ca\/pilot\/"/);
  assert.match(sitemap, /<loc>https:\/\/shadowpath\.coriolislabs\.ca\/pilot\/<\/loc>/);

  const emailLink = pilot.match(/<a\b[^>]*id="pilot-email"[^>]*>/)?.[0];
  assert.ok(emailLink, "the initial HTML must include the primary email action");
  const mailto = new URL(decodeAttribute(emailLink.match(/href="([^"]+)"/)[1]));
  assert.equal(mailto.protocol, "mailto:");
  assert.equal(mailto.pathname, emailAddress);
  assert.equal(mailto.searchParams.get("body"), buildPilotInquiry().body);
  assert.doesNotMatch(emailLink, /\bhidden\b|aria-disabled="true"/);
  assert.match(pilot, /href="mailto:paul@coriolislabs\.ca"/);

  // Optional fields cannot submit personal text through a native form, and stay
  // hidden until the draft-building script is ready to use them.
  assert.doesNotMatch(pilot, /<form\b/i);
  assert.match(pilot, /<div\b[^>]*id="inquiry-fields"[^>]*\bhidden(?:[\s=>])/);
  for (const id of ["pilot-company", "pilot-workflow", "pilot-details"]) {
    const field = pilot.match(new RegExp(`<(?:input|select|textarea)\\b[^>]*id="${id}"[^>]*>`))?.[0];
    assert.ok(field, `missing optional inquiry field ${id}`);
    assert.doesNotMatch(field, /\b(?:name|required|formaction)\s*[=>]/);
  }
});

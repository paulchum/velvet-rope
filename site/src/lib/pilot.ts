export const PILOT_EMAIL = "paul@coriolislabs.ca";
export const PILOT_SUBJECT = "Velvet pilot — scope our agent workflow";

export const PILOT_WORKFLOWS = [
  "Agent refunds",
  "Agent spending or payments",
  "Another consequential action",
] as const;

export const PILOT_EVENTS = [
  "pilot_viewed",
  "pilot_email_opened",
  "pilot_inquiry_copied",
] as const;

export function buildPilotInquiry(input: {
  company?: string;
  workflow?: string;
  details?: string;
} = {}) {
  // Keep mailto URLs practical, even when the helper is called outside the UI.
  // Restore well-formed UTF-16 if truncation splits an emoji's surrogate pair.
  const company = input.company?.trim().slice(0, 100).toWellFormed() || "Not specified yet";
  const workflow = PILOT_WORKFLOWS.find(value => value === input.workflow) ?? PILOT_WORKFLOWS[0];
  const details = input.details?.trim().slice(0, 600).toWellFormed() || "I'd like to discuss the workflow and the limits we need to test.";
  const body = [
    "Hi Paul,",
    "",
    "I'd like to explore a Velvet pilot for one agent workflow.",
    "",
    `Team / company: ${company}`,
    `Workflow: ${workflow}`,
    "",
    details,
    "",
    "Could we arrange a scoping conversation to discuss fit, the test environment, and next steps?",
  ].join("\n");

  return {
    body,
    mailto: `mailto:${PILOT_EMAIL}?subject=${encodeURIComponent(PILOT_SUBJECT)}&body=${encodeURIComponent(body)}`,
    copyText: `To: ${PILOT_EMAIL}\nSubject: ${PILOT_SUBJECT}\n\n${body}`,
  };
}

export function trackPilotEvent(event: typeof PILOT_EVENTS[number]): void {
  // Never include inquiry contents, email addresses, URLs, or visitor identifiers.
  void fetch("/api/events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ event }),
    credentials: "omit",
    keepalive: true,
  }).catch(() => undefined);
}

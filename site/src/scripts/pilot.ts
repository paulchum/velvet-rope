import { buildPilotInquiry, trackPilotEvent } from "../lib/pilot";

const fields = document.querySelector<HTMLElement>("#inquiry-fields")!;
const company = document.querySelector<HTMLInputElement>("#pilot-company")!;
const workflow = document.querySelector<HTMLSelectElement>("#pilot-workflow")!;
const details = document.querySelector<HTMLTextAreaElement>("#pilot-details")!;
const email = document.querySelector<HTMLAnchorElement>("#pilot-email")!;
const copy = document.querySelector<HTMLButtonElement>("#copy-inquiry")!;
const preview = document.querySelector<HTMLDetailsElement>("#inquiry-preview")!;
const draft = document.querySelector<HTMLTextAreaElement>("#inquiry-draft")!;
const status = document.querySelector<HTMLElement>("#inquiry-status")!;

function updateInquiry(): void {
  const inquiry = buildPilotInquiry({
    company: company.value,
    workflow: workflow.value,
    details: details.value,
  });
  email.href = inquiry.mailto;
  draft.value = inquiry.copyText;
  status.textContent = "";
}

fields.addEventListener("input", updateInquiry);
fields.addEventListener("change", updateInquiry);
email.addEventListener("click", () => {
  trackPilotEvent("pilot_email_opened");
  status.textContent = "Send the draft in your email app to contact Paul. If no app opened, copy the inquiry below.";
});
copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(draft.value);
    status.textContent = "Inquiry copied. Paste it into your email and send it to paul@coriolislabs.ca.";
    trackPilotEvent("pilot_inquiry_copied");
  } catch {
    preview.open = true;
    draft.focus();
    draft.select();
    status.textContent = "Automatic copying is unavailable. The inquiry is selected below; copy it and send it from your email.";
  }
});

updateInquiry();
fields.hidden = false;
copy.hidden = false;
preview.hidden = false;
trackPilotEvent("pilot_viewed");

/** Client-only email drafting. User text is never rendered as HTML or sent to a server. */
const form = document.querySelector<HTMLFormElement>("#contact-form");
if (form) {
  const interest = form.querySelector<HTMLSelectElement>("#interest");
  const prepare = form.querySelector<HTMLButtonElement>("[data-prepare]");
  const output = document.querySelector<HTMLElement>("#draft-output");
  const text = document.querySelector<HTMLTextAreaElement>("#draft-text");
  const mail = document.querySelector<HTMLAnchorElement>("#draft-mailto");
  const status = document.querySelector<HTMLElement>("#draft-status");
  const copy = document.querySelector<HTMLButtonElement>("#copy-draft");
  const reset = document.querySelector<HTMLButtonElement>("#reset-draft");
  const recipient = form.dataset.recipient;
  if (interest && prepare && output && text && mail && status && copy && reset && recipient) {
    const subjects: Record<string, string> = {
      pilot: "Velvet pilot scoping",
      investor: "Velvet pre-seed conversation",
      technical: "Velvet technical evaluation",
    };
    const intent = new URLSearchParams(window.location.search).get("intent");
    if (intent === "pilot" || intent === "investor" || intent === "technical") interest.value = intent;
    prepare.disabled = false;
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const data = new FormData(form);
      const subject = subjects[String(data.get("interest"))] ?? "Velvet technical evaluation";
      const organization = String(data.get("organization") ?? "").trim();
      const context = String(data.get("context") ?? "").trim();
      if (context.length < 20) {
        status.textContent = "Please add at least 20 characters of context before preparing a draft.";
        return;
      }
      const body = ["Hi Paul,", "", organization ? `Company / fund: ${organization}` : "", context, "", `Timing: ${String(data.get("timing") ?? "Not specified")}`, "", "Best,"].filter((line, index, lines) => line || lines[index - 1] !== "").join("\n");
      text.value = `To: ${recipient}\nSubject: ${subject}\n\n${body}`;
      mail.href = `mailto:${recipient}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
      output.hidden = false;
      status.textContent = "Draft ready. Nothing has been sent. Review it below, then open your email app or copy the draft.";
      text.focus();
    });
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text.value);
        status.textContent = "Draft copied. Nothing has been sent.";
      } catch {
        text.focus();
        text.select();
        status.textContent = "Clipboard access was unavailable. The draft is selected for manual copying.";
      }
    });
    reset.addEventListener("click", () => {
      form.reset();
      text.value = "";
      mail.href = `mailto:${recipient}`;
      output.hidden = true;
      status.textContent = "Draft cleared. Nothing has been sent.";
      interest.focus();
    });
  }
}

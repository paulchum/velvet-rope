const ROUTES = [
  { id: "browser_automation", ingress: "Operator web UI" },
  { id: "alternate_api", ingress: "Alternate REST API" },
  { id: "database_mutation", ingress: "Direct database session" },
  { id: "queue_insertion", ingress: "Queue worker" },
  { id: "webhook_creation", ingress: "Webhook registration" },
  { id: "admin_console", ingress: "Privileged admin console" },
  { id: "credential_delegation", ingress: "Delegated credential" },
  { id: "human_operator_message", ingress: "Human operator message" },
] as const;

type SiteEvent =
  | "replay_started"
  | "replay_completed"
  | "install_copied"
  | "github_opened"
  | "custom_effect_opened";

function select<ElementType extends Element>(selector: string): ElementType {
  const element = document.querySelector<ElementType>(selector);
  if (!element) throw new Error(`Missing required site element: ${selector}`);
  return element;
}

const consolePanel = select<HTMLElement>(".proof-console");
const routeList = select<HTMLOListElement>("[data-route-list]");
const runButton = select<HTMLButtonElement>("[data-run-proof]");
const resetButton = select<HTMLButtonElement>("[data-reset-proof]");
const testedCount = select<HTMLElement>("[data-tested-count]");
const breachCount = select<HTMLElement>("[data-breach-count]");
const protectedStatus = select<HTMLElement>("[data-protected-status]");
const verdict = select<HTMLElement>("[data-verdict]");
const consoleState = select<HTMLElement>("[data-console-state]");
const navToggle = select<HTMLButtonElement>("[data-nav-toggle]");
const nav = select<HTMLElement>("[data-nav]");
const header = select<HTMLElement>("[data-header]");
const copyButton = select<HTMLButtonElement>("[data-copy-command]");
const command = select<HTMLElement>("[data-command]");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

let replayToken = 0;

function trackEvent(event: SiteEvent): void {
  void fetch("/api/events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ event }),
    credentials: "omit",
    keepalive: true,
  }).catch(() => undefined);
}

function buildRouteList(): void {
  routeList.replaceChildren(
    ...ROUTES.map((route, index) => {
      const item = document.createElement("li");
      item.className = "route-item";
      item.dataset.routeId = route.id;

      const routeIndex = document.createElement("span");
      routeIndex.className = "route-index";
      routeIndex.textContent = String(index + 1).padStart(2, "0");

      const ingress = document.createElement("span");
      ingress.className = "route-ingress";
      ingress.textContent = route.ingress;

      const result = document.createElement("span");
      result.className = "route-result";
      result.textContent = "WAIT";

      item.append(routeIndex);
      item.append(ingress);
      item.append(result);
      return item;
    }),
  );
}

function showReadyState(): void {
  runButton.disabled = false;
  runButton.textContent = "Run eight-path proof";
  testedCount.textContent = "0";
  breachCount.textContent = "0";
  protectedStatus.textContent = "NOT TESTED";
  protectedStatus.classList.remove("is-blocked");
  verdict.textContent = "WAITING FOR REPLAY";
  verdict.classList.remove("is-breach");
  consoleState.textContent = "READY";
  consoleState.classList.remove("is-running", "is-complete");
  consolePanel.setAttribute("aria-busy", "false");
  buildRouteList();
}

function resetProof(): void {
  replayToken += 1;
  showReadyState();
}

function wait(duration: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, duration));
}

async function runProof(): Promise<void> {
  const token = replayToken + 1;
  replayToken = token;
  showReadyState();
  runButton.disabled = true;
  runButton.textContent = "Running proof…";
  consoleState.textContent = "RUNNING";
  consoleState.classList.add("is-running");
  consolePanel.setAttribute("aria-busy", "true");
  trackEvent("replay_started");

  if (!prefersReducedMotion.matches) await wait(350);
  if (token !== replayToken) return;

  protectedStatus.textContent = "BLOCKED";
  protectedStatus.classList.add("is-blocked");

  const routeItems = [...routeList.querySelectorAll<HTMLElement>(".route-item")];
  for (const [index, item] of routeItems.entries()) {
    if (token !== replayToken) return;
    const result = item.querySelector<HTMLElement>(".route-result");
    if (!result) continue;

    item.classList.add("is-testing");
    result.textContent = "TESTING";
    if (!prefersReducedMotion.matches) await wait(230);
    if (token !== replayToken) return;

    item.classList.remove("is-testing");
    item.classList.add("is-breach");
    result.textContent = "BREACH";
    testedCount.textContent = String(index + 1);
    breachCount.textContent = String(index + 1);
  }

  verdict.textContent = "CONTROL_FALSE_SUCCESS";
  verdict.classList.add("is-breach");
  consoleState.textContent = "COMPLETE";
  consoleState.classList.remove("is-running");
  consoleState.classList.add("is-complete");
  consolePanel.setAttribute("aria-busy", "false");
  runButton.disabled = false;
  runButton.textContent = "Replay again";
  trackEvent("replay_completed");
}

async function copyCommand(): Promise<void> {
  const original = copyButton.textContent;
  try {
    await navigator.clipboard.writeText(command.textContent?.trim() ?? "");
    copyButton.textContent = "Copied";
    trackEvent("install_copied");
  } catch {
    copyButton.textContent = "Select command to copy";
  }
  window.setTimeout(() => {
    copyButton.textContent = original;
  }, 1800);
}

function closeNav(): void {
  navToggle.setAttribute("aria-expanded", "false");
  nav.classList.remove("is-open");
}

function toggleNav(): void {
  const expanded = navToggle.getAttribute("aria-expanded") === "true";
  navToggle.setAttribute("aria-expanded", String(!expanded));
  nav.classList.toggle("is-open", !expanded);
}

function updateHeader(): void {
  header.classList.toggle("is-scrolled", window.scrollY > 8);
}

showReadyState();
runButton.addEventListener("click", () => void runProof());
resetButton.addEventListener("click", resetProof);
copyButton.addEventListener("click", () => void copyCommand());
navToggle.addEventListener("click", toggleNav);
nav.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeNav));
document.querySelectorAll<HTMLElement>("[data-track-event]").forEach((element) => {
  element.addEventListener("click", () => {
    trackEvent(element.dataset.trackEvent as SiteEvent);
  });
});
window.addEventListener("scroll", updateHeader, { passive: true });
updateHeader();

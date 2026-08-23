const ROUTES = [
  { id: "browser_automation", ingress: "Operator web UI" },
  { id: "alternate_api", ingress: "Alternate REST API" },
  { id: "database_mutation", ingress: "Direct database session" },
  { id: "queue_insertion", ingress: "Queue worker" },
  { id: "webhook_creation", ingress: "Webhook registration" },
  { id: "admin_console", ingress: "Privileged admin console" },
  { id: "credential_delegation", ingress: "Delegated credential" },
  { id: "human_operator_message", ingress: "Human operator message" },
];

const routeList = document.querySelector("[data-route-list]");
const runButton = document.querySelector("[data-run-proof]");
const resetButton = document.querySelector("[data-reset-proof]");
const testedCount = document.querySelector("[data-tested-count]");
const breachCount = document.querySelector("[data-breach-count]");
const protectedStatus = document.querySelector("[data-protected-status]");
const verdict = document.querySelector("[data-verdict]");
const consoleState = document.querySelector("[data-console-state]");
const navToggle = document.querySelector("[data-nav-toggle]");
const nav = document.querySelector("[data-nav]");
const header = document.querySelector("[data-header]");
const copyButton = document.querySelector("[data-copy-command]");
const command = document.querySelector("[data-command]");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

let replayToken = 0;

function buildRouteList() {
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

      item.append(routeIndex, ingress, result);
      return item;
    }),
  );
}

function resetProof() {
  replayToken += 1;
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
  buildRouteList();
}

function wait(duration) {
  return new Promise((resolve) => window.setTimeout(resolve, duration));
}

async function runProof() {
  const token = replayToken + 1;
  replayToken = token;
  resetProof();
  replayToken = token;
  runButton.disabled = true;
  runButton.textContent = "Running proof…";
  consoleState.textContent = "RUNNING";
  consoleState.classList.add("is-running");

  if (!prefersReducedMotion.matches) {
    await wait(350);
  }
  if (token !== replayToken) return;

  protectedStatus.textContent = "BLOCKED";
  protectedStatus.classList.add("is-blocked");

  const routeItems = [...routeList.querySelectorAll(".route-item")];
  for (const [index, item] of routeItems.entries()) {
    if (token !== replayToken) return;
    item.classList.add("is-testing");
    item.querySelector(".route-result").textContent = "TESTING";
    if (!prefersReducedMotion.matches) {
      await wait(230);
    }
    if (token !== replayToken) return;
    item.classList.remove("is-testing");
    item.classList.add("is-breach");
    item.querySelector(".route-result").textContent = "BREACH";
    testedCount.textContent = String(index + 1);
    breachCount.textContent = String(index + 1);
  }

  verdict.textContent = "CONTROL_FALSE_SUCCESS";
  verdict.classList.add("is-breach");
  consoleState.textContent = "COMPLETE";
  consoleState.classList.remove("is-running");
  consoleState.classList.add("is-complete");
  runButton.disabled = false;
  runButton.textContent = "Replay again";
}

async function copyCommand() {
  const original = copyButton.textContent;
  try {
    await navigator.clipboard.writeText(command.textContent.trim());
    copyButton.textContent = "Copied";
  } catch {
    copyButton.textContent = "Select command to copy";
  }
  window.setTimeout(() => {
    copyButton.textContent = original;
  }, 1800);
}

function toggleNav() {
  const expanded = navToggle.getAttribute("aria-expanded") === "true";
  navToggle.setAttribute("aria-expanded", String(!expanded));
  nav.classList.toggle("is-open", !expanded);
}

function closeNav() {
  navToggle.setAttribute("aria-expanded", "false");
  nav.classList.remove("is-open");
}

function updateHeader() {
  header.classList.toggle("is-scrolled", window.scrollY > 8);
}

buildRouteList();
runButton.addEventListener("click", runProof);
resetButton.addEventListener("click", resetProof);
copyButton.addEventListener("click", copyCommand);
navToggle.addEventListener("click", toggleNav);
nav.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeNav));
window.addEventListener("scroll", updateHeader, { passive: true });
updateHeader();

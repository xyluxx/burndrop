// The options page: the list of protected relays, and verify mode.

import { loadOrigins, onOriginsChanged, saveOrigins } from "./config.js";
import type { Reply, SyncOriginsMessage } from "./messages.js";
import { hostPattern, normalizeOrigin } from "./origins.js";
import { loadBundledMeta, verifyRelay, type PageMeta, type Verification } from "./verify.js";

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) {
    throw new Error(`missing element ${id}`);
  }
  return e as T;
}

const list = el<HTMLUListElement>("origins");
const empty = el<HTMLParagraphElement>("empty");
const addForm = el<HTMLFormElement>("add-form");
const originInput = el<HTMLInputElement>("origin");
const addStatus = el<HTMLParagraphElement>("add-status");
const verifyForm = el<HTMLFormElement>("verify-form");
const verifyInput = el<HTMLInputElement>("verify-origin");
const verifyButton = el<HTMLButtonElement>("verify");
const verifyResult = el<HTMLDivElement>("verify-result");

// Mirrors storage so the duplicate check in addOrigin needs no await before
// permissions.request, which browsers only honour inside the user's gesture.
let current: string[] = [];
let bundled: PageMeta | null = null;

async function render(): Promise<void> {
  current = await loadOrigins();
  list.replaceChildren(...current.map(item));
  empty.hidden = current.length > 0;
}

function item(origin: string): HTMLLIElement {
  const li = document.createElement("li");
  const name = document.createElement("span");
  name.className = "origin";
  name.textContent = origin;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn-secondary";
  remove.textContent = "Remove";
  remove.setAttribute("aria-label", `Remove ${origin}`);
  remove.addEventListener("click", () => run(removeOrigin(origin), addStatus));
  li.append(name, remove);
  return li;
}

async function addOrigin(raw: string): Promise<void> {
  const origin = normalizeOrigin(raw);
  if (current.includes(origin)) {
    status(addStatus, `${origin} is already protected.`, "ok");
    return;
  }
  const granted = await chrome.permissions.request({ origins: [hostPattern(origin, __BROWSER__)] });
  if (!granted) {
    status(addStatus, `Without permission for ${origin} the extension cannot see its links. Nothing was added.`, "error");
    return;
  }
  const origins = await loadOrigins();
  if (!origins.includes(origin)) {
    await saveOrigins([...origins, origin]);
    await requestSync();
  }
  originInput.value = "";
  status(addStatus, `${origin} is now protected.`, "ok");
}

async function removeOrigin(origin: string): Promise<void> {
  await saveOrigins((await loadOrigins()).filter((o) => o !== origin));
  await requestSync();
  await releasePermission(origin);
  status(addStatus, `${origin} removed.`, "ok");
}

// The background owns the registrations; this asks it to make them match storage.
async function requestSync(): Promise<void> {
  const message: SyncOriginsMessage = { type: "sync-origins" };
  const reply = (await chrome.runtime.sendMessage(message)) as Reply;
  if (!reply.ok) {
    throw new Error(reply.error);
  }
}

async function releasePermission(origin: string): Promise<void> {
  try {
    await chrome.permissions.remove({ origins: [hostPattern(origin, __BROWSER__)] });
  } catch {
    // Chrome refuses to remove a permission the manifest requires, which is
    // how the test build grants localhost. The registration is already gone,
    // so the origin is inert either way.
  }
}

async function verify(raw: string): Promise<void> {
  const origin = normalizeOrigin(raw);
  const granted = await chrome.permissions.request({ origins: [hostPattern(origin, __BROWSER__)] });
  if (!granted) {
    throw new Error(`Without permission for ${origin} the page cannot be fetched.`);
  }
  verifyButton.disabled = true;
  showVerdict(`Fetching ${origin}/drop`, "");
  try {
    bundled ??= await loadBundledMeta();
    renderVerification(origin, bundled, await verifyRelay(origin, bundled));
  } finally {
    verifyButton.disabled = false;
    // Verify borrows the permission; only protected relays keep it.
    if (!current.includes(origin)) {
      await releasePermission(origin);
    }
  }
}

function renderVerification(origin: string, meta: PageMeta, { verdict, claim }: Verification): void {
  if (verdict.kind === "verified") {
    showVerdict(`Verified: ${origin} serves the bundled page (version ${meta.version}).`, "ok");
  } else if (verdict.kind === "mismatch") {
    showVerdict(`Mismatch: the page ${origin} serves is not the bundled page. Do not paste a secret into it.`, "bad");
  } else {
    showVerdict(`Could not fetch ${origin}/drop: ${verdict.reason}.`, "bad");
  }
  const rows: Array<[string, string]> = [];
  if (verdict.kind !== "unreachable") {
    rows.push(["Served page", verdict.served]);
  }
  rows.push(["Bundled page", meta.sha256]);
  if ("error" in claim) {
    rows.push(["Relay's claim", `none (${claim.error})`]);
  } else {
    const agreement = verdict.kind === "unreachable" ? "" : claim.sha256 === verdict.served ? ", which agrees with what it served" : ", which does not agree with what it served";
    rows.push(["Relay's claim", `${claim.sha256} (version ${claim.version || "not stated"})${agreement}`]);
  }
  const dl = document.createElement("dl");
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.className = "hash";
    dd.textContent = value;
    dl.append(dt, dd);
  }
  verifyResult.append(dl);
}

function showVerdict(text: string, tone: "" | "ok" | "bad"): void {
  const p = document.createElement("p");
  p.className = tone ? `verdict ${tone}` : "verdict";
  p.textContent = text;
  verifyResult.replaceChildren(p);
  verifyResult.hidden = false;
}

function status(target: HTMLElement, text: string, tone: "ok" | "error"): void {
  target.textContent = text;
  target.className = `status ${tone}`;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function run(task: Promise<void>, target: HTMLElement): void {
  task.catch((err: unknown) => status(target, describe(err), "error"));
}

addForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  run(addOrigin(originInput.value), addStatus);
});
verifyForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  verify(verifyInput.value).catch((err: unknown) => showVerdict(describe(err), "bad"));
});
onOriginsChanged(() => run(render(), addStatus));
run(render(), addStatus);
el("version").textContent = `burndrop extension ${__VERSION__}`;
run(
  loadBundledMeta().then((meta) => {
    bundled = meta;
    el("bundled").textContent = `bundled page ${meta.version}, sha256 ${meta.sha256}`;
  }),
  addStatus,
);

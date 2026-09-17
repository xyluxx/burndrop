// The background: rebuilds content script registrations from storage, and
// moves a tab from a relay's page to the bundled page when the content
// script reports a link. Chrome runs this as a service worker and Firefox as
// an event page; nothing here depends on the difference.

import { loadOrigins } from "./config.js";
import { isMessage, type OpenLinkMessage, type Reply } from "./messages.js";
import { normalizeOrigin, originMatches } from "./origins.js";
import { syncRegistrations } from "./registry.js";

// One reconciliation at a time: startup and an options page change can overlap.
let syncing: Promise<void> = Promise.resolve();
function sync(): Promise<void> {
  syncing = syncing.then(syncRegistrations, syncRegistrations);
  return syncing;
}

function syncInBackground(): void {
  sync().catch((err: unknown) => console.error("burndrop: content script registration failed", err));
}

chrome.runtime.onInstalled.addListener(syncInBackground);
chrome.runtime.onStartup.addListener(syncInBackground);
chrome.action.onClicked.addListener(() => void chrome.runtime.openOptionsPage());
chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse: (reply: Reply) => void) => {
  handle(message, sender).then(sendResponse, (err: unknown) => sendResponse({ ok: false, error: String(err) }));
  return true;
});

// Messages only arrive from this extension's own content scripts and pages,
// so the shape check guards against version skew, not against strangers.
async function handle(message: unknown, sender: chrome.runtime.MessageSender): Promise<Reply> {
  if (!isMessage(message)) {
    return { ok: false, error: "unrecognised message" };
  }
  if (message.type === "sync-origins") {
    await sync();
    return { ok: true };
  }
  return openLink(message, sender);
}

async function openLink(message: OpenLinkMessage, sender: chrome.runtime.MessageSender): Promise<Reply> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) {
    return { ok: false, error: "the link did not come from a tab" };
  }
  let origin: string;
  try {
    origin = normalizeOrigin(message.origin);
  } catch (err) {
    return { ok: false, error: String(err) };
  }
  const origins = await loadOrigins();
  if (!origins.some((configured) => originMatches(configured, origin, __BROWSER__))) {
    await sync();
    return { ok: false, error: `${origin} is not a configured relay` };
  }
  // The fragment is passed through untouched: the bundled page parses it
  // exactly as the hosted page would have, then removes it from the URL.
  const query = new URLSearchParams({ mode: message.mode, origin });
  await chrome.tabs.update(tabId, { url: `${chrome.runtime.getURL("page.html")}?${query}#${message.fragment}` });
  return { ok: true };
}

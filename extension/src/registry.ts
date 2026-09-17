// Keeps the registered content scripts equal to the origins in storage. The
// background runs this at install and at browser start, and whenever the
// options page changes the list, so a registration cannot outlive its origin.

import { loadOrigins } from "./config.js";
import { contentScriptPatterns, SCRIPT_ID_PREFIX, scriptId } from "./origins.js";

function scriptFor(origin: string): chrome.scripting.RegisteredContentScript {
  return {
    id: scriptId(origin),
    js: ["content.js"],
    matches: contentScriptPatterns(origin, __BROWSER__),
    runAt: "document_start",
    allFrames: false,
    persistAcrossSessions: true,
  };
}

export async function syncRegistrations(): Promise<void> {
  const wanted = new Map((await loadOrigins()).map((origin) => [scriptId(origin), scriptFor(origin)]));
  const registered = await chrome.scripting.getRegisteredContentScripts();
  // A registration whose patterns differ from what this version derives (for
  // example after an update changed the port rule) is replaced, not kept.
  const stale = registered.filter((s) => s.id.startsWith(SCRIPT_ID_PREFIX) && !samePatterns(s, wanted.get(s.id))).map((s) => s.id);
  if (stale.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: stale });
  }
  const kept = new Set(registered.map((s) => s.id).filter((id) => !stale.includes(id)));
  const missing = [...wanted.values()].filter((s) => !kept.has(s.id));
  if (missing.length > 0) {
    await chrome.scripting.registerContentScripts(missing);
  }
}

function samePatterns(registered: chrome.scripting.RegisteredContentScript, wanted: chrome.scripting.RegisteredContentScript | undefined): boolean {
  return wanted !== undefined && JSON.stringify(registered.matches) === JSON.stringify(wanted.matches);
}

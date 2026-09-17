// Runs at document_start on the /drop and /reveal paths of a configured
// relay, which is before anything the relay served can execute. It stops the
// document, hands the link to the background, and the background moves the
// tab to the bundled page. The fragment comes from location.hash, which a
// content script can read because it shares the page's window.

import { modeFor, type OpenLinkMessage, type Reply } from "./messages.js";

const mode = modeFor(location.pathname);
if (mode !== null) {
  window.stop();
  const message: OpenLinkMessage = { type: "open-link", origin: location.origin, mode, fragment: location.hash.slice(1) };
  chrome.runtime.sendMessage(message).then(
    (reply: Reply) => {
      if (reply.ok) {
        return;
      }
      // Only a registration that outlived its origin in storage is refused.
      // The background has just removed it, so a reload shows the relay's own
      // page. A reload that is refused again stays stopped rather than loop.
      const entry = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
      if (entry?.type === "reload") {
        console.error(`burndrop: ${reply.error}`);
      } else {
        location.reload();
      }
    },
    (err: unknown) => console.error("burndrop: the extension did not answer", err),
  );
}

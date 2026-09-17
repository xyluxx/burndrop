// Messages between the content script, the options page, and the background.

export type Mode = "drop" | "reveal";

export interface OpenLinkMessage {
  type: "open-link";
  origin: string;
  mode: Mode;
  fragment: string;
}

export interface SyncOriginsMessage {
  type: "sync-origins";
}

export type Message = OpenLinkMessage | SyncOriginsMessage;

export type Reply = { ok: true } | { ok: false; error: string };

export function isMessage(value: unknown): value is Message {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const m = value as Record<string, unknown>;
  if (m["type"] === "sync-origins") {
    return true;
  }
  return m["type"] === "open-link" && typeof m["origin"] === "string" && (m["mode"] === "drop" || m["mode"] === "reveal") && typeof m["fragment"] === "string";
}

/** modeFor maps the two paths the relay serves the page on to a mode; any other path is left alone. */
export function modeFor(pathname: string): Mode | null {
  const path = pathname.replace(/\/$/, "");
  if (path === "/drop") return "drop";
  if (path === "/reveal") return "reveal";
  return null;
}

// Link parsing for the page. Mirrors internal/link in Go: the fragment holds
// key=value pairs, unknown or duplicate fields are rejected, binary fields
// must have their exact length, and text fields are bounded.

import * as b64 from "./base64.js";
import { validateName, validateRetention, validateText, validToken, KEY_SIZE } from "./crypto.js";

export class LinkError extends Error {}

export interface DropLink {
  kind: "drop";
  relay: string | null;
  id: string;
  uploadToken: string;
  recipientKey: Uint8Array;
  name: string;
  purpose: string;
  storage: string;
  retention: string;
}

export interface RevealLink {
  kind: "reveal";
  relay: string | null;
  id: string;
  revealToken: string;
  key: Uint8Array;
  name: string;
  keepsCopy: boolean;
}

export type ParsedLink = DropLink | RevealLink;

const VERSION = "1";

/**
 * normalizeOrigin accepts scheme://host[:port], lowercases it, drops default
 * ports, and allows http only for localhost and loopback addresses.
 */
export function normalizeOrigin(s: string): string {
  if (s.length > 512) {
    throw new LinkError("origin too long");
  }
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new LinkError("origin is not a URL");
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) {
    throw new LinkError("origin must be scheme://host[:port] only");
  }
  const scheme = u.protocol.replace(":", "").toLowerCase();
  const host = u.hostname.toLowerCase();
  if (scheme === "http") {
    if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") {
      throw new LinkError("http is only allowed for localhost");
    }
  } else if (scheme !== "https") {
    throw new LinkError("origin scheme must be https");
  }
  // URL already strips default ports; u.port is empty for them.
  const port = u.port;
  return port ? `${scheme}://${host}:${port}` : `${scheme}://${host}`;
}

function parseFields(frag: string, allowed: string[]): Map<string, string> {
  if (frag === "") {
    throw new LinkError("empty fragment");
  }
  const out = new Map<string, string>();
  for (const part of frag.split("&")) {
    const eq = part.indexOf("=");
    if (eq <= 0) {
      throw new LinkError("malformed field");
    }
    const key = part.slice(0, eq);
    if (!allowed.includes(key)) {
      throw new LinkError(`unknown field ${key}`);
    }
    if (out.has(key)) {
      throw new LinkError(`duplicate field ${key}`);
    }
    let value: string;
    try {
      value = decodeURIComponent(part.slice(eq + 1).replace(/\+/g, " "));
    } catch {
      throw new LinkError(`field ${key} is not valid percent encoding`);
    }
    out.set(key, value);
  }
  if (out.get("v") !== VERSION) {
    throw new LinkError("unsupported link version");
  }
  return out;
}

function required(m: Map<string, string>, keys: string[]): void {
  for (const k of keys) {
    if (!m.get(k)) {
      throw new LinkError(`missing field ${k}`);
    }
  }
}

function decodeKey(s: string): Uint8Array {
  if (s.length !== 43) {
    throw new LinkError("key must be 43 characters");
  }
  // 43 base64url characters decode to exactly KEY_SIZE bytes.
  try {
    return b64.decode(s);
  } catch {
    throw new LinkError("key is not base64url");
  }
}

function relayField(m: Map<string, string>): string | null {
  const r = m.get("r");
  return r ? normalizeOrigin(r) : null;
}

export function parseDropFragment(frag: string): DropLink {
  const m = parseFields(frag, ["v", "i", "u", "k", "n", "p", "s", "t", "r"]);
  required(m, ["i", "u", "k", "n", "t"]);
  const id = m.get("i")!;
  const uploadToken = m.get("u")!;
  if (!validToken(id) || !validToken(uploadToken)) {
    throw new LinkError("malformed id or token");
  }
  const d: DropLink = {
    kind: "drop",
    relay: relayField(m),
    id,
    uploadToken,
    recipientKey: decodeKey(m.get("k")!),
    name: m.get("n")!,
    purpose: m.get("p") ?? "",
    storage: m.get("s") ?? "",
    retention: m.get("t")!,
  };
  try {
    validateName(d.name);
    validateText("purpose", d.purpose);
    validateText("storage", d.storage);
    validateRetention(d.retention);
  } catch (err) {
    throw new LinkError((err as Error).message);
  }
  return d;
}

export function parseRevealFragment(frag: string): RevealLink {
  const m = parseFields(frag, ["v", "i", "o", "k", "n", "c", "r"]);
  required(m, ["i", "o", "k", "n", "c"]);
  const id = m.get("i")!;
  const revealToken = m.get("o")!;
  if (!validToken(id) || !validToken(revealToken)) {
    throw new LinkError("malformed id or token");
  }
  const c = m.get("c");
  if (c !== "0" && c !== "1") {
    throw new LinkError("field c must be 0 or 1");
  }
  const r: RevealLink = {
    kind: "reveal",
    relay: relayField(m),
    id,
    revealToken,
    key: decodeKey(m.get("k")!),
    name: m.get("n")!,
    keepsCopy: c === "1",
  };
  try {
    validateName(r.name);
  } catch (err) {
    throw new LinkError((err as Error).message);
  }
  return r;
}

/** parseLink parses a full URL and returns the link plus the page origin. */
export function parseLink(raw: string): { link: ParsedLink; pageOrigin: string } {
  if (raw.length > 8192) {
    throw new LinkError("link too long");
  }
  const hash = raw.indexOf("#");
  if (hash < 0) {
    throw new LinkError("no fragment");
  }
  const base = raw.slice(0, hash);
  const frag = raw.slice(hash + 1);
  let u: URL;
  try {
    u = new URL(base);
  } catch {
    throw new LinkError("not a URL");
  }
  if (u.search || u.username || u.password) {
    throw new LinkError("links carry no query string or userinfo");
  }
  const pageOrigin = normalizeOrigin(`${u.protocol}//${u.host}`);
  const path = u.pathname.replace(/\/$/, "");
  if (path === "/drop") {
    return { link: parseDropFragment(frag), pageOrigin };
  }
  if (path === "/reveal") {
    return { link: parseRevealFragment(frag), pageOrigin };
  }
  throw new LinkError("path must be /drop or /reveal");
}

function encodeFields(fields: Array<[string, string]>): string {
  return fields.map(([k, v]) => `${k}=${encodeURIComponent(v).replace(/%20/g, "+")}`).join("&");
}

export function buildDropLink(pageOrigin: string, d: Omit<DropLink, "kind">): string {
  const fields: Array<[string, string]> = [
    ["v", VERSION],
    ["i", d.id],
    ["u", d.uploadToken],
    ["k", b64.encode(d.recipientKey)],
    ["n", d.name],
    ["p", d.purpose],
    ["s", d.storage],
    ["t", d.retention],
  ];
  if (d.relay) {
    fields.push(["r", d.relay]);
  }
  return `${normalizeOrigin(pageOrigin)}/drop#${encodeFields(fields)}`;
}

export function buildRevealLink(pageOrigin: string, r: Omit<RevealLink, "kind">): string {
  const fields: Array<[string, string]> = [
    ["v", VERSION],
    ["i", r.id],
    ["o", r.revealToken],
    ["k", b64.encode(r.key)],
    ["n", r.name],
    ["c", r.keepsCopy ? "1" : "0"],
  ];
  if (r.relay) {
    fields.push(["r", r.relay]);
  }
  return `${normalizeOrigin(pageOrigin)}/reveal#${encodeFields(fields)}`;
}

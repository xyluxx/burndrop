/**
 * Builds and parses burndrop links.
 *
 * Everything a client needs travels after the # in the URL, so no server,
 * proxy, or link scanner ever receives an identifier, a token, or a key. See
 * the crypto spec section 5.6 for the format. Parsing is strict, exactly as
 * in the Go reference (internal/link/link.go): the version must be 1, every
 * required field must be present exactly once, no unknown fields are
 * allowed, binary fields must have their exact length, text fields are
 * bounded, and origins must be https (http only for localhost).
 *
 * No Node-only imports: the browser page can reuse this module.
 */
import { decodeBase64Url, encodeBase64Url } from "./base64url.js";
import { validateName, validateRetention, validateText } from "./envelope.js";
import { LinkError } from "./errors.js";

/** Link version, kinds, and page paths. */
export const LINK_VERSION = "1";
export const PATH_DROP = "/drop";
export const PATH_REVEAL = "/reveal";

/** Encoded length of a token or identifier (16 bytes, 22 characters). */
export const TOKEN_LEN = 22;
export const TOKEN_BYTES = 16;
const KEY_LEN = 43;
const KEY_BYTES = 32;
const SALT_LEN = 22;
const SALT_BYTES = 16;

/**
 * A human-to-agent link: the agent's request public key plus what the page
 * must display.
 */
export interface DropLink {
  /** Relay origin; undefined means "same as the page origin". */
  relay?: string;
  id: string;
  uploadToken: string;
  /** 32 bytes. */
  recipientKey: Uint8Array;
  name: string;
  purpose: string;
  storage: string;
  retention: string;
}

/** An agent-to-human link: the reveal token and the decryption key. */
export interface RevealLink {
  relay?: string;
  id: string;
  revealToken: string;
  /** 32 bytes. */
  key: Uint8Array;
  name: string;
  keepsCopy: boolean;
  /** 16 bytes when the reveal needs the password the human set. */
  salt?: Uint8Array;
}

/** The result of parseLink: exactly one kind. */
export type ParsedLink =
  | { kind: "drop"; pageOrigin: string; drop: DropLink }
  | { kind: "reveal"; pageOrigin: string; reveal: RevealLink };

/**
 * Reports whether s is a well-formed token or identifier: exactly TOKEN_LEN
 * characters of canonical base64url decoding to TOKEN_BYTES bytes.
 */
export function isValidToken(s: string): boolean {
  if (s.length !== TOKEN_LEN) {
    return false;
  }
  try {
    return decodeBase64Url(s).length === TOKEN_BYTES;
  } catch {
    return false;
  }
}

/**
 * Validates an origin and returns it as scheme://host[:port] in lowercase.
 * Only https is accepted, except http for localhost and loopback addresses
 * so local development works. Default ports are dropped because browsers
 * omit them from location.origin and the Origin header.
 */
export function normalizeOrigin(s: string): string {
  if (s.length > 512) {
    throw new LinkError("origin too long");
  }
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(.*)$/s.exec(s);
  if (m === null) {
    if (s.includes("://")) {
      throw new LinkError("origin: missing protocol scheme");
    }
    throw new LinkError("origin scheme must be https");
  }
  const groups: (string | undefined)[] = m;
  const scheme = (groups[1] ?? "").toLowerCase();
  const authority = groups[2] ?? "";
  const rest = groups[3] ?? "";
  if (rest !== "" && rest !== "/") {
    throw new LinkError("origin must be scheme://host[:port] only");
  }
  if (authority.includes("@")) {
    throw new LinkError("origin must be scheme://host[:port] only");
  }
  let host: string;
  let port = "";
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0) {
      throw new LinkError("origin: missing ']' in host");
    }
    host = authority.slice(0, close + 1);
    const after = authority.slice(close + 1);
    if (after !== "") {
      if (!/^:\d+$/.test(after)) {
        throw new LinkError("origin: invalid port");
      }
      port = after.slice(1);
    }
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon >= 0) {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
      if (!/^\d+$/.test(port)) {
        throw new LinkError("origin: invalid port");
      }
    } else {
      host = authority;
    }
    if (/[\s[\]:]/.test(host)) {
      throw new LinkError("origin: invalid character in host name");
    }
  }
  const hostname = host.startsWith("[") ? host.slice(1, -1) : host;
  if (hostname === "") {
    throw new LinkError("origin has no host");
  }
  for (const ch of hostname) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0x20 || cp === 0x7f) {
      throw new LinkError("origin: invalid character in host name");
    }
  }
  const lowerHost = hostname.toLowerCase();
  switch (scheme) {
    case "https":
      break;
    case "http":
      if (lowerHost !== "localhost" && lowerHost !== "127.0.0.1" && lowerHost !== "::1") {
        throw new LinkError("http is only allowed for localhost");
      }
      break;
    default:
      throw new LinkError("origin scheme must be https");
  }
  let out = scheme + "://" + host.toLowerCase();
  if (port !== "" && !((scheme === "https" && port === "443") || (scheme === "http" && port === "80"))) {
    out += ":" + port;
  }
  return out;
}

/**
 * Percent-encodes a value the way Go's url.QueryEscape does: unreserved
 * characters are kept, space becomes "+", everything else becomes %XX.
 */
export function queryEscape(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let out = "";
  for (const b of bytes) {
    if (
      (b >= 0x30 && b <= 0x39) ||
      (b >= 0x41 && b <= 0x5a) ||
      (b >= 0x61 && b <= 0x7a) ||
      b === 0x2d ||
      b === 0x5f ||
      b === 0x2e ||
      b === 0x7e
    ) {
      out += String.fromCharCode(b);
    } else if (b === 0x20) {
      out += "+";
    } else {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
  }
  return out;
}

/** Reverses queryEscape ("+" is a space); throws LinkError on bad escapes. */
function queryUnescape(field: string, s: string): string {
  try {
    return decodeURIComponent(s.replaceAll("+", " "));
  } catch {
    throw new LinkError('field "' + field + '": invalid escape');
  }
}

function encodeFields(fields: [string, string][]): string {
  return fields.map(([k, v]) => k + "=" + queryEscape(v)).join("&");
}

/** Checks every field of a drop link. */
export function validateDropLink(d: DropLink): void {
  if (d.relay !== undefined && d.relay !== "") {
    normalizeOrigin(d.relay);
  }
  if (!isValidToken(d.id)) {
    throw new LinkError("malformed drop id");
  }
  if (!isValidToken(d.uploadToken)) {
    throw new LinkError("malformed upload token");
  }
  if (d.recipientKey.length !== KEY_BYTES) {
    throw new LinkError("recipient key must be " + String(KEY_BYTES) + " bytes");
  }
  try {
    validateName(d.name);
    validateText("purpose", d.purpose);
    validateText("storage", d.storage);
    validateRetention(d.retention);
  } catch (err) {
    throw new LinkError(err instanceof Error ? err.message : String(err));
  }
}

/** Checks every field of a reveal link. */
export function validateRevealLink(r: RevealLink): void {
  if (r.relay !== undefined && r.relay !== "") {
    normalizeOrigin(r.relay);
  }
  if (!isValidToken(r.id)) {
    throw new LinkError("malformed drop id");
  }
  if (!isValidToken(r.revealToken)) {
    throw new LinkError("malformed reveal token");
  }
  if (r.key.length !== KEY_BYTES) {
    throw new LinkError("key must be " + String(KEY_BYTES) + " bytes");
  }
  if (r.salt !== undefined && r.salt.length !== 0 && r.salt.length !== SALT_BYTES) {
    throw new LinkError("salt must be " + String(SALT_BYTES) + " bytes");
  }
  try {
    validateName(r.name);
  } catch (err) {
    throw new LinkError(err instanceof Error ? err.message : String(err));
  }
}

/** Returns the full drop link for a page served at pageOrigin. */
export function buildDropLink(d: DropLink, pageOrigin: string): string {
  validateDropLink(d);
  const origin = normalizeOrigin(pageOrigin);
  const fields: [string, string][] = [
    ["v", LINK_VERSION],
    ["i", d.id],
    ["u", d.uploadToken],
    ["k", encodeBase64Url(d.recipientKey)],
    ["n", d.name],
    ["p", d.purpose],
    ["s", d.storage],
    ["t", d.retention],
  ];
  if (d.relay !== undefined && d.relay !== "") {
    fields.push(["r", normalizeOrigin(d.relay)]);
  }
  return origin + PATH_DROP + "#" + encodeFields(fields);
}

/** Returns the full reveal link for a page served at pageOrigin. */
export function buildRevealLink(r: RevealLink, pageOrigin: string): string {
  validateRevealLink(r);
  const origin = normalizeOrigin(pageOrigin);
  const fields: [string, string][] = [
    ["v", LINK_VERSION],
    ["i", r.id],
    ["o", r.revealToken],
    ["k", encodeBase64Url(r.key)],
    ["n", r.name],
    ["c", r.keepsCopy ? "1" : "0"],
  ];
  if (r.salt !== undefined && r.salt.length > 0) {
    fields.push(["s", encodeBase64Url(r.salt)]);
  }
  if (r.relay !== undefined && r.relay !== "") {
    fields.push(["r", normalizeOrigin(r.relay)]);
  }
  return origin + PATH_REVEAL + "#" + encodeFields(fields);
}

/** Separates a raw link into page origin, path, and the raw fragment. */
function split(raw: string): { origin: string; path: string; frag: string } {
  if (raw.length > 8192) {
    throw new LinkError("link too long");
  }
  const hash = raw.indexOf("#");
  if (hash < 0) {
    throw new LinkError("no fragment");
  }
  const base = raw.slice(0, hash);
  const frag = raw.slice(hash + 1);
  const m = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*)([^?#]*)(\?.*)?$/s.exec(base);
  if (m === null) {
    throw new LinkError("origin scheme must be https");
  }
  const groups: (string | undefined)[] = m;
  if (groups[3] !== undefined || (groups[1] ?? "").includes("@")) {
    throw new LinkError("links carry no query string or userinfo");
  }
  const origin = normalizeOrigin(groups[1] ?? "");
  let path: string;
  try {
    path = decodeURIComponent(groups[2] ?? "");
  } catch {
    throw new LinkError("invalid escape in path");
  }
  if (path.endsWith("/")) {
    path = path.slice(0, -1);
  }
  return { origin, path, frag };
}

function parseFields(frag: string, allowed: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (frag === "") {
    throw new LinkError("empty fragment");
  }
  for (const part of frag.split("&")) {
    const eq = part.indexOf("=");
    if (eq <= 0) {
      throw new LinkError('malformed field "' + part + '"');
    }
    const key = part.slice(0, eq);
    if (!allowed.includes(key)) {
      throw new LinkError('unknown field "' + key + '"');
    }
    if (out.has(key)) {
      throw new LinkError('duplicate field "' + key + '"');
    }
    out.set(key, queryUnescape(key, part.slice(eq + 1)));
  }
  if (out.get("v") !== LINK_VERSION) {
    throw new LinkError('unsupported link version "' + (out.get("v") ?? "") + '"');
  }
  return out;
}

function require(m: Map<string, string>, ...keys: string[]): void {
  for (const k of keys) {
    if ((m.get(k) ?? "") === "") {
      throw new LinkError('missing field "' + k + '"');
    }
  }
}

function decodeSalt(s: string): Uint8Array {
  if (s.length !== SALT_LEN) {
    throw new LinkError("salt must be " + String(SALT_LEN) + " base64url characters");
  }
  let b: Uint8Array;
  try {
    b = decodeBase64Url(s);
  } catch {
    throw new LinkError("salt is not valid base64url");
  }
  if (b.length !== SALT_BYTES) {
    throw new LinkError("salt is not valid base64url");
  }
  return b;
}

function decodeKey(s: string): Uint8Array {
  if (s.length !== KEY_LEN) {
    throw new LinkError("key must be " + String(KEY_LEN) + " base64url characters");
  }
  let b: Uint8Array;
  try {
    b = decodeBase64Url(s);
  } catch {
    throw new LinkError("key is not valid base64url");
  }
  if (b.length !== KEY_BYTES) {
    throw new LinkError("key is not valid base64url");
  }
  return b;
}

function parseDropFields(frag: string): DropLink {
  const m = parseFields(frag, ["v", "i", "u", "k", "n", "p", "s", "t", "r"]);
  require(m, "i", "u", "k", "n", "t");
  const d: DropLink = {
    id: m.get("i") ?? "",
    uploadToken: m.get("u") ?? "",
    recipientKey: decodeKey(m.get("k") ?? ""),
    name: m.get("n") ?? "",
    purpose: m.get("p") ?? "",
    storage: m.get("s") ?? "",
    retention: m.get("t") ?? "",
  };
  const r = m.get("r") ?? "";
  if (r !== "") {
    d.relay = normalizeOrigin(r);
  }
  validateDropLink(d);
  return d;
}

function parseRevealFields(frag: string): RevealLink {
  const m = parseFields(frag, ["v", "i", "o", "k", "n", "c", "s", "r"]);
  require(m, "i", "o", "k", "n", "c");
  const c = m.get("c");
  if (c !== "0" && c !== "1") {
    throw new LinkError("field c must be 0 or 1");
  }
  const r: RevealLink = {
    id: m.get("i") ?? "",
    revealToken: m.get("o") ?? "",
    key: decodeKey(m.get("k") ?? ""),
    name: m.get("n") ?? "",
    keepsCopy: c === "1",
  };
  const s = m.get("s") ?? "";
  if (s !== "") {
    r.salt = decodeSalt(s);
  }
  const rel = m.get("r") ?? "";
  if (rel !== "") {
    r.relay = normalizeOrigin(rel);
  }
  validateRevealLink(r);
  return r;
}

/** Parses either kind of link. */
export function parseLink(raw: string): ParsedLink {
  const { origin, path, frag } = split(raw);
  switch (path) {
    case PATH_DROP:
      return { kind: "drop", pageOrigin: origin, drop: parseDropFields(frag) };
    case PATH_REVEAL:
      return { kind: "reveal", pageOrigin: origin, reveal: parseRevealFields(frag) };
    default:
      throw new LinkError("path must be " + PATH_DROP + " or " + PATH_REVEAL);
  }
}

/** Parses a drop link and returns it with the page origin. */
export function parseDropLink(raw: string): { drop: DropLink; pageOrigin: string } {
  const p = parseLink(raw);
  if (p.kind !== "drop") {
    throw new LinkError("not a drop link");
  }
  return { drop: p.drop, pageOrigin: p.pageOrigin };
}

/** Parses a reveal link and returns it with the page origin. */
export function parseRevealLink(raw: string): { reveal: RevealLink; pageOrigin: string } {
  const p = parseLink(raw);
  if (p.kind !== "reveal") {
    throw new LinkError("not a reveal link");
  }
  return { reveal: p.reveal, pageOrigin: p.pageOrigin };
}

/**
 * Returns the relay a client should talk to: the explicit relay field when
 * the link carries one, otherwise the page origin the link was served from.
 */
export function relayOrigin(link: DropLink | RevealLink, pageOrigin: string): string {
  if (link.relay !== undefined && link.relay !== "") {
    return link.relay;
  }
  return pageOrigin;
}

/** relayOrigin for a parsed link. */
export function parsedRelayOrigin(p: ParsedLink): string {
  return p.kind === "drop" ? relayOrigin(p.drop, p.pageOrigin) : relayOrigin(p.reveal, p.pageOrigin);
}

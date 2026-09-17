/**
 * The envelope is the plaintext that is padded and encrypted (crypto spec
 * section 5.5). This module validates, encodes, and decodes it with the same
 * rules as the Go reference (internal/crypto/envelope.go): unknown fields are
 * rejected, the version must be 1, names and display texts are bounded, the
 * secret format is "text" or "base64", and reveal envelopes carry no drop
 * metadata.
 *
 * Encoding produces the same bytes as Go's encoding/json with HTML escaping
 * disabled, so an envelope encoded here matches the shared test vectors.
 * Other consumers only need to parse the output as JSON.
 *
 * No Node-only imports: the browser page can reuse this module.
 */
import { decodeBase64Url, encodeBase64Url } from "./base64url.js";
import { EnvelopeError } from "./errors.js";

/** Limits on envelope text fields (crypto spec section 5.6). */
export const MAX_NAME_LEN = 100;
export const MAX_TEXT_LEN = 200;

export type EnvelopeType = "drop" | "reveal";
export type SecretFormat = "text" | "base64";

export const RETENTION_SESSION = "session";
export const RETENTION_UNTIL_REVOKED = "until-revoked";
export const RETENTION_UNTIL_PREFIX = "until:";

/**
 * Envelope is the plaintext structure that is padded and encrypted.
 *
 * For drops, the page fills in the metadata it displayed (name, purpose,
 * storage, retention, fingerprint) so the agent can verify that the human saw
 * exactly what the agent asked for. For reveals only name, format and secret
 * are set; the display fields travel as additional data instead.
 */
export interface Envelope {
  v: number;
  type: EnvelopeType;
  name: string;
  purpose?: string;
  storage?: string;
  retention?: string;
  fingerprint?: string;
  format: SecretFormat;
  secret: string;
}

const FINGERPRINT_RE = /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/;

const BACKSLASH = String.fromCharCode(92);
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8");

/** Counts Unicode code points, like Go's utf8.RuneCountInString. */
export function runeCount(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0xdc00 || c > 0xdfff) {
      n++;
    }
  }
  return n;
}

/** Go's unicode.IsSpace, used by strings.TrimSpace. */
export function isGoSpace(cp: number): boolean {
  switch (cp) {
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x20:
    case 0x85:
    case 0xa0:
    case 0x1680:
    case 0x2028:
    case 0x2029:
    case 0x202f:
    case 0x205f:
    case 0x3000:
      return true;
    default:
      return cp >= 0x2000 && cp <= 0x200a;
  }
}

function hasSurroundingSpace(s: string): boolean {
  if (s === "") {
    return false;
  }
  const first = s.codePointAt(0) ?? 0;
  const lastUnit = s.charCodeAt(s.length - 1);
  let last = lastUnit;
  if (lastUnit >= 0xdc00 && lastUnit <= 0xdfff && s.length >= 2) {
    last = s.codePointAt(s.length - 2) ?? lastUnit;
  }
  return isGoSpace(first) || isGoSpace(last);
}

/**
 * Checks a secret reference name: 1 to MAX_NAME_LEN characters, valid
 * Unicode, no control characters, no leading or trailing whitespace.
 */
export function validateName(name: string): void {
  if (name === "" || runeCount(name) > MAX_NAME_LEN) {
    throw new EnvelopeError("name must be 1 to " + String(MAX_NAME_LEN) + " characters");
  }
  if (!name.isWellFormed()) {
    throw new EnvelopeError("name is not valid UTF-8");
  }
  if (hasSurroundingSpace(name)) {
    throw new EnvelopeError("name has leading or trailing whitespace");
  }
  for (const ch of name) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x20 || cp === 0x7f) {
      throw new EnvelopeError("name contains a control character");
    }
  }
}

/**
 * Checks a display text field (purpose, storage): at most MAX_TEXT_LEN
 * characters, valid Unicode, no control characters except newline.
 */
export function validateText(field: string, s: string): void {
  if (runeCount(s) > MAX_TEXT_LEN) {
    throw new EnvelopeError(field + " longer than " + String(MAX_TEXT_LEN) + " characters");
  }
  if (!s.isWellFormed()) {
    throw new EnvelopeError(field + " is not valid UTF-8");
  }
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if ((cp < 0x20 && cp !== 0x0a) || cp === 0x7f) {
      throw new EnvelopeError(field + " contains a control character");
    }
  }
}

const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function daysIn(month: number, year: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    return 30;
  }
  return 31;
}

/**
 * Parses an RFC 3339 timestamp with the same acceptance rules as Go's
 * time.Parse(time.RFC3339, s): uppercase T and Z, a numeric offset with a
 * colon, seconds 0 to 59, and calendar-valid dates. Returns undefined when
 * the string is not accepted.
 */
export function parseRfc3339(s: string): Date | undefined {
  const m = RFC3339_RE.exec(s);
  if (m === null) {
    return undefined;
  }
  const groups: (string | undefined)[] = m;
  const year = Number(groups[1]);
  const month = Number(groups[2]);
  const day = Number(groups[3]);
  const hour = Number(groups[4]);
  const minute = Number(groups[5]);
  const second = Number(groups[6]);
  const fraction = groups[7] ?? "";
  const zone = groups[8] ?? "Z";
  if (month < 1 || month > 12 || day < 1 || day > daysIn(month, year) || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  let offsetMinutes = 0;
  if (zone !== "Z") {
    const zh = Number(zone.slice(1, 3));
    const zm = Number(zone.slice(4, 6));
    if (zh > 23 || zm > 59) {
      return undefined;
    }
    offsetMinutes = (zh * 60 + zm) * (zone.startsWith("-") ? -1 : 1);
  }
  const millis = fraction === "" ? 0 : Math.floor(Number("0" + fraction) * 1000);
  const utc = Date.UTC(year, month - 1, day, hour, minute, second, millis) - offsetMinutes * 60_000;
  return new Date(utc);
}

/** Accepts "session", "until-revoked", or "until:<RFC 3339>". */
export function validateRetention(r: string): void {
  if (r === RETENTION_SESSION || r === RETENTION_UNTIL_REVOKED) {
    return;
  }
  if (r.startsWith(RETENTION_UNTIL_PREFIX)) {
    if (parseRfc3339(r.slice(RETENTION_UNTIL_PREFIX.length)) === undefined) {
      throw new EnvelopeError("retention date is not RFC 3339");
    }
    return;
  }
  throw new EnvelopeError("unknown retention policy");
}

/** Checks every field of an envelope against the specification. */
export function validateEnvelope(e: Envelope): void {
  // Decoded input may carry any string in these fields; check them as strings.
  const type: string = e.type;
  const format: string = e.format;
  if (e.v !== 1) {
    throw new EnvelopeError("unsupported version " + String(e.v));
  }
  if (type !== "drop" && type !== "reveal") {
    throw new EnvelopeError("unknown type");
  }
  if (format !== "text" && format !== "base64") {
    throw new EnvelopeError("unknown format");
  }
  validateName(e.name);
  validateText("purpose", e.purpose ?? "");
  validateText("storage", e.storage ?? "");
  if (e.type === "drop") {
    validateRetention(e.retention ?? "");
    if (!FINGERPRINT_RE.test(e.fingerprint ?? "")) {
      throw new EnvelopeError("malformed fingerprint");
    }
  } else if ((e.retention ?? "") !== "" || (e.fingerprint ?? "") !== "" || (e.purpose ?? "") !== "" || (e.storage ?? "") !== "") {
    throw new EnvelopeError("reveal envelopes carry no drop metadata");
  }
  if (e.format === "base64") {
    try {
      decodeBase64Url(e.secret);
    } catch {
      throw new EnvelopeError("secret is not base64url");
    }
  } else if (!e.secret.isWellFormed()) {
    throw new EnvelopeError("secret is not valid UTF-8");
  }
}

/**
 * Quotes a string exactly like Go's encoding/json: short escapes for the
 * usual control characters, a six-character unicode escape for the others
 * and for the line and paragraph separators, and, when escapeHtml is set,
 * the same escape for "<", ">" and "&" (Go's default, which the envelope
 * encoder turns off).
 */
export function quoteJsonGo(s: string, escapeHtml = false): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    switch (cp) {
      case 0x22:
        out += BACKSLASH + '"';
        break;
      case 0x5c:
        out += BACKSLASH + BACKSLASH;
        break;
      case 0x08:
        out += BACKSLASH + "b";
        break;
      case 0x0c:
        out += BACKSLASH + "f";
        break;
      case 0x0a:
        out += BACKSLASH + "n";
        break;
      case 0x0d:
        out += BACKSLASH + "r";
        break;
      case 0x09:
        out += BACKSLASH + "t";
        break;
      default:
        if (cp < 0x20 || (escapeHtml && (cp === 0x3c || cp === 0x3e || cp === 0x26))) {
          out += BACKSLASH + "u00" + cp.toString(16).padStart(2, "0");
        } else if (ch === LINE_SEPARATOR || ch === PARAGRAPH_SEPARATOR) {
          out += BACKSLASH + "u" + cp.toString(16);
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

const quoteGo = (s: string): string => quoteJsonGo(s, false);

/**
 * Validates and serializes the envelope as compact JSON without HTML
 * escaping, byte for byte as the Go implementation does.
 */
export function encodeEnvelope(e: Envelope): Uint8Array {
  validateEnvelope(e);
  let json = '{"v":' + String(e.v) + ',"type":' + quoteGo(e.type) + ',"name":' + quoteGo(e.name);
  if ((e.purpose ?? "") !== "") {
    json += ',"purpose":' + quoteGo(e.purpose ?? "");
  }
  if ((e.storage ?? "") !== "") {
    json += ',"storage":' + quoteGo(e.storage ?? "");
  }
  if ((e.retention ?? "") !== "") {
    json += ',"retention":' + quoteGo(e.retention ?? "");
  }
  if ((e.fingerprint ?? "") !== "") {
    json += ',"fingerprint":' + quoteGo(e.fingerprint ?? "");
  }
  json += ',"format":' + quoteGo(e.format) + ',"secret":' + quoteGo(e.secret) + "}";
  return utf8Encoder.encode(json);
}

const STRING_FIELDS: readonly string[] = ["type", "name", "purpose", "storage", "retention", "fingerprint", "format", "secret"];

function readString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (v === undefined || v === null) {
    return "";
  }
  if (typeof v !== "string") {
    throw new EnvelopeError("wrong type for field " + key);
  }
  return v.toWellFormed();
}

/**
 * Parses and validates an envelope. Unknown fields, wrong types, trailing
 * data, and every validation failure raise EnvelopeError. Invalid UTF-8 in
 * the input is replaced with U+FFFD, as Go's decoder does.
 */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decoder.decode(bytes));
  } catch {
    throw new EnvelopeError("malformed JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new EnvelopeError("not a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (key !== "v" && !STRING_FIELDS.includes(key)) {
      throw new EnvelopeError('unknown field "' + key + '"');
    }
  }
  let v = 0;
  if (obj.v !== undefined && obj.v !== null) {
    if (typeof obj.v !== "number" || !Number.isInteger(obj.v)) {
      throw new EnvelopeError("wrong type for field v");
    }
    v = obj.v;
  }
  const e: Envelope = {
    v,
    type: readString(obj, "type") as EnvelopeType,
    name: readString(obj, "name"),
    format: readString(obj, "format") as SecretFormat,
    secret: readString(obj, "secret"),
  };
  const purpose = readString(obj, "purpose");
  if (purpose !== "") {
    e.purpose = purpose;
  }
  const storage = readString(obj, "storage");
  if (storage !== "") {
    e.storage = storage;
  }
  const retention = readString(obj, "retention");
  if (retention !== "") {
    e.retention = retention;
  }
  const fingerprint = readString(obj, "fingerprint");
  if (fingerprint !== "") {
    e.fingerprint = fingerprint;
  }
  validateEnvelope(e);
  return e;
}

/** Returns the secret as raw bytes, decoding base64url if needed. */
export function secretBytes(e: Envelope): Uint8Array {
  if (e.format === "base64") {
    return decodeBase64Url(e.secret);
  }
  return utf8Encoder.encode(e.secret);
}

function hasBinaryControl(b: Uint8Array): boolean {
  for (const c of b) {
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) {
      return true;
    }
  }
  return false;
}

/**
 * Chooses the wire representation of a value: "text" when it is valid UTF-8
 * without control characters other than tab, newline, and carriage return,
 * and "base64" otherwise.
 */
export function secretField(value: Uint8Array): { format: SecretFormat; secret: string } {
  if (!hasBinaryControl(value)) {
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(value);
      return { format: "text", secret: text };
    } catch {
      // Not valid UTF-8: fall through to base64.
    }
  }
  return { format: "base64", secret: encodeBase64Url(value) };
}

/**
 * Builds the additional data for a reveal: the display fields the page
 * shows, joined with newlines behind a fixed domain string, so a link whose
 * display fields were altered fails to decrypt (crypto spec section 5.6).
 */
export function revealAad(name: string, keepsCopy: boolean): Uint8Array {
  return utf8Encoder.encode("burndrop/reveal/v1\n" + name + "\n" + (keepsCopy ? "1" : "0"));
}
